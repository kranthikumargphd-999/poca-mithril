
import json
import time
import csv
import statistics
from pathlib import Path
from web3 import Web3

# Configuration
RPC_URL = "http://127.0.0.1:7545"
LOAD_LEVELS = [1000, 5000]
REPEATS = 3

BASE_DIR = Path(__file__).resolve().parent
RUN_DIR = BASE_DIR / f"sustained_rerun_{time.time_ns()}"
RUN_DIR.mkdir()

TRIAL_FILE = RUN_DIR / "sustained_load_repeated_results.csv"
DETAIL_FILE = RUN_DIR / "sustained_load_transaction_details.csv"
SUMMARY_FILE = RUN_DIR / "sustained_load_uncertainty.csv"

web3 = Web3(Web3.HTTPProvider(RPC_URL))

if not web3.is_connected():
    raise RuntimeError("Ganache connection failed")

contract_path = (
    BASE_DIR.parent / "blocks" / "build"
    / "contracts" / "Store.json"
)

with open(contract_path, encoding="utf-8") as f:
    artifact = json.load(f)

network = artifact["networks"]["5777"]
contract = web3.eth.contract(
    address=Web3.to_checksum_address(network["address"]),
    abi=artifact["abi"]
)

account = web3.eth.accounts[1]
print("Connected to Ganache:", web3.is_connected())

balance = web3.eth.get_balance(account)

print("Account:", account)
print("Balance (ETH):", web3.from_wei(balance, "ether"))
print("Gas Price (Gwei):", web3.from_wei(web3.eth.gas_price, "gwei"))

def mean_sd(values):
    if not values:
        return 0.0, 0.0
    mean = statistics.mean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean, sd


def iqr_outlier_count(values):
    """Tukey 1.5xIQR outliers; descriptive, not removed."""
    if len(values) < 4:
        return 0

    ordered = sorted(values)
    lower, upper = [], []

    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        lower = ordered[:midpoint]
        upper = ordered[midpoint + 1:]
    else:
        lower = ordered[:midpoint]
        upper = ordered[midpoint:]

    q1 = statistics.median(lower)
    q3 = statistics.median(upper)
    iqr = q3 - q1

    return sum(
        value < q1 - 1.5 * iqr or value > q3 + 1.5 * iqr
        for value in values
    )


trial_rows = []
detail_rows = []

for operations in LOAD_LEVELS:
    for trial in range(1, REPEATS + 1):
        print(f"\nOperations: {operations}, Trial: {trial}")

        success = 0
        failed = 0
        latencies = []
        gas_values = []

        start = time.perf_counter()
        nonce = web3.eth.get_transaction_count(account, "pending")

        for i in range(operations):
            payload = json.dumps({
                "proof_id": i,
                "hash": "POCA_HASH_" + str(i),
                "timestamp": time.time()
            })

            tx_start = time.perf_counter()

            try:
                transaction = contract.functions.addString(
                    payload
                ).build_transaction({
                    "from": account,
                    "nonce": nonce,
                    "gas": 500000,
                    "gasPrice": web3.eth.gas_price
                })

                tx_hash = web3.eth.send_transaction(transaction)
                nonce += 1

                receipt = web3.eth.wait_for_transaction_receipt(
                    tx_hash,
                    timeout=120
                )

                latency_ms = (
                    time.perf_counter() - tx_start
                ) * 1000

                if receipt.status == 1:
                    success += 1
                    latencies.append(latency_ms)
                    gas_values.append(receipt.gasUsed)
                    status = "success"
                else:
                    failed += 1
                    status = "reverted"

                detail_rows.append([
                    operations, trial, i, status,
                    round(latency_ms, 6),
                    receipt.gasUsed, tx_hash.hex()
                ])

            except Exception as exc:
                failed += 1

                if failed <= 3:
                    print(
                        f"ERROR | Workload={operations} "
                        f"| Trial={trial} | Transaction={i}"
                    )
                    print("Error type:", type(exc).__name__)
                    print("Error details:", str(exc))

                detail_rows.append([
                    operations, trial, i, "failed",
                    "", "", str(exc)
                ])

                nonce = web3.eth.get_transaction_count(
                    account, "pending"
                )

        elapsed = time.perf_counter() - start
        average_latency, _ = mean_sd(latencies)
        average_gas, _ = mean_sd(gas_values)
        throughput = success / elapsed if elapsed else 0

        trial_rows.append({
            "Operations": operations,
            "Trial": trial,
            "Successful": success,
            "Failed": failed,
            "Average Latency(ms)": average_latency,
            "Throughput(ops/sec)": throughput,
            "Average Gas": average_gas,
            "Latency IQR Outliers": iqr_outlier_count(latencies),
            "Gas IQR Outliers": iqr_outlier_count(gas_values)
        })

        print(
            f"Success={success}, Failed={failed}, "
            f"Latency={average_latency:.3f} ms, "
            f"Throughput={throughput:.3f}, "
            f"Gas={average_gas:.2f}"
        )

# Save separate trial measurements
fields = list(trial_rows[0].keys())
with open(TRIAL_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(trial_rows)

# Save individual transaction measurements
with open(DETAIL_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "Operations", "Trial", "Operation Index",
        "Status", "Latency(ms)", "Gas Used", "Tx Hash/Error"
    ])
    writer.writerows(detail_rows)

# Statistical summary across repeated runs
summary_rows = []

for operations in LOAD_LEVELS:
    rows = [
        row for row in trial_rows
        if row["Operations"] == operations
    ]

    latency_mean, latency_sd = mean_sd([
        row["Average Latency(ms)"] for row in rows
    ])
    throughput_mean, throughput_sd = mean_sd([
        row["Throughput(ops/sec)"] for row in rows
    ])
    gas_mean, gas_sd = mean_sd([
        row["Average Gas"] for row in rows
    ])

    summary_rows.append([
        operations, REPEATS,
        round(latency_mean, 3),
        round(latency_sd, 3),
        round(throughput_mean, 3),
        round(throughput_sd, 3),
        round(gas_mean, 2),
        round(gas_sd, 2),
        sum(row["Failed"] for row in rows),
        sum(row["Latency IQR Outliers"] for row in rows),
        sum(row["Gas IQR Outliers"] for row in rows)
    ])

with open(SUMMARY_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "Operations", "Trials",
        "Latency Mean(ms)", "Latency SD(ms)",
        "Throughput Mean", "Throughput SD",
        "Gas Mean", "Gas SD",
        "Total Failures", "Latency IQR Outliers",
        "Gas IQR Outliers"
    ])
    writer.writerows(summary_rows)

print("\nCompleted repeated sustained-load evaluation")
print(TRIAL_FILE)
print(DETAIL_FILE)
print(SUMMARY_FILE)
