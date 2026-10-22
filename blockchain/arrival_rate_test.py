
import csv
import json
import time
import statistics
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from web3 import Web3


# ==========================================
# CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent

RPC_URL = "http://127.0.0.1:7545"

ARRIVAL_RATES = [1, 2, 5]

TRANSACTIONS_PER_TRIAL = 20

REPEATS = 3

MIN_BALANCE_ETH = 1.0

DETAIL_FILE = BASE_DIR / "arrival_rate_details.csv"
RESULT_FILE = BASE_DIR / "arrival_rate_results.csv"
SUMMARY_FILE = BASE_DIR / "arrival_rate_uncertainty.csv"


# ==========================================
# CONNECT TO GANACHE
# ==========================================

web3 = Web3(Web3.HTTPProvider(RPC_URL))

if not web3.is_connected():
    raise SystemExit("ERROR: Ganache is not connected.")

print("Connected to Ganache:", web3.is_connected())

gas_price = web3.eth.gas_price

print("Gas price (Gwei):", web3.from_wei(gas_price, "gwei"))


# ==========================================
# SELECT FUNDED ACCOUNT
# ==========================================

account = None

for candidate in web3.eth.accounts:
    balance = float(
        web3.from_wei(
            web3.eth.get_balance(candidate),
            "ether"
        )
    )

    print("Account:", candidate, "| Balance:", balance, "ETH")

    if account is None and balance >= MIN_BALANCE_ETH:
        account = candidate

if account is None:
    raise SystemExit(
        "ERROR: No account has at least 1 ETH. "
        "Fund a Ganache account before running this experiment."
    )

print("\nSelected account:", account)


# ==========================================
# LOAD STORE CONTRACT
# ==========================================

contract_path = (
    BASE_DIR.parent
    / "blocks"
    / "build"
    / "contracts"
    / "Store.json"
)

if not contract_path.exists():
    raise SystemExit(
        f"ERROR: Contract artifact not found: {contract_path}"
    )

with open(contract_path, "r", encoding="utf-8") as file:
    artifact = json.load(file)

network_id = str(web3.net.version)

deployment = artifact.get("networks", {}).get(network_id)

if not deployment:
    raise SystemExit(
        f"ERROR: Store.sol not deployed on network {network_id}."
    )

contract_address = Web3.to_checksum_address(
    deployment["address"]
)

contract = web3.eth.contract(
    address=contract_address,
    abi=artifact["abi"]
)

if not web3.eth.get_code(contract_address):
    raise SystemExit(
        "ERROR: No contract code found at deployed address."
    )

print("Contract:", contract_address)


# ==========================================
# CSV SETTINGS
# ==========================================

detail_rows = []
trial_rows = []

experiment_id = uuid4().hex[:12]


# ==========================================
# ARRIVAL RATE EXPERIMENT
# ==========================================

for rate in ARRIVAL_RATES:

    for trial in range(1, REPEATS + 1):

        print("\n====================================")
        print("Arrival Rate:", rate, "requests/second")
        print("Trial:", trial)
        print("====================================")

        latencies = []
        gas_values = []

        successful = 0
        failed = 0

        trial_start = time.perf_counter()

        for i in range(TRANSACTIONS_PER_TRIAL):

            # Schedule requests at the selected rate.
            scheduled_time = trial_start + (i / rate)
            remaining = scheduled_time - time.perf_counter()

            if remaining > 0:
                time.sleep(remaining)

            transaction_start = time.perf_counter()

            proof_data = {
                "type": "arrival_rate_benchmark",
                "experiment_id": experiment_id,
                "arrival_rate": rate,
                "trial": trial,
                "proof_id": f"{experiment_id}-{rate}-{trial}-{i}",
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat()
            }

            try:
                nonce = web3.eth.get_transaction_count(
                    account, "pending"
                )

                transaction = (
                    contract.functions.addString(
                        json.dumps(
                            proof_data,
                            separators=(",", ":")
                        )
                    ).build_transaction({
                        "from": account,
                        "nonce": nonce,
                        "gas": 500000,
                        "gasPrice": gas_price
                    })
                )

                tx_hash = web3.eth.send_transaction(
                    transaction
                )

                receipt = web3.eth.wait_for_transaction_receipt(
                    tx_hash,
                    timeout=120
                )

                latency_ms = (
                    time.perf_counter() - transaction_start
                ) * 1000

                if receipt.status == 1:
                    successful += 1
                    latencies.append(latency_ms)
                    gas_values.append(receipt.gasUsed)
                    status = "Success"
                else:
                    failed += 1
                    status = "Failed"

                detail_rows.append({
                    "Arrival Rate": rate,
                    "Trial": trial,
                    "Transaction": i + 1,
                    "Status": status,
                    "Latency(ms)": round(latency_ms, 6),
                    "Gas Used": receipt.gasUsed
                })

            except Exception as error:

                failed += 1

                detail_rows.append({
                    "Arrival Rate": rate,
                    "Trial": trial,
                    "Transaction": i + 1,
                    "Status": "Failed",
                    "Latency(ms)": "",
                    "Gas Used": ""
                })

                print("ERROR:", str(error))

                if (
                    "insufficient funds" in str(error).lower()
                ):
                    raise SystemExit(
                        "STOPPED: Insufficient Ganache ETH."
                    )

        elapsed = time.perf_counter() - trial_start

        avg_latency = (
            statistics.mean(latencies)
            if latencies else 0
        )

        throughput = successful / elapsed if elapsed > 0 else 0

        avg_gas = (
            statistics.mean(gas_values)
            if gas_values else 0
        )

        trial_rows.append({
            "Arrival Rate": rate,
            "Trial": trial,
            "Successful": successful,
            "Failed": failed,
            "Average Latency(ms)": round(avg_latency, 6),
            "Throughput(ops/sec)": round(throughput, 6),
            "Average Gas": round(avg_gas, 6)
        })

        print("Successful:", successful)
        print("Failed:", failed)
        print("Average Latency:", round(avg_latency, 3), "ms")
        print("Throughput:", round(throughput, 3), "ops/sec")
        print("Average Gas:", round(avg_gas, 2))


# ==========================================
# WRITE TRANSACTION DETAILS
# ==========================================

with open(DETAIL_FILE, "w", newline="", encoding="utf-8") as file:

    writer = csv.DictWriter(
        file,
        fieldnames=[
            "Arrival Rate",
            "Trial",
            "Transaction",
            "Status",
            "Latency(ms)",
            "Gas Used"
        ]
    )

    writer.writeheader()
    writer.writerows(detail_rows)


# ==========================================
# WRITE TRIAL RESULTS
# ==========================================

with open(RESULT_FILE, "w", newline="", encoding="utf-8") as file:

    writer = csv.DictWriter(
        file,
        fieldnames=[
            "Arrival Rate",
            "Trial",
            "Successful",
            "Failed",
            "Average Latency(ms)",
            "Throughput(ops/sec)",
            "Average Gas"
        ]
    )

    writer.writeheader()
    writer.writerows(trial_rows)


# ==========================================
# CALCULATE MEAN AND STANDARD DEVIATION
# ==========================================

summary_rows = []


def mean_and_sd(values):
    return (
        statistics.mean(values),
        statistics.stdev(values)
    )


for rate in ARRIVAL_RATES:

    rows = [
        row for row in trial_rows
        if row["Arrival Rate"] == rate
        and row["Failed"] == 0
        and row["Successful"] == TRANSACTIONS_PER_TRIAL
    ]

    if len(rows) < 2:
        print(
            "WARNING: Insufficient complete trials for rate",
            rate
        )
        continue

    latency_mean, latency_sd = mean_and_sd([
        row["Average Latency(ms)"] for row in rows
    ])

    throughput_mean, throughput_sd = mean_and_sd([
        row["Throughput(ops/sec)"] for row in rows
    ])

    gas_mean, gas_sd = mean_and_sd([
        row["Average Gas"] for row in rows
    ])

    summary_rows.append({
        "Arrival Rate": rate,
        "Valid Trials": len(rows),
        "Latency Mean(ms)": round(latency_mean, 4),
        "Latency SD(ms)": round(latency_sd, 4),
        "Throughput Mean": round(throughput_mean, 4),
        "Throughput SD": round(throughput_sd, 4),
        "Gas Mean": round(gas_mean, 4),
        "Gas SD": round(gas_sd, 4)
    })


with open(SUMMARY_FILE, "w", newline="", encoding="utf-8") as file:

    if summary_rows:

        writer = csv.DictWriter(
            file,
            fieldnames=list(summary_rows[0].keys())
        )

        writer.writeheader()
        writer.writerows(summary_rows)


print("\n====================================")
print("ARRIVAL RATE EXPERIMENT COMPLETED")
print("====================================")

for row in summary_rows:
    print(row)

print("\nGenerated files:")
print(DETAIL_FILE)
print(RESULT_FILE)
print(SUMMARY_FILE)
