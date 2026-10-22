
import os
import sys
import csv
import json
import time
import hashlib
import statistics
from pathlib import Path

import django

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["R12_BENCHMARK_DB"] = "0"
os.environ["R13_BENCHMARK_DB"] = "1"
os.environ["DJANGO_SETTINGS_MODULE"] = "secureAI.settings"

django.setup()

from django.conf import settings
from app.models import PoCAProof
from app.crypto_utils import verify_poca_signature
from app.blockchain.logic import addNewData, web3

TRIALS = 3
EXPECTED_PROOF_COUNT = 5

PROOF_IDS = [
    "R13-CTRL-64F0B5211A7D",
    "R13-CTRL-B99201406702",
    "R13-CTRL-EDE951FB7525",
    "R13-CTRL-F4B66857FA32",
    "R13-CTRL-C5654615ABBC",
]

print("=" * 65)
print("R1.3 REPEATED MATCHED-ARRIVAL CONTROL")
print("=" * 65)
print("DATABASE:", settings.DATABASES["default"]["NAME"])

if not str(settings.DATABASES["default"]["NAME"]).endswith(
    "db_r13_benchmark_safe.sqlite3"
):
    raise RuntimeError("Incorrect benchmark database!")

proof_map = {
    proof.proof_id: proof
    for proof in PoCAProof.objects.select_related("agent").filter(
        proof_id__in=PROOF_IDS
    )
}

if len(proof_map) != EXPECTED_PROOF_COUNT:
    raise RuntimeError("Five experimental proofs were not found.")

proofs = [proof_map[proof_id] for proof_id in PROOF_IDS]

for proof in proofs:
    if not verify_poca_signature(proof):
        raise RuntimeError(
            f"Invalid proof signature: {proof.proof_id}"
        )

print("Five signed proofs validated.")

# ----------------------------------------------------------
# PREPARE SAME LOGICAL INFORMATION
# ----------------------------------------------------------

proof_records = []

for proof in proofs:
    proof_records.append({
        "proof_id": proof.proof_id,
        "agent_did": proof.agent.did,
        "context_hash": proof.context_hash,
        "model_hash": proof.model_hash,
        "attestation_timestamp":
            proof.attestation_timestamp.isoformat(),
        "safety_score": format(proof.safety_score, ".2f"),
        "signature": proof.signature,
    })

individual_payloads = proof_records
batch_payload = proof_records

def canonical(record):
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

assert [canonical(p) for p in individual_payloads] == [
    canonical(p) for p in batch_payload
]

print("LOGICAL PAYLOAD EQUIVALENCE: PASS")

# ----------------------------------------------------------
# TRANSACTION MEASUREMENT
# ----------------------------------------------------------

def get_calldata_bytes(tx_hash):
    tx = web3.eth.get_transaction(tx_hash)
    tx_input = tx["input"]

    if isinstance(tx_input, str):
        return len(bytes.fromhex(
            tx_input.removeprefix("0x")
        ))

    return len(bytes(tx_input))


def run_method(method, trial):
    payloads = (
        individual_payloads
        if method == "individual"
        else [batch_payload]
    )

    # All five proofs are available at the same
    # experimental arrival instant.
    arrival_start = time.perf_counter()

    gas_total = 0
    calldata_total = 0
    hashes = []
    proof_completion_ms = []

    for payload in payloads:
        result = addNewData(payload)

        if not result.get("success"):
            raise RuntimeError(
                f"Trial {trial}, {method}: {result}"
            )

        gas_total += result["gas_used"]
        calldata_total += get_calldata_bytes(
            result["tx_hash"]
        )
        hashes.append(result["tx_hash"])

        completion_ms = (
            time.perf_counter() - arrival_start
        ) * 1000

        if method == "individual":
            proof_completion_ms.append(completion_ms)
        else:
            proof_completion_ms.extend(
                [completion_ms] * EXPECTED_PROOF_COUNT
            )

    elapsed_s = time.perf_counter() - arrival_start

    return {
        "trial": trial,
        "method": method,
        "proofs": EXPECTED_PROOF_COUNT,
        "transactions": len(payloads),
        "total_gas": gas_total,
        "gas_per_proof":
            gas_total / EXPECTED_PROOF_COUNT,
        "total_calldata_bytes": calldata_total,
        "total_duration_ms": elapsed_s * 1000,
        "mean_proof_completion_ms":
            statistics.mean(proof_completion_ms),
        "throughput_proofs_s":
            EXPECTED_PROOF_COUNT / elapsed_s,
        "tx_hashes": ";".join(hashes),
    }


# ----------------------------------------------------------
# THREE PAIRED TRIALS - ALTERNATING EXECUTION ORDER
# ----------------------------------------------------------

orders = [
    ["individual", "batch"],
    ["batch", "individual"],
    ["individual", "batch"],
]

output_file = (
    PROJECT_ROOT
    / "reproducibility"
    / "r1_3_repeated_control_results.csv"
)

if output_file.exists():
    raise RuntimeError(
        "Results CSV already exists. Preserve the previous "
        "experiment before running again."
    )

rows = []

for trial, order in enumerate(orders, start=1):
    print(f"\nTRIAL {trial}: {' -> '.join(order)}")

    for method in order:
        result = run_method(method, trial)
        rows.append(result)

        print(
            method,
            "| Gas:", result["total_gas"],
            "| Calldata:", result["total_calldata_bytes"],
            "| Mean completion ms:",
            round(result["mean_proof_completion_ms"], 3),
            "| Throughput:",
            round(result["throughput_proofs_s"], 4),
        )

# ----------------------------------------------------------
# CSV EXPORT
# ----------------------------------------------------------

with open(
    output_file, "w", newline="", encoding="utf-8"
) as file:
    writer = csv.DictWriter(
        file, fieldnames=list(rows[0].keys())
    )
    writer.writeheader()
    writer.writerows(rows)

print("\n" + "=" * 65)
print("THREE-TRIAL SUMMARY")
print("=" * 65)

for method in ["individual", "batch"]:
    subset = [r for r in rows if r["method"] == method]

    print("\nMETHOD:", method)
    print(
        "MEAN GAS:",
        round(statistics.mean(
            r["total_gas"] for r in subset
        ), 2)
    )
    print(
        "MEAN COMPLETION MS:",
        round(statistics.mean(
            r["mean_proof_completion_ms"]
            for r in subset
        ), 3)
    )
    print(
        "MEAN THROUGHPUT:",
        round(statistics.mean(
            r["throughput_proofs_s"] for r in subset
        ), 4)
    )

print("\nCSV SAVED:", output_file)
