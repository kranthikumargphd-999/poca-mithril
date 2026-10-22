import os
import sys
import django
from pathlib import Path

# Locate project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(PROJECT_ROOT))

# Use isolated benchmark database
os.environ["R12_BENCHMARK_DB"] = "0"
os.environ["R13_BENCHMARK_DB"] = "1"
os.environ["DJANGO_SETTINGS_MODULE"] = "secureAI.settings"

django.setup()

from django.conf import settings
from app.models import Agent, PoCAProof
from app.crypto_utils import (
    verify_poca_signature,
    verify_poca_signature_onchain,
)

print("=" * 60)
print("R1.3 FINAL CONTROLLED EXPERIMENT")
print("=" * 60)

print("Database:", settings.DATABASES["default"]["NAME"])

print("Total proofs:", PoCAProof.objects.count())

print("Total agents:", Agent.objects.count())



# ==========================================================
# STEP 2: SELECT FIVE VALID SIGNED PROOFS
# ==========================================================

from app.crypto_utils import verify_poca_signature

candidate_proofs = (
    PoCAProof.objects
    .select_related("agent")
    .filter(agent__agent_id="AGT-0005")
    .order_by("-id")
)

verified_proofs = []

for proof in candidate_proofs:
    if verify_poca_signature(proof):
        verified_proofs.append(proof)

    if len(verified_proofs) == 5:
        break

if len(verified_proofs) != 5:
    raise RuntimeError(
        f"Expected 5 valid proofs, found {len(verified_proofs)}"
    )

print("\nSELECTED FIVE VERIFIED PROOFS")

for proof in verified_proofs:
    print(
        proof.proof_id,
        "| Agent:", proof.agent.agent_id,
        "| Signature valid: True"
    )


# ==========================================================
# STEP 3: BUILD IDENTICAL LOGICAL PROOF RECORDS
# ==========================================================

import json
import hashlib

proof_records = []

for proof in verified_proofs:
    record = {
        "proof_id": proof.proof_id,
        "agent_did": proof.agent.did,
        "context_hash": proof.context_hash,
        "model_hash": proof.model_hash,
        "attestation_timestamp": proof.attestation_timestamp.isoformat(),
        "safety_score": format(proof.safety_score, ".2f"),
        "signature": proof.signature,
    }

    proof_records.append(record)

# Canonical JSON serialization
serialized_records = [
    json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )
    for record in proof_records
]

# One record per transaction
individual_payloads = serialized_records

# Same five complete records in one transaction
batch_payload = json.dumps(
    proof_records,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False
)

print("\nR1.3 PAYLOAD EQUIVALENCE CHECK")

print("Proof records:", len(proof_records))
print("Individual payloads:", len(individual_payloads))
print("Batch payloads:", 1)

individual_hashes = [
    hashlib.sha256(payload.encode("utf-8")).hexdigest()
    for payload in individual_payloads
]

batch_records = json.loads(batch_payload)

batch_hashes = [
    hashlib.sha256(
        json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    for record in batch_records
]

same_information = individual_hashes == batch_hashes

print("SAME FIVE PROOF RECORDS:", same_information)

if not same_information:
    raise RuntimeError("Payload-equivalence check failed.")



# ==========================================================
# STEP 4: FINAL MATCHED-INFORMATION BLOCKCHAIN COMPARISON
# ==========================================================

import time
import csv
from datetime import datetime, timezone as dt_timezone
from app.blockchain.logic import addNewData

# IMPORTANT:
# This experiment submits SIX transactions to Ganache:
# five individual transactions and one batch transaction.

def run_anchor_experiment(method, payloads):
    results = []
    experiment_start = time.perf_counter()

    for payload in payloads:
        tx_start = time.perf_counter()

        result = addNewData(json.loads(payload))

        tx_end = time.perf_counter()

        if not result.get("success"):
            raise RuntimeError(
                f"{method} transaction failed: {result}"
            )

        results.append({
            "gas": result["gas_used"],
            "duration_ms": (tx_end - tx_start) * 1000,
            "tx_hash": result["tx_hash"],
        })

    total_duration = time.perf_counter() - experiment_start

    return {
        "method": method,
        "transactions": len(results),
        "total_gas": sum(r["gas"] for r in results),
        "gas_per_proof": sum(r["gas"] for r in results) / 5,
        "duration_ms": total_duration * 1000,
        "throughput_proofs_per_second": 5 / total_duration,
        "transaction_hashes": ";".join(
            r["tx_hash"] for r in results
        ),
    }


# Same five complete proof records
individual_results = run_anchor_experiment(
    "individual_full_records",
    individual_payloads
)

batch_results = run_anchor_experiment(
    "batch_full_records",
    [batch_payload]
)

print("\nFINAL R1.3 CONTROLLED RESULTS")

for result in [individual_results, batch_results]:
    print(
        result["method"],
        "| Transactions:", result["transactions"],
        "| Total gas:", result["total_gas"],
        "| Gas/proof:", round(result["gas_per_proof"], 2),
        "| Throughput:", round(
            result["throughput_proofs_per_second"], 4
        ),
        "proofs/s"
    )


# Save experiment results
output_file = (
    PROJECT_ROOT
    / "reproducibility"
    / "r1_3_final_control_results.csv"
)

with open(output_file, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "method",
            "transactions",
            "total_gas",
            "gas_per_proof",
            "duration_ms",
            "throughput_proofs_per_second",
            "transaction_hashes",
        ]
    )

    writer.writeheader()
    writer.writerows([individual_results, batch_results])

print("\nSaved results to:", output_file)


