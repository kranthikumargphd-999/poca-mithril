"""R1.3 controlled Store.sol anchoring experiment (benchmark-only fixtures).

Three matched arms, each using the same five deterministic mock proof records:
  individual: five transactions storing complete separate proof records
  full_batch: one transaction storing all five full proof records
  relay_summary: one transaction approximating the PRODUCTION relay's batch-summary
                 JSON fields, excluding full proof records

IMPORTANT: The relay_summary arm is a production-FORMAT proxy, NOT a run through
MithrilBatchProcessor.anchor_batch or a cryptographic verification experiment.
It has less on-chain information than individual/full_batch. Its lower gas cost
(if observed) cannot be attributed to batching alone.

Execute in the PROJECT ROOT:
  python -m app.blockchain.r1_3_matched_benchmark_v2

Place this file at app/blockchain/r1_3_matched_benchmark_v2.py.
Requires running local Ganache and the deployed Store.sol configuration.
Writes r1_3_matched_results_v2.csv alongside this script. Does not overwrite
r1_3_matched_results.csv. Submits 21 test transactions (3 * (5 + 1 + 1)).
"""
import base64
import csv
import hashlib
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from app.blockchain.logic import web3, contract_file, DEFAULT_ACCOUNT

TRIALS = 3
BATCH_SIZE = 5
OUT = Path(__file__).with_name("r1_3_matched_results_v2.csv")
MODES = ("individual", "full_batch", "relay_summary")


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def contract_encoded(obj) -> str:
    # Match addNewData's base64(JSON) approach, but use a consistent deterministic
    # JSON encoding for all three modes to avoid serializer variation.
    return base64.b64encode(canonical_json(obj)).decode("ascii")


def fixtures(trial):
    records = []
    for i in range(BATCH_SIZE):
        proof_id = f"R13-T{trial:02d}-P{i + 1:02d}"
        records.append({
            "proof_id": proof_id,
            "agent_id": "AGT-R13-BENCH",
            "context_hash": "sha256:" + sha256((proof_id + ":context").encode()).hex(),
            "model_hash": "sha256:" + sha256(b"r13-model-fixture").hex(),
            "timestamp": "2026-10-17T00:00:00+00:00",
            "safety_score": "0.87",
            "signature_fixture_hash": "sha256:" + sha256((proof_id + ":signature-fixture").encode()).hex(),
        })
    return records


def merkle_root_from_signatures(records):
    # Benchmark proxy for Merkle hashing of proof signatures. The fixture hashes
    # are NOT ECDSA signatures or validated PoCA proof data.
    nodes = [sha256(r["signature_fixture_hash"].encode("ascii")) for r in records]
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [sha256(nodes[i] + nodes[i + 1]) for i in range(0, len(nodes), 2)]
    return nodes[0].hex()


def batch_signature_digest(records):
    # Proxy digest of ordered signature fixtures, not an aggregated signature.
    return sha256(b"".join(bytes.fromhex(r["signature_fixture_hash"][7:]) for r in records)).hex()


def make_payloads(records, trial, mode):
    if mode == "individual":
        return [{"type": "r13_individual_full_record", "trial": trial, "proof": r} for r in records]
    if mode == "full_batch":
        return [{
            "type": "r13_batch_full_records", "trial": trial,
            "num_proofs": len(records), "proofs": records,
            "merkle_root": merkle_root_from_signatures(records),
            "batch_digest": batch_signature_digest(records),
        }]
    if mode == "relay_summary":
        return [{
            # Follow the field SHAPE seen in app/batch_processor.py anchor_batch()
            "type": "mithril_batch", "batch_id": f"R13-BATCH-T{trial:02d}",
            "agents": [{
                "agent_id": "AGT-R13-BENCH",
                "agent_name": "R13 benchmark agent",
                "did": "did:secureai:r13-benchmark-fixture",
                "model_hash": records[0]["model_hash"],
            }],
            "merkle_root": merkle_root_from_signatures(records),
            "aggregated_signature": batch_signature_digest(records),
            "num_proofs": len(records),
            "timestamp": "2026-10-17T00:00:00+00:00",
        }]
    raise ValueError(f"Unknown mode: {mode}")


def measure(trial, mode, records):
    payloads = make_payloads(records, trial, mode)
    # Matched zero-spread arrival; one serial submitter per arm. The two
    # batching modes represent the same five records in one transaction.
    start = time.perf_counter()
    completion_seconds = []
    tx_hashes = []
    gas_used = []
    byte_lengths = []
    for payload in payloads:
        encoded = contract_encoded(payload)
        byte_lengths.append(len(encoded.encode("ascii")))
        tx_hash = contract_file.functions.addString(encoded).transact({"from": DEFAULT_ACCOUNT})
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise RuntimeError(f"Failed transaction: {tx_hash.hex()}")
        gas_used.append(int(receipt.gasUsed))
        tx_hashes.append(tx_hash.hex())
        completion_seconds.append(time.perf_counter() - start)
    elapsed = completion_seconds[-1]
    proof_completion = (completion_seconds if mode == "individual"
                        else [elapsed] * len(records))
    return {
        "trial": trial,
        "mode": mode,
        "records": len(records),
        "transactions": len(payloads),
        "elapsed_s": round(elapsed, 6),
        "mean_proof_completion_ms": round(statistics.mean(proof_completion) * 1000, 3),
        "last_proof_completion_ms": round(max(proof_completion) * 1000, 3),
        "throughput_proofs_per_s": round(len(records) / elapsed, 4),
        "total_gas": sum(gas_used),
        "gas_per_proof": round(sum(gas_used) / len(records), 2),
        "total_encoded_bytes": sum(byte_lengths),
        "transaction_hashes": ";".join(tx_hashes),
    }


def main():
    if not web3.is_connected():
        raise RuntimeError("Ganache is not connected")
    if not web3.eth.get_code(contract_file.address):
        raise RuntimeError("No deployed Store.sol code at configured contract address")
    print("Store.sol:", contract_file.address, "chain:", web3.eth.chain_id)
    print("R1.3: three matched benchmark arms;", TRIALS, "trials;", BATCH_SIZE, "records per trial")
    print("Single serial submission worker, zero-spread arrival, receipt timing for all arms.")
    print("NOTE: relay_summary is a production-FORMAT proxy, not a verified PoCA relay execution.")
    rows = []
    for trial in range(1, TRIALS + 1):
        records = fixtures(trial)
        # Rotate run order to reduce one-mode-always-first effects.
        order = MODES[(trial - 1):] + MODES[:(trial - 1)]
        for mode in order:
            row = measure(trial, mode, records)
            rows.append(row)
            print(f"trial={trial} mode={mode} tx={row['transactions']} "
                  f"gas={row['total_gas']} elapsed_s={row['elapsed_s']} "
                  f"throughput={row['throughput_proofs_per_s']}")
    with OUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("\nSaved:", OUT)
    for mode in MODES:
        group = [row for row in rows if row["mode"] == mode]
        print(mode, "mean gas/proof:", round(statistics.mean(r["gas_per_proof"] for r in group), 2),
              "mean throughput:", round(statistics.mean(r["throughput_proofs_per_s"] for r in group), 3),
              "mean completion ms:", round(statistics.mean(r["mean_proof_completion_ms"] for r in group), 3),
              "encoded bytes:", round(statistics.mean(r["total_encoded_bytes"] for r in group), 1))
    print("CAUTION: Different on-chain representations. Do not infer isolated scheduling/relay superiority.")


if __name__ == "__main__":
    main()
