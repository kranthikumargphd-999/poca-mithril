"""R1.3 controlled anchoring comparison for the deployed Store.sol contract.

Benchmark-only deterministic mock proof records; not signed PoCA proofs.
Same five records, one submission worker, immediate common arrival time,
same on-chain contract/encoding and transaction-receipt boundary.
Both modes store the same complete proof records. Batch additionally stores
an illustrative Merkle root and SHA256 batch digest; it is *not* the existing
production root-only relay payload.

Run in project root: python -m app.blockchain.r1_3_matched_benchmark
Requires Ganache running and app.blockchain.logic configured for its network.
"""
import base64
import csv
import hashlib
import json
import statistics
import time
from pathlib import Path
import sys

# Allow execution as python blockchain\r1_3_matched_benchmark.py from project root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.blockchain.logic import web3, contract_file, DEFAULT_ACCOUNT

TRIALS = 3
BATCH_SIZE = 5
OUT = Path(__file__).with_name("r1_3_matched_results.csv")


def h(data):
    return hashlib.sha256(data).digest()


def json_encode(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def sample_records(trial):
    # Identical semantic records in both arms; test-only hashes, no private keys.
    result = []
    for i in range(BATCH_SIZE):
        uid = f"R13-T{trial:02d}-P{i + 1:02d}"
        result.append({
            "proof_id": uid,
            "agent_id": "AGT-R13-BENCH",
            "context_hash": "sha256:" + h((uid + ":context").encode()).hex(),
            "model_hash": "sha256:" + h(b"r13-model-fixture").hex(),
            "timestamp": "2026-10-17T00:00:00+00:00",
            "safety_score": "0.87",
            "signature_fixture_hash": "sha256:" + h((uid + ":signature-fixture").encode()).hex(),
        })
    return result


def merkle_root(records):
    nodes = [h(json_encode(r).encode("ascii")) for r in records]
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [h(nodes[j] + nodes[j + 1]) for j in range(0, len(nodes), 2)]
    return nodes[0].hex()


def payloads(records, trial, mode):
    if mode == "individual":
        return [{"type": "r13_individual_full_record", "trial": trial, "proof": r}
                for r in records]
    digest = h(b"".join(bytes.fromhex(r["signature_fixture_hash"][7:]) for r in records)).hex()
    return [{
        "type": "r13_batch_full_records",
        "trial": trial,
        "num_proofs": len(records),
        "proofs": records,
        "merkle_root": merkle_root(records),
        "batch_digest": digest,
    }]


def measure(trial, mode, records):
    # Five records become eligible at the same moment in both arms (zero-spread
    # fixed arrival schedule); the submitting worker is one serial worker.
    items = payloads(records, trial, mode)
    start = time.perf_counter()
    completion = []
    gases = []
    tx_hashes = []
    sizes = []
    for payload in items:
        encoded = json_encode(payload)
        sizes.append(len(encoded.encode("ascii")))
        receipt = web3.eth.wait_for_transaction_receipt(
            contract_file.functions.addString(encoded).transact({"from": DEFAULT_ACCOUNT})
        )
        if receipt.status != 1:
            raise RuntimeError(f"Transaction reverted: {receipt.transactionHash.hex()}")
        gases.append(int(receipt.gasUsed))
        tx_hashes.append(receipt.transactionHash.hex())
        completion.append(time.perf_counter() - start)
    elapsed = completion[-1]
    # Every record in the batch completes when the single batch tx confirms.
    proof_completion = completion if mode == "individual" else [elapsed] * len(records)
    return {
        "trial": trial,
        "mode": mode,
        "records": len(records),
        "transactions": len(items),
        "elapsed_s": round(elapsed, 6),
        "mean_proof_completion_ms": round(statistics.mean(proof_completion) * 1000, 3),
        "last_proof_completion_ms": round(max(proof_completion) * 1000, 3),
        "throughput_proofs_per_s": round(len(records) / elapsed, 4),
        "total_gas": sum(gases),
        "gas_per_proof": round(sum(gases) / len(records), 2),
        "total_encoded_bytes": sum(sizes),
        "transaction_hashes": ";".join(tx_hashes),
    }


def main():
    if not web3.is_connected():
        raise RuntimeError("Ganache not connected: start Ganache on configured RPC")
    code = web3.eth.get_code(contract_file.address)
    if not code:
        raise RuntimeError("No contract code at configured Store.sol address")
    print("Store.sol:", contract_file.address, "chain:", web3.eth.chain_id)
    print("Running", TRIALS, "paired trials x", BATCH_SIZE, "proof fixtures; 1 serial worker")
    print("Both modes store complete identical proof fixture content on-chain.")
    rows = []
    for trial in range(1, TRIALS + 1):
        records = sample_records(trial)
        order = ("individual", "batch") if trial % 2 else ("batch", "individual")
        for mode in order:
            row = measure(trial, mode, records)
            rows.append(row)
            print(f"trial={trial} {mode}: tx={row['transactions']} gas={row['total_gas']} "
                  f"elapsed={row['elapsed_s']}s throughput={row['throughput_proofs_per_s']}/s")
    with OUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print("\nSaved:", OUT)
    for mode in ("individual", "batch"):
        selected = [r for r in rows if r["mode"] == mode]
        print(mode, "mean gas/proof:", round(statistics.mean(r["gas_per_proof"] for r in selected), 2),
              "mean throughput:", round(statistics.mean(r["throughput_proofs_per_s"] for r in selected), 3),
              "mean completion ms:", round(statistics.mean(r["mean_proof_completion_ms"] for r in selected), 3))
    print("IMPORTANT: This is controlled full-record storage batching, not production root-only anchoring.")


if __name__ == "__main__":
    main()
