
import csv
import hashlib
import json
import queue
import statistics
import threading
import time
from pathlib import Path

OUTPUT = (
    Path(__file__).resolve().parent
    / "r1_3_persistent_worker_results.csv"
)

TRIALS = 30

# Same deterministic workload in both methods
proofs = [
    {
        "proof_id": f"R13-SCHED-{i:03d}",
        "context_hash": hashlib.sha256(
            f"context-{i}".encode()
        ).hexdigest(),
        "signature": "a1" * 64,
    }
    for i in range(5)
]

payload = json.dumps(
    proofs,
    sort_keys=True,
    separators=(",", ":")
).encode("utf-8")


def process_payload(data):
    return hashlib.sha256(data).hexdigest()


jobs = queue.Queue()

# Worker starts BEFORE measurement begins.
def worker():
    while True:
        job = jobs.get()

        if job is None:
            jobs.task_done()
            break

        data, output = job
        output["start_ns"] = time.perf_counter_ns()
        output["result"] = process_payload(data)
        output["end_ns"] = time.perf_counter_ns()
        output["event"].set()
        jobs.task_done()


thread = threading.Thread(target=worker, daemon=True)
thread.start()


def run_immediate():
    start = time.perf_counter_ns()
    result = process_payload(payload)
    end = time.perf_counter_ns()

    return {
        "result": result,
        "total_ms": (end - start) / 1_000_000,
        "queue_ms": 0.0,
        "processing_ms": (end - start) / 1_000_000,
    }


def run_queued():
    output = {"event": threading.Event()}

    start = time.perf_counter_ns()
    jobs.put((payload, output))
    output["event"].wait()
    end = time.perf_counter_ns()

    return {
        "result": output["result"],
        "total_ms": (end - start) / 1_000_000,
        "queue_ms": (
            output["start_ns"] - start
        ) / 1_000_000,
        "processing_ms": (
            output["end_ns"] - output["start_ns"]
        ) / 1_000_000,
    }


rows = []

# Warm-up
run_immediate()
run_queued()

for trial in range(1, TRIALS + 1):
    methods = (
        ["immediate", "queued"]
        if trial % 2
        else ["queued", "immediate"]
    )

    for method in methods:
        measurement = (
            run_immediate()
            if method == "immediate"
            else run_queued()
        )

        expected = process_payload(payload)

        if measurement["result"] != expected:
            raise RuntimeError("Processing output mismatch")

        rows.append({
            "trial": trial,
            "method": method,
            "payload_bytes": len(payload),
            "total_ms": measurement["total_ms"],
            "queue_ms": measurement["queue_ms"],
            "processing_ms": measurement["processing_ms"],
            "output_hash": measurement["result"],
        })


# Stop persistent worker after measurements
jobs.put(None)
jobs.join()
thread.join()

if OUTPUT.exists():
    raise RuntimeError(
        "CSV already exists. Preserve previous results."
    )

with open(OUTPUT, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=list(rows[0].keys())
    )
    writer.writeheader()
    writer.writerows(rows)


print("=" * 60)
print("R1.3 PERSISTENT WORKER CONTROL")
print("=" * 60)

for method in ["immediate", "queued"]:
    subset = [
        row for row in rows
        if row["method"] == method
    ]

    for metric in ["total_ms", "queue_ms", "processing_ms"]:
        values = [row[metric] for row in subset]

        print(
            method,
            metric,
            "| mean:",
            round(statistics.mean(values), 6),
            "| median:",
            round(statistics.median(values), 6),
        )

print("\nCSV SAVED:", OUTPUT)
