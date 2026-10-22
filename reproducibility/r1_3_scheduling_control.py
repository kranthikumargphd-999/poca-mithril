
import csv
import hashlib
import json
import queue
import statistics
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = PROJECT_ROOT / "reproducibility" / "r1_3_scheduling_results.csv"

TRIALS = 30

# Identical deterministic workload in both conditions
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
    proofs, sort_keys=True, separators=(",", ":")
).encode()


def process_payload(data):
    # Fixed, identical work in both conditions.
    return hashlib.sha256(data).hexdigest()


def immediate_run():
    start = time.perf_counter_ns()
    result = process_payload(payload)
    end = time.perf_counter_ns()
    return result, (end - start) / 1_000_000


def queued_run():
    jobs = queue.Queue()
    completed = threading.Event()
    output = {}

    def worker():
        item = jobs.get()
        try:
            output["result"] = process_payload(item)
            output["finished_ns"] = time.perf_counter_ns()
        finally:
            completed.set()
            jobs.task_done()

    thread = threading.Thread(target=worker)
    thread.start()

    start = time.perf_counter_ns()
    jobs.put(payload)
    completed.wait()
    elapsed_ms = (
        output["finished_ns"] - start
    ) / 1_000_000

    thread.join()
    return output["result"], elapsed_ms


rows = []

if OUTPUT.exists():
    raise RuntimeError(
        "Results already exist. Preserve them before rerunning."
    )

# Warm-up
immediate_run()
queued_run()

for trial in range(1, TRIALS + 1):
    # Alternate order to reduce systematic order effects.
    methods = (
        ["immediate", "queued"]
        if trial % 2
        else ["queued", "immediate"]
    )

    for method in methods:
        if method == "immediate":
            result, duration = immediate_run()
        else:
            result, duration = queued_run()

        if result != process_payload(payload):
            raise RuntimeError("Output mismatch")

        rows.append({
            "trial": trial,
            "method": method,
            "duration_ms": duration,
            "payload_bytes": len(payload),
            "output_hash": result,
        })


with open(OUTPUT, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(
        file, fieldnames=rows[0].keys()
    )
    writer.writeheader()
    writer.writerows(rows)


print("=" * 60)
print("R1.3 SCHEDULING MICROBENCHMARK")
print("=" * 60)

for method in ["immediate", "queued"]:
    values = [
        row["duration_ms"]
        for row in rows
        if row["method"] == method
    ]

    print(
        method,
        "| trials:", len(values),
        "| mean ms:", round(statistics.mean(values), 6),
        "| median ms:", round(statistics.median(values), 6),
        "| stdev ms:", round(statistics.stdev(values), 6),
    )

print("CSV SAVED:", OUTPUT)
