import os
import sys
import json
import subprocess
import uuid
from pathlib import Path

# Find the folder containing manage.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Add the Django project root to Python's import path
sys.path.insert(0, str(PROJECT_ROOT))

# Use only the R1.2 benchmark database
os.environ["R12_BENCHMARK_DB"] = "1"
os.environ["R13_BENCHMARK_DB"] = "0"

# Configure Django
os.environ["DJANGO_SETTINGS_MODULE"] = "secureAI.settings"

import django
django.setup()

from django.db import (
    IntegrityError,
    OperationalError,
    transaction,
    connection,
)
from app.models import ProcessedRequest


def claim_request(request_id):
    try:
        with transaction.atomic():
            ProcessedRequest.objects.create(
                request_id=request_id
            )
        return "ACCEPTED"

    except IntegrityError:
        return "DUPLICATE_REJECTED"

    except OperationalError:
        return "DATABASE_BUSY"


def independent_verifier(request_id):
    connection.close()

    result = claim_request(request_id)

    print(json.dumps({
        "pid": os.getpid(),
        "request_id": request_id,
        "result": result
    }))


def run_process(request_id):
    environment = os.environ.copy()
    environment["R12_BENCHMARK_DB"] = "1"
    environment["R13_BENCHMARK_DB"] = "0"

    return subprocess.run(
        [
            sys.executable,
            os.path.abspath(__file__),
            "--verifier",
            request_id
        ],
        capture_output=True,
        text=True,
        env=environment
    )

from concurrent.futures import ThreadPoolExecutor
from collections import Counter

def test_concurrent_verifiers():
    print("\nTEST 3: Five concurrent independent verifiers")

    request_id = "R12-CONCURRENT-" + uuid.uuid4().hex

    with ThreadPoolExecutor(max_workers=5) as executor:
        processes = list(
            executor.map(
                run_process,
                [request_id] * 5
            )
        )

    results = []

    for process in processes:
        if process.returncode != 0:
            print("PROCESS ERROR:", process.stderr)
            return False

        try:
            result = json.loads(process.stdout)
            results.append(result)
        except ValueError:
            print("INVALID OUTPUT:", process.stdout)
            return False

    counts = Counter(
        result["result"] for result in results
    )

    database_count = ProcessedRequest.objects.filter(
        request_id=request_id
    ).count()

    print("Process results:")
    for result in results:
        print(result)

    print("Outcome counts:", dict(counts))
    print("Database record count:", database_count)

    passed = (
        counts["ACCEPTED"] == 1
        and counts["DUPLICATE_REJECTED"] == 4
        and counts["DATABASE_BUSY"] == 0
        and len({r["pid"] for r in results}) == 5
        and database_count == 1
    )

    if passed:
        print("PASS: All duplicate requests rejected")
    else:
        print("NOT FULLY PASSED: Inspect contention outcomes")

    return passed


def test_restart_persistence():
    print("\nTEST 4: Replay protection after verifier restart")

    request_id = "R12-RESTART-" + uuid.uuid4().hex

    # Verifier A starts, claims request ID, then exits.
    first = run_process(request_id)

    # A new independent verifier process starts afterward.
    second = run_process(request_id)

    if first.returncode != 0 or second.returncode != 0:
        print("FAIL: Verifier process error")
        print(first.stderr, second.stderr)
        return False

    try:
        result_a = json.loads(first.stdout)
        result_b = json.loads(second.stdout)
    except ValueError:
        print("FAIL: Invalid verifier output")
        return False

    database_count = ProcessedRequest.objects.filter(
        request_id=request_id
    ).count()

    print("Before restart:", result_a)
    print("After restart:", result_b)
    print("Database record count:", database_count)

    passed = (
        result_a["result"] == "ACCEPTED"
        and result_b["result"] == "DUPLICATE_REJECTED"
        and result_a["pid"] != result_b["pid"]
        and database_count == 1
    )

    if passed:
        print("PASS: Replay protection survives process restart")
    else:
        print("FAIL: Restart persistence test")

    return passed


def main():
    db_name = connection.settings_dict["NAME"]

    print("R1.2 INDEPENDENT VERIFIER TEST")
    print("Database:", db_name)

    request_id = "R12-SHARED-" + uuid.uuid4().hex

    print("\nTEST 1: Verifier A claims request")

    verifier_a = run_process(request_id)
    print(verifier_a.stdout.strip())

    print("\nTEST 2: Verifier B claims same request")

    verifier_b = run_process(request_id)
    print(verifier_b.stdout.strip())

    if verifier_a.returncode or verifier_b.returncode:
        print("FAIL: Verifier process error")
        print(verifier_a.stderr)
        print(verifier_b.stderr)
        sys.exit(1)

    try:
        result_a = json.loads(verifier_a.stdout)
        result_b = json.loads(verifier_b.stdout)
    except ValueError:
        print("FAIL: Invalid verifier output")
        sys.exit(1)

    database_count = ProcessedRequest.objects.filter(
        request_id=request_id
    ).count()

    passed = (
        result_a["result"] == "ACCEPTED"
        and result_b["result"] == "DUPLICATE_REJECTED"
        and result_a["pid"] != result_b["pid"]
        and database_count == 1
    )

    print("\nIndependent process IDs:",
          result_a["pid"], result_b["pid"])
    print("Database record count:", database_count)

    if passed:
        print("PASS: Independent verifiers share replay state")
    else:
        print("FAIL: Shared replay-state test")
        sys.exit(1)

    # Test simultaneous duplicate requests
    concurrent_passed = test_concurrent_verifiers()

    if not concurrent_passed:
        print(
            "Concurrent test needs further investigation."
        )
        sys.exit(1)
    
    restart_passed = test_restart_persistence()

    if not restart_passed:
        print("Restart persistence test needs investigation.")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--verifier":
        independent_verifier(sys.argv[2])
    else:
        main()
