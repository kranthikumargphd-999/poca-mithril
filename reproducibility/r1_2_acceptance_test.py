import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SCRIPT = Path(__file__).resolve()


def setup_database(database_path):
    os.environ.setdefault(
        "DJANGO_SETTINGS_MODULE", "secureAI.settings"
    )

    from django.conf import settings

    settings.DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": str(database_path),
            "OPTIONS": {"timeout": 20},
        }
    }

    import django
    django.setup()


def worker(database_path, proof_id):
    setup_database(database_path)

    from app.models import Agent
    from django.db import connections

    agent = Agent.objects.get(agent_id="R12-AGENT")

    # Fixed registry fixture: real signature verification still runs.
    registry = [{
        "type": "agent_registration",
        "agent_id": agent.agent_id,
        "did": agent.did,
        "public_key": agent.public_key,
        "model_hash": agent.model_hash,
    }]

    blockchain_stub = ModuleType("app.blockchain.logic")
    blockchain_stub.retrieveData = lambda: registry

    with patch.dict(
        sys.modules,
        {"app.blockchain.logic": blockchain_stub},
    ):
        from app.proof_acceptance import accept_poca_proof
        accepted, status = accept_poca_proof(proof_id)

    connections.close_all()

    print("RESULT_JSON=" + json.dumps({
        "accepted": accepted,
        "status": status,
    }))


def call_worker(database_path, proof_id):
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--worker",
            str(database_path),
            proof_id,
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stdout + result.stderr)

    for line in reversed(result.stdout.splitlines()):
        if line.startswith("RESULT_JSON="):
            return json.loads(line.split("=", 1)[1])

    raise RuntimeError("Worker returned no result:\n" + result.stdout)


def run_tests(database_path):
    setup_database(database_path)

    import hashlib
    from django.core.management import call_command
    from django.db import connections
    from django.utils import timezone
    from ecdsa import SigningKey, SECP256k1

    from app.crypto_utils import canonical_poca_message, generate_did
    from app.models import Agent, PoCAProof, Users

    call_command("migrate", verbosity=0, interactive=False)

    key = SigningKey.from_string(
        bytes.fromhex("00" * 31 + "01"),
        curve=SECP256k1,
    )
    public_key = key.get_verifying_key().to_string().hex()

    user = Users.objects.create(
        username="r12_test_user",
        email="r12@example.invalid",
        password="unused-test-password",
    )

    agent = Agent.objects.create(
        agent_id="R12-AGENT",
        name="Replay test agent",
        llm_provider="ollama",
        model_name="test-model",
        api_key_encrypted="",
        private_key_encrypted="",
        public_key=public_key,
        did=generate_did(public_key),
        model_hash="sha256:test-model",
        registered_by=user,
    )

    def make_proof(proof_id):
        timestamp = timezone.now()

        message = canonical_poca_message(
            proof_id=proof_id,
            agent_did=agent.did,
            context_hash="sha256:test-context",
            model_hash=agent.model_hash,
            timestamp=timestamp.isoformat(),
            safety_score=0.87,
        )

        signature = key.sign_deterministic(
            message,
            hashfunc=hashlib.sha256,
        ).hex()

        return PoCAProof.objects.create(
            proof_id=proof_id,
            agent=agent,
            submitted_by=user,
            query_text="Test request",
            ai_response="Test response",
            context_hash="sha256:test-context",
            model_hash=agent.model_hash,
            safety_score=0.87,
            attestation_timestamp=timestamp,
            signature=signature,
        )

    # 1. Acceptance persists after the accepting process exits.
    proof = make_proof("R12-RESTART")
    connections.close_all()

    first = call_worker(database_path, proof.proof_id)
    second = call_worker(database_path, proof.proof_id)

    assert first == {"accepted": True, "status": "ACCEPTED"}, first
    assert second == {
        "accepted": False,
        "status": "ALREADY_ACCEPTED_OR_CHANGED",
    }, second

    proof.refresh_from_db()
    assert proof.accepted_at is not None
    print("PASS: first acceptance and replay after process restart")
    print("Restart results:", first, second)

    # 2. Five independent processes attempt the same acceptance.
    proof = make_proof("R12-CONCURRENT")
    connections.close_all()

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(
            lambda _: call_worker(database_path, proof.proof_id),
            range(5),
        ))

    accepted_count = sum(r["accepted"] for r in results)
    duplicate_count = sum(
        r["status"] == "ALREADY_ACCEPTED_OR_CHANGED"
        for r in results
    )
    busy_count = sum(
        r["status"] == "DATABASE_BUSY" for r in results
    )

    print("Concurrent results:", results)
    print(
        f"Accepted={accepted_count}, "
        f"Duplicate rejections={duplicate_count}, "
        f"Database busy={busy_count}"
    )

    assert accepted_count == 1, results
    assert duplicate_count + busy_count == 4, results

    proof.refresh_from_db()
    assert proof.accepted_at is not None
    print("PASS: exactly one acceptance across five processes")

    # 3. An invalid proof must not consume its identifier.
    proof = make_proof("R12-INVALID")
    original_signature = proof.signature

    PoCAProof.objects.filter(pk=proof.pk).update(signature="00")
    connections.close_all()

    invalid = call_worker(database_path, proof.proof_id)
    assert invalid == {
        "accepted": False,
        "status": "INVALID_PROOF",
    }, invalid

    proof.refresh_from_db()
    assert proof.accepted_at is None

    PoCAProof.objects.filter(pk=proof.pk).update(
        signature=original_signature
    )
    connections.close_all()

    valid = call_worker(database_path, proof.proof_id)
    assert valid == {"accepted": True, "status": "ACCEPTED"}, valid
    print("PASS: invalid proof rejected without consuming identifier")

    connections.close_all()
    print("ALL ACCEPTANCE CHECKS PASSED")
    print(
        "Scope: real ECDSA verification and shared file-based SQLite; "
        "blockchain registry responses were mocked."
    )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(sys.argv[2], sys.argv[3])
    else:
        with tempfile.TemporaryDirectory(prefix="r12_acceptance_") as folder:
            run_tests(Path(folder) / "acceptance.sqlite3")