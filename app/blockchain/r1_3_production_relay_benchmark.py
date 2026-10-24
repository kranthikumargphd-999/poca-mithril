"""R1.3 production-relay validation (explicitly opt-in, MUTATES DB AND GANACHE).
Place at app/blockchain/r1_3_production_relay_benchmark.py and run from project root:
python -m app.blockchain.r1_3_production_relay_benchmark --agent-id AGT-0005 --user-id 1
python -m app.blockchain.r1_3_production_relay_benchmark --agent-id AGT-0005 --user-id 1 --execute
Run ONLY on a backup/isolated clone of your SQLite database and local Ganache state.
Requires a pre-existing agent whose keys match exactly one live blockchain
agent_registration record; the code does not register or modify an agent.
Every trial generates and formally accepts five *valid, actual ECDSA-signed* PoCA database rows.
Both arms use the SAME five proofs and signed metadata. Baseline performs
two-phase snapshot-based live-registry verification and one-proof Merkle
hash/digest, then issues five Store.sol transactions. Relay executes the
production MithrilBatchProcessor.process_pending_batches() entry point, including
DB reservation, live verification, Merkle aggregation, batching, and persistence.
The two arms intentionally use the SAME mithril_batch payload FIELD SCHEMA,
but their roots, counts, IDs, and actual ABI calldata differ (1 vs 5 proofs).
The comparison measures a production-relay workflow against a carefully aligned
single-proof baseline, NOT a proof of byte-for-byte identical calldata.
Outputs r1_3_production_relay_results_revised.csv (NEW file) and one console summary.
Production stage timings are captured from the existing R13_TIMING instrumentation.
NOTE: completion latencies start with pre-generated, already-signed proofs; no AI
response creation or signing latency is included. Queue wait includes proof age
from database creation, so it is not identical to post-start dispatch delay.
The script will NOT run without --execute. No cleanup is attempted because
blockchain writes are irreversible; use your isolated snapshot to roll back.
"""
import argparse
import base64
import csv
import json
import statistics
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "secureAI.settings")
import django
django.setup()
from django.utils import timezone
from app.models import Agent, PoCAProof, Users
from app.crypto_utils import (
    generate_context_hash, generate_signature, generate_did,
    build_merkle_tree,
    generate_aggregated_signature,
    verify_poca_signature_with_registry
)
from app.batch_processor import MithrilBatchProcessor
from app.proof_acceptance import accept_poca_proof
import app.batch_processor as batch_module
from app.blockchain.logic import web3, contract_file, addNewData, retrieveData

TRIALS = 30
BATCH_SIZE = 5

WORKER_COUNT = 1
ARRIVAL_INTERVAL_SECONDS = 0.0

OUT = Path(__file__).with_name('r1_3_production_relay_results_revised.csv')
TIMING_FILE = Path(__file__).resolve().parents[2] / 'reproducibility' / 'r1_3_component_timings.csv'


def ensure_agent_registration(agent):
    registrations = retrieveData()
    if not isinstance(registrations, list):
        raise RuntimeError('Could not retrieve live blockchain registry')
    matches = [r for r in registrations if isinstance(r, dict)
            and r.get('type') == 'agent_registration'
            and r.get('agent_id') == agent.agent_id]
    if len(matches) != 1:
        raise RuntimeError(f'Expected exactly one registration for {agent.agent_id}; found {len(matches)}')
    r = matches[0]
    if any(r.get(k) != getattr(agent, k) for k in ('did', 'public_key', 'model_hash')):
        raise RuntimeError('On-chain agent DID/public-key/model-hash differs from Django agent')
    if generate_did(agent.public_key) != agent.did:
        raise RuntimeError('Agent DID is inconsistent with its public key')


def make_signed_proofs(agent, user, trial):
    """Create persisted, uniquely identified records. No AI API call is needed."""
    records = []
    for index in range(BATCH_SIZE):
        # proof_id max_length=20; use 8 UUID hex characters and a short prefix.*
        proof_id = 'R13-' + uuid.uuid4().hex[:12].upper()
        query = f'R1.3 production benchmark trial {trial}, item {index + 1}'
        when = timezone.now()
        context_hash = generate_context_hash(query, user.pk, agent.pk)
        safety = 0.87
        signature = generate_signature(
            proof_id=proof_id,
            agent_did=agent.did,
            context_hash=context_hash,
            model_hash=agent.model_hash,
            timestamp=when.isoformat(),
            safety_score=safety,
            private_key_encrypted=agent.private_key_encrypted,
        )
        proof = PoCAProof.objects.create(
            proof_id=proof_id, agent=agent, submitted_by=user,
            query_text=query, ai_response='Benchmark fixture only; no generated response',
            context_hash=context_hash, model_hash=agent.model_hash,
            safety_score=safety, attestation_timestamp=when, signature=signature,
            is_batched=False,
        )
        # Route the fixture through the same cryptographic acceptance gate*
        # used by submit_query_view. Do not fabricate accepted_at timestamps.*
        accepted, status = accept_poca_proof(proof.proof_id)
        if not accepted:
            raise RuntimeError(
                f'Benchmark proof acceptance failed for {proof.proof_id}: {status}'
            )
        proof.refresh_from_db()
        records.append(proof)
    return records


def agent_info(agent):
    return {
        'agent_id': agent.agent_id,
        'agent_name': agent.name,
        'did': agent.did,
        'model_hash': agent.model_hash,
    }


def build_single_payload(proof):
    """Same production batch-summary FIELD SCHEMA, with num_proofs=1."""
    return {
        'type': 'mithril_batch',
        'batch_id': 'R13S-' + uuid.uuid4().hex[:12].upper(),
        'agents': [agent_info(proof.agent)],
        'merkle_root': build_merkle_tree([proof.signature])['root'],
        'aggregated_signature': generate_aggregated_signature([proof]),
        'num_proofs': 1,
        'timestamp': timezone.now().isoformat(),
    }


def details_for_transaction(tx_hash, stored_obj):
    """Actual chain-calldata size; produced app data is *not* ABI calldata."""
    tx = web3.eth.get_transaction(tx_hash)
    raw = tx['input']
    calldata_size = len(bytes.fromhex(raw[2:])) if isinstance(raw, str) else len(raw)
    encoded = base64.b64encode(json.dumps(stored_obj).encode()).decode()
    return calldata_size, len(encoded.encode('ascii'))


def individual_arm(proofs):
    """Sequential individual anchors; same two registry-read phases as relay.
    Identical pre-signed proof input; one worker; all five are ready at start.
    The completion clock begins when the individual arm starts. Initial and
    recheck registry reads are timed and counted in the verification total.
    """
    started = time.perf_counter()
    gas, completions, calldata_bytes, encoded_bytes, hashes = [], [], [], [], []
    hashing_seconds = 0.0
    chain_seconds = 0.0
    initial_start = time.perf_counter()
    initial_registry = retrieveData()
    if not isinstance(initial_registry, list):
        raise RuntimeError('Initial blockchain registry retrieval failed')
    for proof in proofs:
        if not proof.signature or not verify_poca_signature_with_registry(proof, initial_registry):
            raise RuntimeError(f'Initial live verification failed: {proof.proof_id}')
    initial_verify_seconds = time.perf_counter() - initial_start
    prepared = []
    for proof in proofs:
        before = time.perf_counter()
        payload = build_single_payload(proof)
        hashing_seconds += time.perf_counter() - before
        prepared.append((proof, payload))
    # Fresh blockchain state at second-phase start, BEFORE any individual
    # anchoring. Exactly two full-registry reads, like the production relay.
    recheck_start = time.perf_counter()
    recheck_registry = retrieveData()
    if not isinstance(recheck_registry, list):
        raise RuntimeError('Second blockchain registry retrieval failed')
    for proof in proofs:
        if not proof.signature or not verify_poca_signature_with_registry(proof, recheck_registry):
            raise RuntimeError(f'Second live verification failed: {proof.proof_id}')
    recheck_verify_seconds = time.perf_counter() - recheck_start
    for proof, payload in prepared:
        before = time.perf_counter()
        result = addNewData(payload)
        chain_seconds += time.perf_counter() - before
        if not result.get('success'):
            raise RuntimeError(f'Individual anchor failure: {result}')
        gas.append(int(result['gas_used']))
        hashes.append(result['tx_hash'])
        cbytes, ebytes = details_for_transaction(result['tx_hash'], payload)
        calldata_bytes.append(cbytes)
        encoded_bytes.append(ebytes)
        completions.append(time.perf_counter() - started)
    elapsed = time.perf_counter() - started
    return {
        'transactions': len(hashes),
        'total_gas': sum(gas),
        'total_calldata_bytes': sum(calldata_bytes),
        'total_encoded_app_bytes': sum(encoded_bytes),
        'mean_proof_completion_ms': statistics.mean(completions) * 1000,
        'last_proof_completion_ms': completions[-1] * 1000,
        'elapsed_s': elapsed,
        'throughput_proofs_s': len(proofs) / elapsed,
        'verify_ms': (initial_verify_seconds + recheck_verify_seconds) * 1000,
        'merkle_and_digest_ms': hashing_seconds * 1000,
        'chain_receipt_ms': chain_seconds * 1000,
        'queue_wait_ms': '',
        'verification_initial_ms': initial_verify_seconds * 1000,
        'verification_recheck_ms': recheck_verify_seconds * 1000,
        'merkle_initial_ms': '',
        'merkle_recheck_ms': '',
        'transaction_hashes': ';'.join(hashes),
    }


@contextmanager
def record_production_anchor():
    """Wrap module's addNewData reference WITHOUT replacing production logic."""
    original = batch_module.addNewData
    captured = []
    def capture(payload):
        begun = time.perf_counter()
        outcome = original(payload)
        duration = time.perf_counter() - begun
        captured.append((payload, outcome, duration))
        return outcome
    batch_module.addNewData = capture
    try:
        yield captured
    finally:
        batch_module.addNewData = original


def relay_arm(proofs):
    """Run actual process_pending_batches, DB reservation and anchor_batch."""
    ids = {p.pk for p in proofs}
    pending_ids = set(MithrilBatchProcessor.get_pending_proofs(limit=BATCH_SIZE).values_list('pk', flat=True))
    if pending_ids != ids:
        raise RuntimeError('Pending queue differs from the five intended benchmark proofs')
    # The production processor already logs fine-grained stages when R13_TIMING=1.*
    # Capture the appended rows from THIS run only; never mix historical measurements.*
    log_offset = TIMING_FILE.stat().st_size if TIMING_FILE.exists() else 0
    started = time.perf_counter()
    with record_production_anchor() as captures:
        batch, message = MithrilBatchProcessor.process_pending_batches()
    elapsed = time.perf_counter() - started
    if batch is not None:
        batch.refresh_from_db()
    if batch is None or batch.status != 'anchored' or len(captures) != 1:
        raise RuntimeError(f'Production relay failed or performed unexpected transaction: {message}; {captures}')
    payload, result, chain_seconds = captures[0]
    if not result['success'] or batch.tx_hash != result['tx_hash']:
        raise RuntimeError('Mismatch between live receipt and recorded batch')
    cbytes, ebytes = details_for_transaction(result['tx_hash'], payload)
    recorded = {}
    if TIMING_FILE.exists():
        with TIMING_FILE.open('r', encoding='utf-8', newline='') as f:
            f.seek(log_offset)
            for line in f:
                cells = next(csv.reader([line]), [])
                # Instrumentation schema: timestamp, process_id, batch_id, metric, duration_ms*
                if len(cells) == 5 and cells[1] == str(os.getpid()):
                    try:
                        recorded.setdefault(cells[3], []).append(float(cells[4]))
                    except ValueError:
                        pass
    # Stage values are measurements of the original production code, not reconstructed estimates.*
    stage = lambda name: round(sum(recorded[name]), 4) if name in recorded else ''
    return {
        'transactions': 1,
        'total_gas': int(result['gas_used']),
        'total_calldata_bytes': cbytes,
        'total_encoded_app_bytes': ebytes,
        'mean_proof_completion_ms': elapsed * 1000,
        'last_proof_completion_ms': elapsed * 1000,
        'elapsed_s': elapsed,
        'throughput_proofs_s': len(proofs) / elapsed,
        'verify_ms': (round(sum(recorded.get('initial_verification', []) + recorded.get('reverification', [])), 4)
                    if 'initial_verification' in recorded and 'reverification' in recorded else ''),
        'merkle_and_digest_ms': (round(sum(recorded.get('merkle_construction', []) + recorded.get('merkle_recheck', [])), 4)
                                if 'merkle_construction' in recorded and 'merkle_recheck' in recorded else ''),
        'queue_wait_ms': stage('mean_queue_wait'),
        'verification_initial_ms': stage('initial_verification'),
        'verification_recheck_ms': stage('reverification'),
        'merkle_initial_ms': stage('merkle_construction'),
        'merkle_recheck_ms': stage('merkle_recheck'),
        'chain_receipt_ms': chain_seconds * 1000,
        'transaction_hashes': result['tx_hash'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-id', required=True, help='Existing registered agent ID, e.g. AGT-0005')
    parser.add_argument('--user-id', required=True, type=int, help='Existing user primary-key ID')
    parser.add_argument('--execute', action='store_true', help='EXPLICIT consent to write DB + Ganache')
    args = parser.parse_args()
    if not args.execute:
        print("DRY RUN. NO DATABASE OR BLOCKCHAIN CHANGES.")
        total_proofs = TRIALS * BATCH_SIZE
        total_batches = TRIALS
        total_transactions = TRIALS * (BATCH_SIZE + 1)
        print(f"Trials: {TRIALS}")
        print(f"Proofs per trial: {BATCH_SIZE}")
        print(f"Total signed proofs: {total_proofs}")
        print(f"Total batches: {total_batches}")
        print(f"Total blockchain transactions: {total_transactions}")
        print("Use isolated SQLite and Ganache backups.")
        return
    if WORKER_COUNT != 1 or ARRIVAL_INTERVAL_SECONDS != 0.0:
        raise RuntimeError('This implementation supports only one worker and simultaneous-ready proofs')
    os.environ['R13_TIMING'] = '1'  # Enable existing production stage logging.
    if not web3.is_connected() or not web3.eth.get_code(contract_file.address):
        raise RuntimeError('Ganache missing or Store.sol not deployed at configured address')
    agent = Agent.objects.get(agent_id=args.agent_id)
    user = Users.objects.get(pk=args.user_id)
    if not agent.private_key_encrypted:
        raise RuntimeError('Agent signing key unavailable')
    ensure_agent_registration(agent)
    if MithrilBatchProcessor.get_pending_count() != 0:
        raise RuntimeError('Cannot run production relay benchmark with existing pending proofs. Use isolated database.')
    print('Executing REAL production relay vs verified five-transaction baseline')
    print('Pre-generated, simultaneously ready proof comparison: AI generation, signing and live arrival scheduling excluded.')
    print('Store.sol', contract_file.address, 'chain', web3.eth.chain_id)
    rows = []
    for trial in range(1, TRIALS + 1):
        if MithrilBatchProcessor.get_pending_count() != 0:
            raise RuntimeError('Pending records unexpectedly exist between trials')
        proofs = make_signed_proofs(agent, user, trial)
        proof_ids = ';'.join(p.proof_id for p in proofs)
        # Alternate order. Relay-first leaves is_batched=True but baseline*
        # still verifies exactly the SAME immutable cryptographic fields.
        order = ('individual_verified', 'production_relay') if trial % 2 else ('production_relay', 'individual_verified')
        for mode in order:
            result = individual_arm(proofs) if mode == 'individual_verified' else relay_arm(proofs)
            rows.append({'trial': trial, 'mode': mode, 'proof_count': BATCH_SIZE,
                        'worker_count': WORKER_COUNT,
                        'arrival_interval_s': ARRIVAL_INTERVAL_SECONDS,
                         'proof_ids': proof_ids, **result})
            print('trial', trial, 'mode', mode, 'gas', result['total_gas'],
                'throughput', round(result['throughput_proofs_s'], 3),
                'calldata_bytes', result['total_calldata_bytes'])
    with OUT.open('w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print('\nSaved:', OUT)
    for mode in ('individual_verified', 'production_relay'):
        runs = [r for r in rows if r['mode'] == mode]
        print(mode, 'mean_gas_per_proof=', round(statistics.mean(r['total_gas'] / BATCH_SIZE for r in runs), 2),
            'mean_throughput=', round(statistics.mean(r['throughput_proofs_s'] for r in runs), 3),
            'mean_completion_ms=', round(statistics.mean(r['mean_proof_completion_ms'] for r in runs), 3),
            'mean_calldata_bytes=', round(statistics.mean(r['total_calldata_bytes'] for r in runs), 1))
    print('IMPORTANT: Same PoCA proofs and payload field schema; calldata content/length remains different.')
    print('Baseline is production-EQUIVALENT verification; relay is actual unmodified production entry point.')

if __name__ == '__main__':
    main()
