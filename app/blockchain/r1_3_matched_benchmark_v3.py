"""R1.3 matched blockchain-storage comparison with a byte-matched control.

Run from secureAI project root:
    python -m app.blockchain.r1_3_matched_benchmark_v3

Place in app/blockchain/ alongside logic.py and V2 script. Requires local
Ganache and an existing Store.sol deployment. Writes only a NEW V3 CSV.

The four arms use the SAME five deterministic, unsigned benchmark fixtures:
  individual              5 Store.sol.addString transactions, one full record each
  full_batch              1 transaction with all five full records
  full_batch_byte_matched 1 full-record batch padded to MATCH the aggregate
                           encoded bytes of the five individual transactions
  relay_summary           1 production-format summary-proxy transaction

All arms: same contract/account, same zero-spread arrival schedule, one
serial worker, and common receipt-to-completion timing boundary. The
byte-matched control equalizes *aggregate base64-encoded application string
bytes*, not transaction-calldata bytes, number of ABI envelopes, or per-tx
payloads. The summary arm carries less information and does not execute
production PoCA verification or relay scheduling. DO NOT present these as
full end-to-end relay measurements or perfect isolation of batching alone.
"""
import base64
import csv
import hashlib
import json
import statistics
import time
from pathlib import Path

from app.blockchain.logic import web3, contract_file, DEFAULT_ACCOUNT

TRIALS = 3
BATCH_SIZE = 5
OUT = Path(__file__).with_name('r1_3_matched_results_v3.csv')
MODES = ('individual', 'full_batch', 'full_batch_byte_matched', 'relay_summary')


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def contract_encoded(obj) -> str:
    return base64.b64encode(canonical_json(obj)).decode('ascii')


def fixtures(trial):
    records = []
    for i in range(BATCH_SIZE):
        proof_id = f'R13-T{trial:02d}-P{i + 1:02d}'
        records.append({
            'proof_id': proof_id,
            'agent_id': 'AGT-R13-BENCH',
            'context_hash': 'sha256:' + sha256((proof_id + ':context').encode()).hex(),
            'model_hash': 'sha256:' + sha256(b'r13-model-fixture').hex(),
            'timestamp': '2026-10-17T00:00:00+00:00',
            'safety_score': '0.87',
            'signature_fixture_hash': 'sha256:' + sha256((proof_id + ':signature-fixture').encode()).hex(),
        })
    return records


def merkle_root_from_signatures(records):
    # Fixture hashes are NOT actual ECDSA signatures.
    nodes = [sha256(r['signature_fixture_hash'].encode('ascii')) for r in records]
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [sha256(nodes[i] + nodes[i + 1]) for i in range(0, len(nodes), 2)]
    return nodes[0].hex()


def batch_signature_digest(records):
    return sha256(b''.join(bytes.fromhex(r['signature_fixture_hash'][7:]) for r in records)).hex()


def individual_payloads(records, trial):
    return [{'type': 'r13_individual_full_record', 'trial': trial, 'proof': r} for r in records]


def full_batch_payload(records, trial):
    return {
        'type': 'r13_batch_full_records', 'trial': trial,
        'num_proofs': len(records), 'proofs': records,
        'merkle_root': merkle_root_from_signatures(records),
        'batch_digest': batch_signature_digest(records),
    }


def byte_matched_payload(records, trial):
    target = sum(len(contract_encoded(p).encode('ascii')) for p in individual_payloads(records, trial))
    base = full_batch_payload(records, trial)
    base['benchmark_padding'] = ''
    size_at_zero = len(contract_encoded(base).encode('ascii'))
    if size_at_zero > target:
        raise RuntimeError(f'Batch with padding field ({size_at_zero} bytes) exceeds individual total ({target})')
    # Each Base64 size is divisible by four. The target is the sum of five
    # Base64 lengths, so it is also divisible by four; an exact match exists.
    low, high = 0, target
    while low <= high:
        mid = (low + high) // 2
        base['benchmark_padding'] = '0' * mid
        current = len(contract_encoded(base).encode('ascii'))
        if current == target:
            return base
        if current < target:
            low = mid + 1
        else:
            high = mid - 1
    raise RuntimeError(f'Cannot match application-string length of {target} bytes')


def make_payloads(records, trial, mode):
    if mode == 'individual':
        return individual_payloads(records, trial)
    if mode == 'full_batch':
        return [full_batch_payload(records, trial)]
    if mode == 'full_batch_byte_matched':
        return [byte_matched_payload(records, trial)]
    if mode == 'relay_summary':
        return [{
            'type': 'mithril_batch', 'batch_id': f'R13-BATCH-T{trial:02d}',
            'agents': [{
                'agent_id': 'AGT-R13-BENCH',
                'agent_name': 'R13 benchmark agent',
                'did': 'did:secureai:r13-benchmark-fixture',
                'model_hash': records[0]['model_hash'],
            }],
            'merkle_root': merkle_root_from_signatures(records),
            'aggregated_signature': batch_signature_digest(records),
            'num_proofs': len(records),
            'timestamp': '2026-10-17T00:00:00+00:00',
        }]
    raise ValueError(f'Unknown mode: {mode}')


def measure(trial, mode, records):
    items = make_payloads(records, trial, mode)
    target_bytes = sum(len(contract_encoded(p)) for p in individual_payloads(records, trial))
    lengths = [len(contract_encoded(p)) for p in items]
    if mode == 'full_batch_byte_matched' and sum(lengths) != target_bytes:
        raise AssertionError('Byte-matched control does not have same aggregate encoded length')
    start = time.perf_counter()
    completions, gas, hashes = [], [], []
    for item in items:
        encoded = contract_encoded(item)
        tx_hash = contract_file.functions.addString(encoded).transact({'from': DEFAULT_ACCOUNT})
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise RuntimeError(f'Reverted transaction: {tx_hash.hex()}')
        gas.append(int(receipt.gasUsed))
        hashes.append(tx_hash.hex())
        completions.append(time.perf_counter() - start)
    elapsed = completions[-1]
    proof_times = completions if mode == 'individual' else [elapsed] * len(records)
    return {
        'trial': trial,
        'mode': mode,
        'records': len(records),
        'transactions': len(items),
        'elapsed_s': round(elapsed, 6),
        'mean_proof_completion_ms': round(statistics.mean(proof_times) * 1000, 3),
        'last_proof_completion_ms': round(max(proof_times) * 1000, 3),
        'throughput_proofs_per_s': round(len(records) / elapsed, 4),
        'total_gas': sum(gas),
        'gas_per_proof': round(sum(gas) / len(records), 2),
        'total_encoded_bytes': sum(lengths),
        'individual_aggregate_encoded_bytes': target_bytes,
        'transaction_hashes': ';'.join(hashes),
    }


def main():
    if not web3.is_connected():
        raise RuntimeError('Ganache is not connected')
    if not web3.eth.get_code(contract_file.address):
        raise RuntimeError('No deployed Store.sol code at configured address')
    print('Store.sol:', contract_file.address, 'chain:', web3.eth.chain_id)
    print('R1.3 V3: 4 modes, 3 paired trials, 5 unsigned proof fixtures per trial')
    print('Same zero-spread arrival, one serial sender, transaction receipt boundary')
    print('Byte-matched control matches aggregate encoded application-data bytes ONLY.')
    rows = []
    for trial in range(1, TRIALS + 1):
        records = fixtures(trial)
        order = MODES[(trial - 1):] + MODES[:(trial - 1)]
        for mode in order:
            result = measure(trial, mode, records)
            rows.append(result)
            print(f"trial={trial} mode={mode} tx={result['transactions']} "
                  f"encoded_bytes={result['total_encoded_bytes']} "
                  f"gas={result['total_gas']} elapsed_s={result['elapsed_s']} "
                  f"throughput={result['throughput_proofs_per_s']}")
    with OUT.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print('\nSaved:', OUT)
    for mode in MODES:
        group = [r for r in rows if r['mode'] == mode]
        print(mode, 'mean gas/proof:', round(statistics.mean(r['gas_per_proof'] for r in group), 2),
              'mean throughput:', round(statistics.mean(r['throughput_proofs_per_s'] for r in group), 3),
              'mean completion ms:', round(statistics.mean(r['mean_proof_completion_ms'] for r in group), 3),
              'encoded bytes:', round(statistics.mean(r['total_encoded_bytes'] for r in group), 1))
    print('LIMITATION: Calldata envelope/gas per transaction still differs; not a full PoCA relay.')


if __name__ == '__main__':
    main()
