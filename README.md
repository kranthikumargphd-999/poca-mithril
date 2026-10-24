# SecureAI — Blockchain-Verified AI Trust Platform

A Django-based platform that attaches cryptographic, blockchain-anchored proofs to AI agent responses, using two research contributions:

- PoCA (Proof-of-Context Attestation): request-context metadata, agent identity, registered model identifier, timestamp, and safety score are included in a canonical attestation signed with the agent’s private key. The current prototype does not include a response-content hash or verify model weights or runtime execution.
- **Novel 2 — Mithril-inspired Batch Aggregation:** individual proofs are collected into batches of `BATCH_SIZE` (default 5), combined into a Merkle tree, and anchored to the blockchain as a single transaction — rather than one transaction per proof.

> **Scope note for reviewers/examiners:** the "Mithril" batching implemented here uses a Merkle-tree root plus a hash-based signature aggregation, **not** full BLS/threshold cryptographic aggregation as in the original Mithril protocol. Similarly, PoCA uses context-hash + ECDSA signing, **not** a zero-knowledge proof circuit. Both are documented here explicitly as scoped proof-of-concept implementations; full threshold aggregation and ZK-SNARK circuits are identified as future work.

---

## 1. Architecture

```
┌─────────────────────────────────────────────┐
│  Django App (Users, Agents, Dashboard)       │
├─────────────────────────────────────────────┤
│  PoCA Engine        │  Mithril Batch Engine  │
│  (crypto_utils.py)  │  (batch_processor.py)  │
├─────────────────────────────────────────────┤
│  Blockchain Layer (app/blockchain/logic.py)  │
│  → Ganache (local Ethereum test chain)       │
│  → Store.sol (Truffle-deployed contract)     │
└─────────────────────────────────────────────┘
```

**Where data lives:**

| Data | SQLite | Ganache (on-chain) |
|---|---|---|
| Users, sessions | ✅ | ❌ |
| Agent name, description, API key (encrypted), private key (encrypted) | ✅ | ❌ never |
| Agent DID, public key, model hash | ✅ | ✅ (on registration) |
| Individual PoCA proof (query, response, signature) | ✅ | ❌ (only referenced later inside a batch) |
| Mithril batch (Merkle root, aggregated signature, tx hash, block number, gas used) | ✅ | ✅ |

---

## 2. Prerequisites

- Python 3.10+
- Node.js + npm (for Truffle/Ganache tooling)
- [Ganache](https://trufflesuite.com/ganache/) (desktop app)
- Truffle: `npm install -g truffle`
- A free [Groq](https://console.groq.com) API key (or OpenAI/Hugging Face/Ollama)

---

## 3. Setup — first time only

### 3.1 Python environment
```bash
pip install -r req.txt
# If requirements.txt doesn't exist yet, at minimum:
pip install django web3 cryptography ecdsa pillow
```

### 3.2 Ganache — create a SAVED workspace (not Quickstart)
1. Open Ganache → **New Workspace**
2. Name it (e.g. `PHD-WORKSPACE`)
3. Under "Truffle Projects" → Add Project → select `blocks/truffle-config.js`
4. Save, and confirm the RPC server shows `HTTP://127.0.0.1:7545`

Always reopen this **same saved workspace** going forward — a fresh Quickstart chain each time will change your accounts and orphan any previously deployed contract.

### 3.3 Deploy the smart contract (first time, or after editing `Store.sol`)
```bash
cd blocks
npx truffle migrate
```
This writes the deployed contract's address into `blocks/build/contracts/Store.json`. The Django code reads this address dynamically — you never need to hardcode it.

### 3.4 Django database setup
```bash
python manage.py makemigrations
python manage.py migrate
```

### 3.5 Configure Django secret and Fernet encryption keys (Windows CMD)

`secureAI/settings.py` reads both values from environment variables:

- `DJANGO_SECRET_KEY`: Django application signing secret.
- `FERNET_KEY`: encrypts/decrypts stored agent private keys and provider API keys.

**For a fresh local installation**, open Windows **Command Prompt (CMD)** at the project root. Generate and set both values in the **same CMD window**:

```cmd
for /f "delims=" %i in ('python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"') do @set "DJANGO_SECRET_KEY=%i"
for /f "delims=" %i in ('python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"') do @set "FERNET_KEY=%i"
```

> These exact commands are for an **interactive CMD prompt**. Inside a `.bat` or `.cmd` file use `%%i` instead of `%i`. In PowerShell, use different syntax. Setting only a secret value without the variable name does not configure Django.

Check that both variables exist without printing their secret values:

```cmd
python -c "import os; print('DJANGO_SECRET_KEY configured:', bool(os.getenv('DJANGO_SECRET_KEY'))); print('FERNET_KEY configured:', bool(os.getenv('FERNET_KEY')))"
python manage.py check
```

Both checks should print `True`, followed by a successful Django system check. Then apply migrations with `python manage.py migrate` and launch Django with `python manage.py runserver`.

**Important persistence warning:** `set` configures only the current CMD session. New terminals need the **same** keys restored through a private environment/secret manager. Generate Fernet keys **only once for a new installation**: replacing an existing Fernet key can make previously encrypted agent private keys and API credentials unreadable. Changing the Django secret key can invalidate signed sessions/tokens. Do not commit either secret, a real `.env` file, or the generated local database to GitHub. Never paste secret values into `secureAI/settings.py`; the settings module already reads environment variables.

### 3.6 Create the Administrator account
There is **no public sign-up path to Administrator** — this is deliberate, for security. Registering through the website always creates an End User. Create the one Admin account via the Django shell:
```bash
python manage.py shell
```
```python
from app.models import Users
if not Users.objects.filter(username='Admin_123').exists():
    admin = Users(username='Admin_123', email='admin@secureai.com', role='admin', is_active=True)
    admin.set_password('REPLACE_WITH_A_STRONG_UNIQUE_PASSWORD')  # choose your own before running
    admin.save()
    print("Admin created.")
else:
    print("Admin already exists.")
```
Log in at `/` using your own administrator password once the server is running (Section 4). Never publish real administrator credentials.

---

## 4. Running the project (every time)

1. **Open Ganache** → open your saved workspace (Section 3.2). Leave it running.
2. **Start Django:**
   ```bash
   python manage.py runserver
   ```
4. Visit `http://127.0.0.1:8000/`

You should **not** need to redeploy the contract or regenerate keys again — those are one-time setup steps. Restore the existing environment variables when opening a new terminal.

---

## 5. Usage guide

### 5.1 As Administrator
1. Log in with the Admin account created in Section 3.6.
2. **Register an AI Agent** (`Agents` → `Register New Agent`):
   - Agent Name — any label, e.g. `MedicalAssistant-GPT`
   - LLM Provider — `groq`, `openai`, `huggingface`, or `ollama`
   - Model Name — must be a real, current model string for that provider (e.g. `openai/gpt-oss-20b` for Groq — check https://console.groq.com/docs/models, as provider model names change over time)
   - API Key — get one free at https://console.groq.com (Groq) or the equivalent provider console; not required for Ollama (local models)
   - On submit: a keypair + DID are generated, the agent is saved, and its DID/public key/model hash are anchored on-chain in one transaction.
3. **View Agents / Users / PoCA Proofs / Mithril Batches / Blockchain Transactions / Reports** from the sidebar — all read live from the database.
4. **Verify a batch's integrity**: open any batch and click "Verify" — this recomputes the Merkle root from the proofs currently in the database and compares it to the root that was anchored on-chain. A mismatch means something was altered after anchoring.

### 5.2 As End User
1. Register a normal account from the landing page (always created as End User — role cannot be chosen at signup).
2. **Available Agents** → pick an active agent → **Submit Query**.
3. Behind the scenes: the AI responds → a safety score is calculated → the response is hashed and signed → saved as a `PoCAProof` (not yet on-chain).
4. Once 5 proofs (`MithrilBatchProcessor.BATCH_SIZE`) are pending, they are automatically batched into one Merkle tree and anchored on-chain in a single transaction.
5. **My History / Verified Responses / Verification Status** show proof status and let you download a verification report or view the transaction on the local explorer.

---

## 6. Key configuration

| Setting | Location | Purpose |
|---|---|---|
| `BATCH_SIZE` | `app/batch_processor.py` | Number of proofs collected before an automatic batch anchor (default 5) |
| `BATCH_TIMEOUT` | `app/batch_processor.py` | Seconds before a smaller batch is forced anyway (default 300) |
| `FERNET_KEY` | `secureAI/settings.py` | Encrypts agent private keys and API keys at rest |
| `GANACHE_RPC_URL` (implicit, `127.0.0.1:7545`) | `app/blockchain/logic.py` | Ganache connection |

---

## 7. Known limitations (documented for transparency, not oversights)

- **Mithril aggregation** is a Merkle-tree + hashed-signature-concatenation scheme, not full BLS threshold aggregation.
- **PoCA** is context-hash + ECDSA signing, not a zero-knowledge proof circuit.
- SQLite's `select_for_update()` locking is weaker than PostgreSQL/MySQL — fine for single-user demo/testing, not for concurrent production load.
- Ganache is a local test chain; nothing here is deployed to a public testnet or mainnet.

---

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `w3.is_connected()` returns `False` | Ganache isn't running, or running on a different port than 7545 |
| Contract address seems wrong / data "disappeared" | Ganache workspace was reset, or you used Quickstart instead of a saved workspace — see Section 3.2 |
| `ValueError: too many/not enough values to unpack` around batch anchoring | A view is calling `MithrilBatchProcessor.anchor_batch()` expecting the old 3-value return instead of the current 4-value one (`success, tx_hash, block_number, gas_used`) |
| Agent registration succeeds but no Ganache transaction appears | Check `addNewData()` in `app/blockchain/logic.py` returned `{"success": True, ...}` — inspect the Django console output for the raw result dict |

---

## 9. Project credits

Built as part of a PhD Q1 conference paper implementation. Django + Ganache/Truffle + Web3.py, with Groq/OpenAI/Hugging Face/Ollama as pluggable LLM backends.
---

## 10. Research experiment reproduction and evidence

**Research scope:** PoCA-Mithril authenticates signed agent identity and request-context metadata and anchors batches on a local Ganache chain. The tests do not establish AI-response-content integrity, model-weight integrity, Byzantine resilience, or production-blockchain throughput. Preserve the supplied historical CSV/log outputs when repeating experiments.

### 10.1 Reproducibility prerequisites

- Use Python 3.10.x and install Python packages with `python -m pip install -r req.txt`.
- Use the `blocks/contracts/Store.sol` contract, Truffle configuration in `blocks/truffle-config.js`, and a local Ganache workspace on `127.0.0.1:7545`.
- Restore existing environment secrets or create fresh secrets for a **new** experimental database as described in Section 3.5.
- Deploy `Store.sol` by running `cd blocks` and `npx truffle migrate`; return to the project root and run `python manage.py migrate`.
- Benchmark scripts that create proofs or submit blockchain transactions must run only on an **isolated disposable copy** of the SQLite database and Ganache workspace. Some tests use mocked blockchain fixtures; they should not be described as live-chain trials.

### 10.2 R1.1: Canonical encoding and cryptographic tests

```cmd
python manage.py test app.tests.CanonicalPoCATestVectorTests -v 2
```

Evidence: `reproducibility/r1_1_signed_test_vector.json`, `reproducibility/r1_1_test_results.txt`, and `reproducibility/r1_1_blockchain_registry_trace.txt`.

The last file records a **controlled Django-shell comparison** against live Ganache registration data; it is not an execution log from a production HTTP verification endpoint.

### 10.3 R1.2: Persistent replay protection

```cmd
python manage.py test app.tests.ProcessedRequestTests app.tests.R12ReplayConcurrencyTests -v 2
```

Additional sources: `reproducibility/r1_2_acceptance_test.py`, `reproducibility/r1_2_independent_verifier_test.py`, `reproducibility/r1_2_test_results.txt`, and `reproducibility/r1_2_acceptance_results.txt`. The evaluated shared-state guarantee is confined to processes using the tested SQLite database; independent multi-server deployment was not evaluated.

### 10.4 R1.3: Matched-worker, production-relay comparison

The existing benchmark script provides an opt-in live experiment that **writes both SQLite records and Ganache transactions**. It requires a previously registered agent whose on-chain DID, public key, and model hash match the Django agent. Replace the sample IDs with the corresponding IDs from your disposable test setup.

```cmd
python -m app.blockchain.r1_3_production_relay_benchmark --agent-id AGT-0005 --user-id 1
```

The command above does not execute the experiment without `--execute`. For a disposable environment only:

```cmd
python -m app.blockchain.r1_3_production_relay_benchmark --agent-id AGT-0005 --user-id 1 --execute
```

The saved 30-pair dataset is `app/blockchain/r1_3_production_relay_results_revised.csv`. Further controls and per-stage timings are in `reproducibility/r1_3_component_timings.csv` and the `reproducibility/r1_3_*results.csv` files. Proof inputs are shared between paired arms, but actual batch-versus-individual transaction calldata differ. Pre-existing proof generation/signing and AI response time are outside this benchmark's completion-latency boundary.

### 10.5 R2.5: Security and recovery tests

```cmd
python manage.py test app -v 2
```

The earlier `reproducibility/r2_5_security_tests.txt` logs **12 tests**. Following the updated test fixtures, the local run on 24 October 2026 reported **15 tests, OK**. Save the actual new console output as `reproducibility/r2_5_security_tests_latest.txt` and include it in the repository without altering the historical 12-test log. The recovery tests intentionally mock external blockchain outcomes; they establish controlled state-transition behavior rather than an actual network-outage recovery trial. Concurrent SQLite tests can encounter lock contention; do not classify a lock as a duplicate rejection.

In Windows CMD, capture the complete execution log with:

```cmd
python manage.py test app -v 2 > reproducibility\r2_5_security_tests_latest.txt 2>&1
```

### 10.6 Sustained workloads and arrival-rate measurements

Run only against your **disposable** Ganache chain with the compiled/deployed `Store.sol` artifact present:

```cmd
python blockchain/sustained_load_test.py
python blockchain/arrival_rate_test.py
```

`sustained_load_test.py` uses 1,000 and 5,000 operations at three repetitions each and creates a new `blockchain/sustained_rerun_*` directory containing raw transaction details, per-trial records, and uncertainty summaries. Arrival-rate results use `blockchain/arrival_rate_results.csv`, `blockchain/arrival_rate_details.csv`, and `blockchain/arrival_rate_uncertainty.csv`.

Distinguish successful trials from failed experiments when interpreting results. In particular, do not treat zero-valued summaries from failed trials as successful performance measurements. Latency and throughput are local-system-dependent and can vary on re-execution.

### 10.7 Research artifacts and code availability

- Source implementation: `app/crypto_utils.py`, `app/proof_acceptance.py`, `app/batch_processor.py`, `app/views.py`, `app/blockchain/logic.py`.
- Contract: `blocks/contracts/Store.sol`. DID registration is recorded using this storage contract and the Django implementation; the repository does not claim a separate standalone DID-registry Solidity contract.
- Test implementation: `app/tests.py` and `reproducibility/` scripts.
- Configuration: `secureAI/settings.py`, `blocks/truffle-config.js`, `req.txt`.
- Workload generators and machine-readable results: `blockchain/` and `app/blockchain/`.

Do not include actual Django or Fernet secrets, provider API keys, private wallet keys, local production data, `db.sqlite3`, or Python cache directories in public commits.
