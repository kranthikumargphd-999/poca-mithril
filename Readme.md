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

### 3.5 Generate your encryption key (once, ever — do not regenerate after real data exists)
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key())"
```
Paste the output into `secureAI/settings.py`:
```python
FERNET_KEY = b'paste-the-generated-key-here'
```

### 3.6 Create the Administrator account
There is **no public sign-up path to Administrator** — this is deliberate, for security. Registering through the website always creates an End User. Create the one Admin account via the Django shell:
```bash
python manage.py shell
```
```python
from app.models import Users
if not Users.objects.filter(username='Admin_123').exists():
    admin = Users(username='Admin_123', email='admin@secureai.com', role='admin', is_active=True)
    admin.set_password('Admin@123')   # change this password
    admin.save()
    print("Admin created.")
else:
    print("Admin already exists.")
```
Log in at `/` using these credentials once the server is running (Section 4).

---

## 4. Running the project (every time)

1. **Open Ganache** → open your saved workspace (Section 3.2). Leave it running.
2. **Start Django:**
   ```bash
   python manage.py runserver
   ```
3. Visit `http://127.0.0.1:8000/`

You should **not** need to redeploy the contract or regenerate keys again — those are one-time setup steps.

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