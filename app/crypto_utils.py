"""
SecureAI cryptographic and AI-provider utility functions.

This module provides:
- Fernet encryption/decryption
- ECDSA key generation and signing
- DID/model/context hashing helpers
- Merkle tree and aggregated-signature helpers
- Groq API integration
- Hugging Face Inference Providers integration
- Ollama local API integration
"""

import hashlib
import uuid
from datetime import datetime, timezone

import requests
from cryptography.fernet import Fernet
from django.conf import settings
from ecdsa import SECP256k1, SigningKey, VerifyingKey # type: ignore


# CONSTANTS
GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"
HUGGINGFACE_CHAT_URL = "https://router.huggingface.co/v1/chat/completions"
OLLAMA_BASE_URL = "http://localhost:11434"

# Stable defaults used only by the connection-test helpers.
DEFAULT_GROQ_TEST_MODEL = "openai/gpt-oss-20b"
DEFAULT_HF_TEST_MODEL = "openai/gpt-oss-20b"


# COMMON HELPERS
def _require_non_empty(value, name):
    # Validate values that must not be empty.
    if value is None or str(value).strip() == "":
        raise ValueError(f"{name} is required")


def _safe_response_text(response, limit=2000):
    #Return a bounded response body for useful error messages.
    text = response.text or ""
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _extract_json_error(response):
    #Extract a readable error message from a JSON API response.
    try:
        body = response.json()
        
        if isinstance(body, dict):
            error = body.get("error")
            
            if isinstance(error, dict):
                return (
                    error.get("message")
                    or error.get("type")
                    or str(error)
                )
                
            if error:
                return str(error)
            
            if body.get("message"):
                return str(body["message"])
            
    except ValueError:
        pass
    
    return _safe_response_text(response) or "Unknown API error"


# ENCRYPTION / DECRYPTION
def get_fernet():
    #Create a Fernet instance from settings.FERNET_KEY.
    key = getattr(settings, "FERNET_KEY", None)
    if not key:
        raise RuntimeError("FERNET_KEY is not configured in Django settings")
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def encrypt_value(raw_value: str) -> str:
    #Encrypt a string for storage.
    _require_non_empty(raw_value, "raw_value")
    return get_fernet().encrypt(raw_value.encode()).decode()


def decrypt_value(encrypted_value: str) -> str:
    #Decrypt a value previously encrypted with encrypt_value().
    _require_non_empty(encrypted_value, "encrypted_value")
    return get_fernet().decrypt(encrypted_value.encode()).decode()


# KEY / ID / HASH HELPERS
def generate_keypair():
    #Return a SECP256k1 (private_key_hex, public_key_hex) pair.
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    
    return (
        private_key.to_string().hex(),
        public_key.to_string().hex(),
    )


def generate_did(public_key_hex: str) -> str:
    #Generate a deterministic DID from a public key.
    _require_non_empty(public_key_hex, "public_key_hex")
    digest = hashlib.sha256(public_key_hex.encode()).hexdigest()[:32]
    return f"did:secureai:{digest}"


def generate_model_hash(provider: str, model_name: str) -> str:
    #Generate a deterministic hash identifying provider + model.
    _require_non_empty(provider, "provider")
    _require_non_empty(model_name, "model_name")
    value = f"{provider.strip().lower()}|{model_name.strip()}"
    
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def generate_agent_id():
    #Generate AGT-0001 style IDs for compatibility with existing data.
    from .models import Agent
    count = Agent.objects.count() + 1
    return f"AGT-{count:04d}"


def generate_proof_id():
    #Generate a collision-resistant proof ID.
    return f"PROOF-{uuid.uuid4().hex[:8].upper()}"


def generate_batch_id():
    #Generate BATCH-0001 style IDs for compatibility with existing data.
    from .models import MithrilBatch
    
    count = MithrilBatch.objects.count() + 1
    return f"BATCH-{count:04d}"


def generate_context_hash(query_text: str, user_id: int, agent_id: int) -> str:
    #Generate a unique SHA-256 hash for a query execution context."""
    _require_non_empty(query_text, "query_text")
    
    timestamp = datetime.now(timezone.utc).isoformat()
    context = f"{query_text}|{user_id}|{agent_id}|{timestamp}"
    
    return "sha256:" + hashlib.sha256(context.encode()).hexdigest()


# def generate_signature(context_hash: str, private_key_encrypted: str) -> str:
#     """
#     Sign a context hash with the agent's encrypted SECP256k1 private key.
#     IMPORTANT:
#     This function intentionally raises an error if decryption/signing fails.
#     A fake/dummy signature must never be stored as a valid PoCA proof.
#     """
#     _require_non_empty(context_hash, "context_hash")
#     _require_non_empty(private_key_encrypted, "private_key_encrypted")
    
#     try:
#         private_key_hex = decrypt_value(private_key_encrypted)
#         private_key_bytes = bytes.fromhex(private_key_hex)
        
#         signing_key = SigningKey.from_string(
#             private_key_bytes,
#             curve=SECP256k1,
#         )
        
#         signature = signing_key.sign(context_hash.encode())
#         return signature.hex()
    
#     except Exception as exc:
#         raise RuntimeError(
#             f"Failed to generate cryptographic signature: {exc}"
#         ) from exc


def canonical_poca_message(
    proof_id: str,
    agent_did: str,
    context_hash: str,
    model_hash: str,
    timestamp: str,
    safety_score: float,
) -> bytes:
    """Serialize PoCA fields deterministically before signing."""
    import json

    message = {
        "version": 1,
        "proof_id": proof_id,
        "agent_did": agent_did,
        "context_hash": context_hash,
        "model_hash": model_hash,
        "timestamp": timestamp,
        "safety_score": format(float(safety_score), ".2f"),
    }

    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def generate_signature(
    proof_id: str,
    agent_did: str,
    context_hash: str,
    model_hash: str,
    timestamp: str,
    safety_score: float,
    private_key_encrypted: str,
) -> str:
    """Sign the canonical PoCA message using the agent's private key."""
    _require_non_empty(proof_id, "proof_id")
    _require_non_empty(agent_did, "agent_did")
    _require_non_empty(context_hash, "context_hash")
    _require_non_empty(model_hash, "model_hash")
    _require_non_empty(timestamp, "timestamp")
    _require_non_empty(private_key_encrypted, "private_key_encrypted")

    try:
        private_key_hex = decrypt_value(private_key_encrypted)
        private_key_bytes = bytes.fromhex(private_key_hex)

        signing_key = SigningKey.from_string(
            private_key_bytes,
            curve=SECP256k1,
        )

        message = canonical_poca_message(
            proof_id=proof_id,
            agent_did=agent_did,
            context_hash=context_hash,
            model_hash=model_hash,
            timestamp=timestamp,
            safety_score=safety_score,
        )

        signature = signing_key.sign_deterministic(
            message,
            hashfunc=hashlib.sha256,
        )

        return signature.hex()

    except Exception as exc:
        raise RuntimeError(
            f"Failed to sign canonical PoCA message: {exc}"
        ) from exc


def verify_poca_signature(proof) -> bool:
    """
    Verify the signature of a stored PoCA proof.

    The proof must contain the same fields that were used
    when generating its canonical signature.
    """
    try:
        if not proof.agent or not proof.agent.public_key:
            return False

        if not proof.attestation_timestamp:
            return False

        message = canonical_poca_message(
            proof_id=proof.proof_id,
            agent_did=proof.agent.did,
            context_hash=proof.context_hash,
            model_hash=proof.model_hash,
            timestamp=proof.attestation_timestamp.isoformat(),
            safety_score=proof.safety_score,
        )

        verifying_key = VerifyingKey.from_string(
            bytes.fromhex(proof.agent.public_key),
            curve=SECP256k1,
        )

        verifying_key.verify(
            bytes.fromhex(proof.signature),
            message,
            hashfunc=hashlib.sha256,
        )

        # Ensure that the stored DID corresponds to the public key.
        if generate_did(proof.agent.public_key) != proof.agent.did:
            return False

        # Ensure that the proof's model hash matches the registered agent model hash.
        if proof.model_hash != proof.agent.model_hash:
            return False

        return True

    except Exception:
        return False


def verify_poca_signature_onchain(proof) -> bool:
    """
    Verify a PoCA proof against the live blockchain registry.

    Fail closed when the registration is missing, duplicated,
    inconsistent, or its signature is invalid.
    """
    try:
        from app.blockchain.logic import retrieveData

        if not proof.agent or not proof.attestation_timestamp:
            return False

        if not proof.signature:
            return False

        # Retrieve live blockchain registrations.
        records = retrieveData()

        if not isinstance(records, list):
            return False

        # Find registrations for the agent ID.
        registrations = [
            r for r in records
            if isinstance(r, dict)
            and r.get("type") == "agent_registration"
            and r.get("agent_id") == proof.agent.agent_id
        ]

        # Reject missing or ambiguous registrations.
        if len(registrations) != 1:
            return False

        registered = registrations[0]

        registered_did = registered.get("did")
        registered_public_key = registered.get("public_key")
        registered_model_hash = registered.get("model_hash")

        if not all([
            registered_did,
            registered_public_key,
            registered_model_hash,
        ]):
            return False

        # Compare the blockchain DID with the proof's agent DID.
        if registered_did != proof.agent.did:
            return False

        # Compare the blockchain public key with local agent metadata.
        if registered_public_key != proof.agent.public_key:
            return False

        # Ensure the DID corresponds to the registered public key.
        if generate_did(registered_public_key) != registered_did:
            return False

        # Compare model hashes against blockchain registration.
        if proof.model_hash != registered_model_hash:
            return False

        if proof.agent.model_hash != registered_model_hash:
            return False

        # Reconstruct canonical message.
        message = canonical_poca_message(
            proof_id=proof.proof_id,
            agent_did=registered_did,
            context_hash=proof.context_hash,
            model_hash=proof.model_hash,
            timestamp=proof.attestation_timestamp.isoformat(),
            safety_score=proof.safety_score,
        )

        # IMPORTANT: Verify using the BLOCKCHAIN public key.
        verifying_key = VerifyingKey.from_string(
            bytes.fromhex(registered_public_key),
            curve=SECP256k1,
        )

        verifying_key.verify(
            bytes.fromhex(proof.signature),
            message,
            hashfunc=hashlib.sha256,
        )

        return True

    except Exception:
        return False

# MERKLE TREE / MITHRIL HELPERS
def hash_data(data: str) -> str:
    #Generate a SHA-256 hash of a string.
    _require_non_empty(data, "data")
    return hashlib.sha256(data.encode()).hexdigest()


def build_merkle_tree(leaves: list) -> dict:
    """
    Build a Merkle tree from a list of leaf strings.
    For an odd-sized level, the final hash is duplicated before hashing
    the parent node.
    """
    if not leaves:
        return {
            "root": None,
            "tree": [],
            "levels": [],
            "num_leaves": 0,
        }
        
    current_level = [hash_data(str(leaf)) for leaf in leaves]
    tree = [current_level.copy()]
    
    while len(current_level) > 1:
        next_level = []
        
        for index in range(0, len(current_level), 2):
            left = current_level[index]
            
            if index + 1 < len(current_level):
                right = current_level[index + 1]
            else:
                right = left
                
            next_level.append(hash_data(left + right))
            
        tree.append(next_level)
        current_level = next_level
        
    return {
        "root": current_level[0],
        "tree": tree,
        "levels": tree,
        "num_leaves": len(leaves),
    }


def generate_aggregated_signature(proofs):
    """
    Produce the project's simplified proof aggregation.
    This is a SHA-256 hash of concatenated proof signatures. It is suitable
    for the current proof-of-concept flow, but it is not true BLS signature
    aggregation.
    """
    if not proofs:
        return None
    
    signatures = []
    
    for proof in proofs:
        signature = getattr(proof, "signature", None)
        _require_non_empty(signature, "proof.signature")
        signatures.append(signature)
        
    combined = "".join(signatures)
    return hashlib.sha256(combined.encode()).hexdigest()


# GROQ
def generate_groq_response(api_key, model_name, query_text, system_prompt=None,):
    #Generate an assistant response using Groq Chat Completions.
    _require_non_empty(api_key, "Groq API key")
    _require_non_empty(model_name, "Groq model name")
    _require_non_empty(query_text, "query_text")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    
    messages = []
    
    if system_prompt:
        messages.append({
            "role": "system",
            "content": system_prompt,
        })
        
    messages.append({
        "role": "user",
        "content": query_text,
    })
    
    payload = {
        "model": model_name,
        "messages": messages,
        "temperature": 0.7,
        "max_completion_tokens": 2000,
        "stream": False,
    }
    
    try:
        response = requests.post(
            GROQ_CHAT_URL,
            headers=headers,
            json=payload,
            timeout=60,
        )
        
    except requests.exceptions.Timeout as exc:
        raise RuntimeError("Groq API request timed out") from exc
    
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Unable to connect to Groq: {exc}"
        ) from exc
        
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Groq request failed: {exc}"
        ) from exc
        
    if response.status_code != 200:
        message = _extract_json_error(response)
        raise RuntimeError(
            f"Groq API error {response.status_code}: {message}"
        )
        
    try:
        result = response.json()
        content = result["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(
            f"Unexpected Groq response format: {_safe_response_text(response)}"
        ) from exc
        
    if not content or not str(content).strip():
        raise RuntimeError("Groq returned an empty AI response")
    
    return str(content).strip()


def test_groq_connection(api_key, model_name=DEFAULT_GROQ_TEST_MODEL,):
    #Test Groq authentication and model access.
    try:
        response_text = generate_groq_response(
            api_key=api_key,
            model_name=model_name,
            query_text="Reply with exactly: OK",
        )
        
        return True, f"Groq API is working. Response: {response_text[:100]}"
    
    except Exception as exc:
        return False, str(exc)


# HUGGING FACE INFERENCE PROVIDERS
def generate_huggingface_response(api_key, model_name, query_text, system_prompt=None,):
    """
    Generate an assistant response through Hugging Face Inference Providers.
    Uses the current OpenAI-compatible router endpoint:
    https://router.huggingface.co/v1/chat/completions
    """
    _require_non_empty(api_key, "Hugging Face API token")
    _require_non_empty(model_name, "Hugging Face model name")
    _require_non_empty(query_text, "query_text")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    
    messages = []
    
    if system_prompt:
        messages.append({
            "role": "system",
            "content": system_prompt,
        })
        
    messages.append({
        "role": "user",
        "content": query_text,
    })
    
    payload = {
        "model": model_name,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 1000,
        "stream": False,
    }
    
    try:
        response = requests.post(
            HUGGINGFACE_CHAT_URL,
            headers=headers,
            json=payload,
            timeout=90,
        )
        
    except requests.exceptions.Timeout as exc:
        raise RuntimeError(
            "Hugging Face API request timed out"
        ) from exc
        
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Unable to connect to Hugging Face: {exc}"
        ) from exc
        
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Hugging Face request failed: {exc}"
        ) from exc
        
    if response.status_code != 200:
        message = _extract_json_error(response)
        
        if response.status_code == 401:
            prefix = "Invalid Hugging Face token or authentication failed"
        elif response.status_code == 402:
            prefix = "Hugging Face inference credits/billing error"
        elif response.status_code == 403:
            prefix = "Hugging Face access denied; check token/model permissions"
        elif response.status_code == 404:
            prefix = (
                "Hugging Face model/route not found or model is not available "
                "through Inference Providers"
            )
        elif response.status_code == 429:
            prefix = "Hugging Face rate limit exceeded"
        elif response.status_code == 503:
            prefix = "Hugging Face provider/model is temporarily unavailable"
        else:
            prefix = "Hugging Face API request failed"
            
        raise RuntimeError(
            f"{prefix} ({response.status_code}): {message}"
        )
        
    try:
        result = response.json()
        content = result["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(
            "Unexpected Hugging Face response format: "
            f"{_safe_response_text(response)}"
        ) from exc
        
    if not content or not str(content).strip():
        raise RuntimeError("Hugging Face returned an empty AI response")
    
    return str(content).strip()


def test_huggingface_connection(api_key, model_name=DEFAULT_HF_TEST_MODEL,):
    #Test Hugging Face authentication and model inference access.
    try:
        response_text = generate_huggingface_response(
            api_key=api_key,
            model_name=model_name,
            query_text="Reply with exactly: OK",
        )
        
        return (
            True,
            "Hugging Face API is working. "
            f"Response: {response_text[:100]}",
        )
        
    except Exception as exc:
        return False, str(exc)


# OLLAMA
def check_ollama_connection():
    #Check whether the local Ollama service is reachable.
    try:
        response = requests.get(
            f"{OLLAMA_BASE_URL}/api/tags",
            timeout=3,
        )
        
    except requests.exceptions.ConnectionError:
        return False, "Ollama is not running. Start it with: ollama serve"
    
    except requests.exceptions.Timeout:
        return False, "Ollama connection check timed out"
    
    except requests.RequestException as exc:
        return False, f"Error connecting to Ollama: {exc}"
    
    if response.status_code == 200:
        return True, "Ollama is running"
    
    return (
        False,
        f"Ollama returned status {response.status_code}: "
        f"{_extract_json_error(response)}",
    )


def get_ollama_models():
    #Return names of models installed in local Ollama.
    try:
        response = requests.get(
            f"{OLLAMA_BASE_URL}/api/tags",
            timeout=5,
        )
        
        if response.status_code != 200:
            return []
        
        data = response.json()
        return [
            model.get("name") or model.get("model")
            for model in data.get("models", [])
            if model.get("name") or model.get("model")
        ]
        
    except (requests.RequestException, ValueError, TypeError):
        return []


def generate_ollama_response(model_name, query_text, system_prompt=None,):
    #Generate an assistant response using local Ollama.
    _require_non_empty(model_name, "Ollama model name")
    _require_non_empty(query_text, "query_text")
    
    messages = []
    
    if system_prompt:
        messages.append({
            "role": "system",
            "content": system_prompt,
        })
        
    messages.append({
        "role": "user",
        "content": query_text,
    })
    
    payload = {
        "model": model_name,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.7,
            "num_predict": 2000,
            "num_ctx": 4096,
        },
    }
    
    timeout = getattr(settings, "OLLAMA_TIMEOUT", 120)
    
    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=timeout,
        )
        
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            "Ollama is not running. Start it with: ollama serve"
        ) from exc
        
    except requests.exceptions.Timeout as exc:
        raise RuntimeError(
            f"Ollama request timed out after {timeout} seconds"
        ) from exc
        
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Ollama request failed: {exc}"
        ) from exc
        
    if response.status_code != 200:
        raise RuntimeError(
            f"Ollama API error {response.status_code}: "
            f"{_extract_json_error(response)}"
        )
        
    try:
        result = response.json()
        content = result.get("message", {}).get("content")
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            f"Unexpected Ollama response format: {_safe_response_text(response)}"
        ) from exc
        
    if not content or not str(content).strip():
        raise RuntimeError("Ollama returned an empty AI response")
    
    return str(content).strip()


def test_ollama_model(model_name):
    #Test whether a local Ollama model can generate a response.
    try:
        response_text = generate_ollama_response(
            model_name=model_name,
            query_text="Reply with exactly: OK",
        )
        
        return True, f"Model is working. Response: {response_text[:100]}"
    
    except Exception as exc:
        return False, str(exc)