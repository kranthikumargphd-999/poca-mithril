from django.db import OperationalError
from django.utils import timezone

from .crypto_utils import verify_poca_signature_onchain
from .models import PoCAProof


def accept_poca_proof(proof_id):
    """
    Accept a valid signed proof once.

    This records acceptance, not blockchain confirmation.
    """
    try:
        proof = (
            PoCAProof.objects
            .select_related("agent")
            .get(proof_id=proof_id)
        )
    except PoCAProof.DoesNotExist:
        return False, "NOT_FOUND"
    except OperationalError:
        return False, "DATABASE_BUSY"

    # Verify before consuming the proof identifier.
    if not verify_poca_signature_onchain(proof):
        return False, "INVALID_PROOF"

    accepted_time = timezone.now()

    try:
        # A single conditional UPDATE is atomic.
        # Match the verified fields so changed data cannot be accepted.
        updated = PoCAProof.objects.filter(
            pk=proof.pk,
            proof_id=proof.proof_id,
            accepted_at__isnull=True,
            agent_id=proof.agent_id,
            context_hash=proof.context_hash,
            model_hash=proof.model_hash,
            attestation_timestamp=proof.attestation_timestamp,
            safety_score=proof.safety_score,
            signature=proof.signature,
        ).update(accepted_at=accepted_time)

    except OperationalError:
        # A busy database is not a duplicate-proof result.
        return False, "DATABASE_BUSY"

    if updated == 1:
        return True, "ACCEPTED"

    return False, "ALREADY_ACCEPTED_OR_CHANGED"