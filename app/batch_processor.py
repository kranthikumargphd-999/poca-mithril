"""
Mithril Batch Processor

Creates Mithril-style batches from valid PoCA proofs, builds a Merkle root,
generates the aggregated signature, anchors the batch on the blockchain,
and records the blockchain transaction.

Important behavior:
- Proofs are reserved atomically before anchoring so two requests do not
    normally batch the same proof.
- If blockchain anchoring fails, the proofs are RELEASED back to the pending
    queue instead of remaining permanently marked as batched.
- A failed batch remains in MithrilBatch for audit/history.
- process_pending_batches() respects both BATCH_SIZE and BATCH_TIMEOUT.
"""

import hashlib
import traceback
import os
import time
import csv
from pathlib import Path

from django.db import transaction
from django.utils import timezone

from .models import (
    BlockchainTransaction,
    MithrilBatch,
    PoCAProof,
    Agent,
)
from .crypto_utils import (
    build_merkle_tree,
    generate_aggregated_signature,
    generate_batch_id,
    verify_poca_signature,
    verify_poca_signature_onchain,
)
from .blockchain.logic import addNewData



def save_r13_timing(metric, duration_ms, batch_id=""):
    """
    Save R1.3 component-level timing measurements.

    Logging is enabled only when R13_TIMING=1.
    """

    if os.environ.get("R13_TIMING") != "1":
        return

    project_root = Path(__file__).resolve().parent.parent

    output_dir = project_root / "reproducibility"
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / "r1_3_component_timings.csv"

    file_exists = output_file.exists()

    with open(
        output_file,
        mode="a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "timestamp",
                "process_id",
                "batch_id",
                "metric",
                "duration_ms"
            ])

        writer.writerow([
            timezone.now().isoformat(),
            os.getpid(),
            batch_id,
            metric,
            round(duration_ms, 4)
        ])



class MithrilBatchProcessor:
    #Handles Mithril batch creation and blockchain anchoring.

    # Number of proofs normally required before creating a batch.
    BATCH_SIZE = 5

    # Allow a smaller batch when the oldest proof has waited 5 minutes.
    BATCH_TIMEOUT = 300

    # PENDING PROOFS
    @classmethod
    def get_pending_proofs(cls, limit=None):
        #Return proofs that have not yet been successfully assignedto a Mithril batch.
        proofs = PoCAProof.objects.filter(
            accepted_at__isnull=False,
            is_batched=False
        ).order_by(
            "created_at",
            "pk",
        )

        if limit is not None:
            if limit <= 0:
                return proofs.none()

            proofs = proofs[:limit]

        return proofs

    @classmethod
    def get_pending_count(cls):
        #Return the number of proofs waiting for Mithril batching.

        return PoCAProof.objects.filter(
            is_batched=False,
            accepted_at__isnull=False
        ).count()

    # BATCH TRIGGER

    @classmethod
    def should_create_batch(cls):
        """
        Decide whether a batch should be created.
        A batch is allowed when:
        1. pending proofs >= BATCH_SIZE, OR
        2. the oldest pending proof has waited >= BATCH_TIMEOUT.
        """
        pending_count = cls.get_pending_count()

        if pending_count == 0:
            return False, "No pending proofs"

        if pending_count >= cls.BATCH_SIZE:
            return (
                True,
                f"Batch size reached: {pending_count} proofs pending",
            )

        oldest = (
            PoCAProof.objects
            .filter(is_batched=False, accepted_at__isnull=False,)
            .order_by("created_at", "pk")
            .first()
        )

        if oldest is not None:
            time_diff = (
                timezone.now() - oldest.created_at
            ).total_seconds()

            if time_diff >= cls.BATCH_TIMEOUT:
                return (
                    True,
                    "Batch timeout reached: "
                    f"{int(time_diff)} seconds since oldest proof",
                )

            remaining = max(
                0,
                cls.BATCH_TIMEOUT - int(time_diff),
            )

            return (
                False,
                f"Not enough proofs "
                f"({pending_count}/{cls.BATCH_SIZE}); "
                f"timeout in approximately {remaining} seconds",
            )

        return (
            False,
            f"Not enough proofs "
            f"({pending_count}/{cls.BATCH_SIZE})",
        )

    # RESERVATION / RELEASE
    @classmethod
    def _reserve_proofs_for_batch(cls):
        """
        Atomically reserve up to BATCH_SIZE pending proofs.
        Reserving them before the external blockchain call reduces the risk
        of two simultaneous requests creating two batches from the same proof.
        NOTE:
        select_for_update() provides real row locking on databases such as
        PostgreSQL/MySQL. SQLite has more limited locking semantics.
        """
        with transaction.atomic():
            pending_proofs = list(
                PoCAProof.objects
                .select_for_update()
                .filter(is_batched=False, accepted_at__isnull=False)
                .order_by("created_at", "pk")[:cls.BATCH_SIZE]
            )
            
            # R1.3: Measure proof queue waiting time
            if os.environ.get("R13_TIMING") == "1" and pending_proofs:
                from django.utils import timezone

                reservation_time = timezone.now()

                queue_wait_times_ms = [
                    (reservation_time - proof.created_at).total_seconds() * 1000
                    for proof in pending_proofs
                ]

                mean_queue_wait_ms = (
                    sum(queue_wait_times_ms) / len(queue_wait_times_ms)
                )
                save_r13_timing("mean_queue_wait", mean_queue_wait_ms)

                save_r13_timing(
                    "max_queue_wait",
                    max(queue_wait_times_ms)
                )

                print(
                    f"R1.3 Mean Queue Waiting Time: "
                    f"{mean_queue_wait_ms:.4f} ms"
                )

                print(
                    f"R1.3 Maximum Queue Waiting Time: "
                    f"{max(queue_wait_times_ms):.4f} ms"
                )

            if not pending_proofs:
                return None, []

            # A Merkle batch requires a signature for every leaf.
            # Validate every PoCA signature before including it in a batch.
            invalid_proofs = []

            # R1.3: Measure signature and registry verification
            verification_start = time.perf_counter()

            for proof in pending_proofs:
                if not proof.signature or not verify_poca_signature_onchain(proof):
                    invalid_proofs.append(proof.proof_id)

            verification_time_ms = (
                time.perf_counter() - verification_start
            ) * 1000
            # NEW LINE - Save timing to CSV
            save_r13_timing("initial_verification", verification_time_ms)
            if os.environ.get("R13_TIMING") == "1":
                print(
                    f"R1.3 Verification Time: "
                    f"{verification_time_ms:.4f} ms"
                )

            if invalid_proofs:
                raise ValueError(
                    "Cannot create Mithril batch because these proofs "
                    "have missing or invalid signatures: "
                    + ", ".join(invalid_proofs)
                )


            leaves = [
                proof.signature
                for proof in pending_proofs
            ]

            # R1.3: Measure Merkle-tree construction
            merkle_start = time.perf_counter()

            merkle_result = build_merkle_tree(leaves)

            merkle_time_ms = (
                time.perf_counter() - merkle_start
            ) * 1000
            # NEW LINE - Save timing to CSV
            save_r13_timing("merkle_construction", merkle_time_ms)
            if os.environ.get("R13_TIMING") == "1":
                print(
                    f"R1.3 Merkle Construction Time: "
                    f"{merkle_time_ms:.4f} ms"
            )

            if not merkle_result:
                raise RuntimeError(
                    "Merkle-tree generation returned no result."
                )

            merkle_root = merkle_result.get("root")

            if not merkle_root:
                raise RuntimeError(
                    "Merkle-tree generation returned an empty root."
                )

            aggregated_signature = (
                generate_aggregated_signature(
                    pending_proofs
                )
            )

            if not aggregated_signature:
                raise RuntimeError(
                    "Aggregated signature generation failed."
                )

            batch_id = generate_batch_id()

            if not batch_id:
                raise RuntimeError(
                    "Batch ID generation failed."
                )

            batch = MithrilBatch.objects.create(
                batch_id=batch_id,
                merkle_root=merkle_root,
                aggregated_signature=aggregated_signature,
                num_proofs=len(pending_proofs),
                status="pending",
            )

            # Reserve proofs so another request cannot normally pick them.
            proof_ids = [
                proof.pk
                for proof in pending_proofs
            ]

            updated = (
                PoCAProof.objects
                .filter(
                    pk__in=proof_ids,
                    is_batched=False,
                )
                .update(
                    batch=batch,
                    is_batched=True,
                )
            )

            if updated != len(proof_ids):
                raise RuntimeError(
                    "Could not reserve all selected proofs. "
                    "The transaction has been rolled back."
                )

            return batch, pending_proofs
        
    @classmethod
    def _release_failed_batch_proofs(cls, batch):
        """
        Return proofs from a failed batch to the pending queue.
        This is the key fix missing from the original implementation.
        Without it, an anchoring failure leaves proofs permanently marked
        is_batched=True and they are never retried.
        """
        with transaction.atomic():
            (
                PoCAProof.objects
                .filter(
                    batch=batch,
                    is_batched=True,
                )
                .update(
                    batch=None,
                    is_batched=False,
                )
            )
            
    # CREATE BATCH
    @classmethod
    def create_batch(cls):
        """
        Create one Mithril batch from up to BATCH_SIZE pending proofs.
        Returns:
            (batch, message) on successful anchoring.
            (None, message) when no batch is anchored.
        """
        batch = None
        try:
            # STEP 1: Reserve proofs + create pending batch
            batch, pending_proofs = (
                cls._reserve_proofs_for_batch()
            )
            if batch is None:
                return None, "No pending proofs to batch"
            print(
                f"Mithril batch reserved: {batch.batch_id} "
                f"({len(pending_proofs)} proofs)"
            )
            
            # STEP 2: Anchor outside the DB transaction
            # NOTE: anchor_batch() now returns 4 values (gas_used added)
            # instead of 3 — this is the real-receipt fix.
            success, tx_hash, block_number, gas_used = (
                cls.anchor_batch(batch)
            )
            # STEP 3A: Successful anchoring
            if success:
                if not tx_hash:
                    raise RuntimeError(
                        "Blockchain anchoring reported success "
                        "without a transaction hash."
                    )
                with transaction.atomic():
                    locked_batch = (
                        MithrilBatch.objects
                        .select_for_update()
                        .get(pk=batch.pk)
                    )
                    locked_batch.status = "anchored"
                    locked_batch.tx_hash = tx_hash
                    locked_batch.block_number = block_number
                    locked_batch.anchored_at = timezone.now()
                    locked_batch.save(
                        update_fields=[
                            "status",
                            "tx_hash",
                            "block_number",
                            "anchored_at",
                        ]
                    )
                    
                    transaction_record = BlockchainTransaction.objects.create(
                        tx_hash=tx_hash,
                        tx_type="batch_anchor",
                        related_batch=locked_batch,
                        block_number=block_number,
                        gas_used=gas_used,
                        status="success",
                    )
                    
                    # Get all unique agents involved in this batch
                    agents = Agent.objects.filter(
                        proofs__batch=locked_batch
                    ).distinct()
                    
                    # Attach multiple agents to transaction
                    for agent in agents:
                        transaction_record.related_agents.add(agent)
                        
                return (
                    batch,
                    f"Batch {batch.batch_id} created "
                    "and anchored successfully",
                )
            # STEP 3B: Failed anchoring
            cls._mark_batch_failed(
                batch=batch,
                failure_reason="Blockchain anchoring returned failure",
            )
            
            cls._release_failed_batch_proofs(batch)
            
            return (
                None,
                f"Batch {batch.batch_id} anchoring failed. "
                "Its proofs were returned to the pending queue.",
            )
            
        except Exception as exc:
            print(
                f"Error creating Mithril batch: {exc}"
            )
            traceback.print_exc()
            
            # If reservation already created a batch, mark it failed
            # and return its proofs to the queue.
            if batch is not None:
                try:
                    cls._mark_batch_failed(
                        batch=batch,
                        failure_reason=str(exc),
                    )
                except Exception as status_exc:
                    print(
                        "Could not mark failed Mithril batch: "
                        f"{status_exc}"
                    )
                    
                try:
                    cls._release_failed_batch_proofs(batch)
                except Exception as release_exc:
                    print(
                        "CRITICAL: Could not release proofs "
                        f"from failed batch {batch.batch_id}: "
                        f"{release_exc}"
                    )
            return (
                None,
                f"Mithril batch creation failed: {exc}",
            )


    # FAILED BATCH RECORD
    @classmethod
    def _mark_batch_failed(cls, batch, failure_reason=None,):
        """
        Mark the MithrilBatch as failed and create a failed
        BlockchainTransaction record.
        The current BlockchainTransaction model shown in the existing code
        does not contain a failure_reason field, so the reason is logged
        rather than saved there.
        
        NOTE: A failed anchor attempt genuinely has no real transaction hash
        (nothing was mined), so a synthetic reference hash is still the
        correct choice here — this is the one legitimate remaining use of
        _generate_reference_hash().
        """
        if failure_reason:
            print(
                f"Batch {batch.batch_id} failure reason: "
                f"{failure_reason}"
            )
            
        with transaction.atomic():
            locked_batch = (
                MithrilBatch.objects
                .select_for_update()
                .get(pk=batch.pk)
            )
            
            locked_batch.status = "failed"
            locked_batch.save(
                update_fields=["status"]
            )
            
            # Use a unique synthetic failed transaction reference rather
            # than the same all-zero hash for every failure. This avoids
            # collisions if tx_hash is unique in your model.
            failed_tx_hash = cls._generate_reference_hash(
                prefix="failed",
                batch=locked_batch,
            )
            
            BlockchainTransaction.objects.create(
                tx_hash=failed_tx_hash,
                tx_type="batch_anchor",
                related_batch=locked_batch,
                status="failed",
            )
            
    # BLOCKCHAIN ANCHOR
    @classmethod
    def anchor_batch(cls, batch):
        """
        Anchor one Mithril batch to the blockchain.
        Returns:
            (True, tx_hash, block_number, gas_used)
            or
            (False, None, None, None)
            
        FIXED: addNewData() now returns a real receipt dict
        {"success": bool, "tx_hash": str, "block_number": int, "gas_used": int}
        instead of just the string "Success". This method now passes through
        the REAL values instead of generating fake proof-of-concept ones.
        """
        try:
            if batch is None:
                raise ValueError(
                    "Batch is required for blockchain anchoring."
                )
                
            if not batch.merkle_root:
                raise ValueError(
                    "Cannot anchor a batch without a Merkle root."
                )
                
            if not batch.aggregated_signature:
                raise ValueError(
                    "Cannot anchor a batch without "
                    "an aggregated signature."
                )
            anchor_time = timezone.now()
            # Get agents associated with this batch
            agents = Agent.objects.filter(proofs__batch=batch).distinct()
            agent_identity = []
            
            for agent in agents:
                agent_identity.append(
                    {
                        "agent_id": agent.agent_id,
                        "agent_name": agent.name,
                        "did": agent.did,
                        "model_hash": agent.model_hash,
                    }
                )
            if not agent_identity:
                raise ValueError(
                    "No agents found for this batch."
                )
            data = {
                "type": "mithril_batch",
                "batch_id": batch.batch_id,
                # Multiple DID information
                "agents": agent_identity,
                "merkle_root": batch.merkle_root,
                "aggregated_signature":batch.aggregated_signature,
                "num_proofs":batch.num_proofs,
                "timestamp":anchor_time.isoformat(),
            }
            
            # FIX 1: Revalidate proofs immediately before blockchain anchoring.
            batch_proofs = list(
                PoCAProof.objects
                .filter(batch=batch)
                .select_related("agent")
            )

            # Confirm the batch contains the expected number of proofs.
            if len(batch_proofs) != batch.num_proofs:
                raise ValueError(
                    "Batch proof count does not match the reserved batch."
                )
                
            # R1.3: Measure proof re-verification before anchoring.
            reverification_start = time.perf_counter()
            
            # Verify every proof again before anchoring.
            for proof in batch_proofs:
                if not proof.signature or not verify_poca_signature_onchain(proof):
                    raise ValueError(
                        f"Invalid PoCA signature detected before anchoring: "
                        f"{proof.proof_id}"
                    )
                    
            reverification_time_ms = (
                time.perf_counter() - reverification_start
            ) * 1000
            
            save_r13_timing(
                "reverification",
                reverification_time_ms,
                batch.batch_id
            )
            if os.environ.get("R13_TIMING") == "1":
                print(
                    f"R1.3 Re-verification Time: "
                    f"{reverification_time_ms:.4f} ms"
                )
                
            # Recompute the Merkle root from the verified signatures.
            # R1.3: Measure Merkle reconstruction before anchoring.
            merkle_recheck_start = time.perf_counter()

            merkle_result = build_merkle_tree(
                [proof.signature for proof in batch_proofs]
            )

            merkle_recheck_time_ms = (
                time.perf_counter() - merkle_recheck_start
            ) * 1000
            save_r13_timing(
                "merkle_recheck",
                merkle_recheck_time_ms,
                batch.batch_id
            )
            if os.environ.get("R13_TIMING") == "1":
                print(
                    f"R1.3 Merkle Recheck Time: "
                    f"{merkle_recheck_time_ms:.4f} ms"
                )
            
            if not merkle_result or merkle_result.get("root") != batch.merkle_root:
                raise ValueError(
                    "Batch Merkle root does not match the verified proof signatures."
                )

            # Submit only after all validation checks pass.
            # R1.3: Measure blockchain transaction submission
            # and receipt confirmation together.
            blockchain_start = time.perf_counter()
            
            # Submit only after all validation checks pass.
            result = addNewData(data)
            
            blockchain_time_ms = (
                time.perf_counter() - blockchain_start
            ) * 1000
            # NEW LINE - Save timing to CSV
            save_r13_timing(
                "blockchain_submission_receipt",
                blockchain_time_ms,
                batch.batch_id
            )
            if os.environ.get("R13_TIMING") == "1":
                print(
                    f"R1.3 Blockchain Submission + Receipt Time: "
                    f"{blockchain_time_ms:.4f} ms"
                )
                
                print(
                    f"R1.3 Blockchain Gas Used: "
                    f"{result.get('gas_used', 'N/A') if isinstance(result, dict) else 'N/A'}"
                )
            
            
            print(
                f"Mithril blockchain result "
                f"for {batch.batch_id}: {result}"
            )
            
            if not result["success"]:
                return False, None, None, None
            
            return (
                True,
                result["tx_hash"],
                result["block_number"],
                result["gas_used"],
            )
            
        except Exception as exc:
            print(
                f"Error anchoring batch "
                f"{getattr(batch, 'batch_id', 'UNKNOWN')}: "
                f"{exc}"
            )
            traceback.print_exc()
            
            return False, None, None, None
        
        
    @classmethod
    def _generate_reference_hash(cls, prefix, batch, timestamp=None,):
        """
        Generate a unique 0x-prefixed 40-hex-character reference.
        Used ONLY for failed-batch records now (see _mark_batch_failed).
        This is NOT claimed as a real blockchain transaction hash — a failed
        anchor attempt has no real receipt to report.
        """
        if timestamp is None:
            timestamp = timezone.now()
            
        source = (
            f"{prefix}|"
            f"{batch.batch_id}|"
            f"{batch.merkle_root}|"
            f"{timestamp.isoformat()}"
        )
        
        digest = hashlib.sha256(
            source.encode("utf-8")
        ).hexdigest()
        
        return "0x" + digest[:40]
    
    # PROCESS PENDING
    @classmethod
    def process_pending_batches(cls):
        """
        Check the trigger conditions and create ONE batch if needed.
        Calling this method is preferred over manually checking only
        pending_count >= BATCH_SIZE because this method also honors
        BATCH_TIMEOUT.
        """
        should_create, reason = (
            cls.should_create_batch()
        )
        
        if not should_create:
            return None, reason
        
        batch, message = cls.create_batch()
        
        if batch is not None:
            return batch, message
        
        return None, message
    
    # STATS
    @classmethod
    def get_batch_stats(cls):
        """
        Return current Mithril batch statistics.
        """
        total_batches = (
            MithrilBatch.objects.count()
        )
        anchored_batches = (
            MithrilBatch.objects
            .filter(status="anchored")
            .count()
        )
        pending_batches = (
            MithrilBatch.objects
            .filter(status="pending")
            .count()
        )
        
        failed_batches = (
            MithrilBatch.objects
            .filter(status="failed")
            .count()
        )
        total_proofs_batched = (
            PoCAProof.objects
            .filter(is_batched=True)
            .count()
        )
        pending_proofs = (
            cls.get_pending_count()
        )
        return {
            "total_batches": total_batches,
            "anchored_batches": anchored_batches,
            "pending_batches": pending_batches,
            "failed_batches": failed_batches,
            "total_proofs_batched": total_proofs_batched,
            "pending_proofs": pending_proofs,
        }