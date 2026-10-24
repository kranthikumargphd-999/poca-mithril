
import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.db import IntegrityError, transaction
from django.test import SimpleTestCase, TestCase, RequestFactory

from ecdsa import SECP256k1, SigningKey # type: ignore

from app.batch_processor import MithrilBatchProcessor
from app.crypto_utils import (
    canonical_poca_message,
    encrypt_value,
    generate_did,
    generate_signature,
    verify_poca_signature,
)
from app.models import ProcessedRequest
from app.views import verify_single_proof_view

from django.test import TestCase
from django.db import IntegrityError, transaction

from app.models import ProcessedRequest


# ============================================================
# EXISTING TESTS: BATCH SIGNATURE VALIDATION
# ============================================================

class BatchSignatureValidationTests(SimpleTestCase):

    @patch("app.batch_processor.addNewData")
    @patch("app.batch_processor.Agent.objects.filter")
    @patch("app.batch_processor.PoCAProof.objects.filter")
    @patch(
        "app.batch_processor.verify_poca_signature_with_registry",
        return_value=False,
    )
    def test_invalid_signature_is_rejected_before_anchoring(
        self,
        mock_verify_signature,
        mock_proof_filter,
        mock_agent_filter,
        mock_add_new_data,
    ):
        proof = SimpleNamespace(
            proof_id="TEST-PROOF-001",
            signature="invalid-test-signature",
            agent=SimpleNamespace(
                agent_id="TEST-AGENT",
                name="Test Agent",
                did="did:secureai:test",
                model_hash="test-model-hash",
            ),
        )

        proof_queryset = MagicMock()
        proof_queryset.select_related.return_value = [proof]
        mock_proof_filter.return_value = proof_queryset

        agent_queryset = MagicMock()
        agent_queryset.distinct.return_value = [proof.agent]
        mock_agent_filter.return_value = agent_queryset

        batch = SimpleNamespace(
            pk=1,
            batch_id="TEST-BATCH-001",
            merkle_root="test-merkle-root",
            aggregated_signature="test-aggregate",
            num_proofs=1,
        )

        with patch("app.batch_processor.retrieveData", return_value=[]):
            result = MithrilBatchProcessor.anchor_batch(batch)

        self.assertEqual(result, (False, None, None, None))
        mock_verify_signature.assert_called_once_with(proof, [])
        mock_add_new_data.assert_not_called()


# ============================================================
# EXISTING TESTS: SINGLE-PROOF SIGNATURE VALIDATION
# ============================================================

class SingleProofSignatureValidationTests(SimpleTestCase):

    @patch("app.views.verify_poca_signature_onchain", return_value=False)
    @patch("app.views.PoCAProof.objects.get")
    @patch("app.views.Users.objects.get")
    def test_invalid_signature_is_rejected_before_anchoring(
        self,
        mock_user_get,
        mock_proof_get,
        mock_verify_signature,
    ):
        user = SimpleNamespace(id=1)

        proof = SimpleNamespace(
            proof_id="TEST-PROOF-002",
            submitted_by=user,
            is_batched=False,
            accepted_at=None,
            signature="invalid-test-signature",
        )

        mock_user_get.return_value = user
        mock_proof_get.return_value = proof

        factory = RequestFactory()
        request = factory.post(
            "/verify-single-proof/TEST-PROOF-002/"
        )
        request.session = {
            "is_authenticated": True,
            "user_id": 1,
        }

        with patch(
            "app.blockchain.logic.addNewData"
        ) as mock_add_new_data:
            response = verify_single_proof_view(
                request,
                "TEST-PROOF-002",
            )

        self.assertEqual(response.status_code, 400)
        response_data = json.loads(response.content)

        self.assertFalse(response_data["success"])
        mock_verify_signature.assert_called_once_with(proof)
        mock_add_new_data.assert_not_called()


# ============================================================
# R1.1: CANONICAL POCA SERIALIZATION TESTS
# ============================================================

class CanonicalPoCATestVectorTests(SimpleTestCase):

    PRIVATE_KEY_HEX = "00" * 31 + "01"

    PROOF_ID = "RESP-0001"
    AGENT_DID = "did:secureai:test123"
    CONTEXT_HASH = "sha256:abc123"
    MODEL_HASH = "sha256:def456"
    TIMESTAMP = "2026-10-09T12:30:00+00:00"
    SAFETY_SCORE = 0.87

    EXPECTED_MESSAGE = (
        b'{"agent_did":"did:secureai:test123",'
        b'"context_hash":"sha256:abc123",'
        b'"model_hash":"sha256:def456",'
        b'"proof_id":"RESP-0001",'
        b'"safety_score":"0.87",'
        b'"timestamp":"2026-10-09T12:30:00+00:00",'
        b'"version":1}'
    )

    EXPECTED_MESSAGE_HEX = (
        "7b226167656e745f646964223a226469643a73656375726561693a"
        "74657374313233222c22636f6e746578745f68617368223a2273"
        "68613235363a616263313233222c226d6f64656c5f6861736822"
        "3a227368613235363a646566343536222c2270726f6f665f6964"
        "223a22524553502d30303031222c227361666574795f73636f72"
        "65223a22302e3837222c2274696d657374616d70223a223230"
        "32362d31302d30395431323a33303a30302b30303a3030222c"
        "2276657273696f6e223a317d"
    )

    def _create_signed_proof(self, safety_score=None):
        if safety_score is None:
            safety_score = self.SAFETY_SCORE

        signing_key = SigningKey.from_string(
            bytes.fromhex(self.PRIVATE_KEY_HEX),
            curve=SECP256k1,
        )

        public_key_hex = (
            signing_key.get_verifying_key().to_string().hex()
        )

        agent_did = generate_did(public_key_hex)

        signature = generate_signature(
            proof_id=self.PROOF_ID,
            agent_did=agent_did,
            context_hash=self.CONTEXT_HASH,
            model_hash=self.MODEL_HASH,
            timestamp=self.TIMESTAMP,
            safety_score=self.SAFETY_SCORE,
            private_key_encrypted=encrypt_value(
                self.PRIVATE_KEY_HEX
            ),
        )

        proof = SimpleNamespace(
            agent=SimpleNamespace(
                public_key=public_key_hex,
                did=agent_did,
                model_hash=self.MODEL_HASH,
            ),
            proof_id=self.PROOF_ID,
            context_hash=self.CONTEXT_HASH,
            model_hash=self.MODEL_HASH,
            attestation_timestamp=datetime.fromisoformat(
                self.TIMESTAMP
            ),
            safety_score=safety_score,
            signature=signature,
        )

        return proof

    def test_canonical_message_matches_expected_bytes(self):
        message = canonical_poca_message(
            proof_id=self.PROOF_ID,
            agent_did=self.AGENT_DID,
            context_hash=self.CONTEXT_HASH,
            model_hash=self.MODEL_HASH,
            timestamp=self.TIMESTAMP,
            safety_score=self.SAFETY_SCORE,
        )
        
        self.assertEqual(message, self.EXPECTED_MESSAGE)
        self.assertEqual(
            message.hex(),
            self.EXPECTED_MESSAGE_HEX,
        )
        print("\n========== R1.1 TEST VECTOR ==========")
        print("Canonical JSON:")
        print(self.EXPECTED_MESSAGE.decode("utf-8"))
        print("\nUTF-8 Hex:")
        print(self.EXPECTED_MESSAGE.hex())
        print("\n======================================")



    def test_signature_verifies_for_canonical_message(self):
        proof = self._create_signed_proof()

        self.assertTrue(verify_poca_signature(proof))
        from app.crypto_utils import canonical_poca_message

        message = canonical_poca_message(
            proof_id=proof.proof_id,
            agent_did=proof.agent.did,
            context_hash=proof.context_hash,
            model_hash=proof.model_hash,
            timestamp=proof.attestation_timestamp.isoformat(),
            safety_score=proof.safety_score,
        )

        print("\n========== FINAL R1.1 SIGNED TEST VECTOR ==========")

        print("\nCanonical JSON:")
        print(message.decode("utf-8"))

        print("\nUTF-8 Hex:")
        print(message.hex())

        print("\nRegistered DID:")
        print(proof.agent.did)

        print("\nPublic Key:")
        print(proof.agent.public_key)

        print("\nSignature:")
        print(proof.signature)

        print("\nRegistered Model Hash:")
        print(proof.agent.model_hash)

        print("\nProof Model Hash:")
        print(proof.model_hash)

        print("\nModel Hash Match:")
        print(proof.model_hash == proof.agent.model_hash)

        print("\n===================================================")
                

    def test_modified_signed_field_invalidates_signature(self):
        proof = self._create_signed_proof(safety_score=99.0)

        self.assertFalse(verify_poca_signature(proof))
    
    
    def test_forged_agent_did_is_rejected(self):
        proof = self._create_signed_proof()

        self.assertTrue(verify_poca_signature(proof))

        proof.agent.did = "did:secureai:forged-agent"

        self.assertFalse(verify_poca_signature(proof))

        print("R1.1 Forged DID: REJECTED")


    def test_forged_registered_model_hash_is_rejected(self):
        proof = self._create_signed_proof()

        self.assertTrue(verify_poca_signature(proof))

        proof.agent.model_hash = "sha256:forged-model"

        self.assertFalse(verify_poca_signature(proof))

        print("R1.1 Forged registered model hash: REJECTED")




# ============================================================
# R1.2: PERSISTENT REQUEST-ID STORAGE TESTS
# ============================================================


class ProcessedRequestTests(TestCase):
    """Tests for persistent request-ID storage and duplicate rejection."""

    def test_request_id_is_saved_in_database(self):
        request_id = "R1-2-TEST-001"

        record = ProcessedRequest.objects.create(
            request_id=request_id
        )

        saved_record = ProcessedRequest.objects.get(
            pk=record.pk
        )

        self.assertEqual(saved_record.request_id, request_id)
        self.assertIsNotNone(saved_record.created_at)

    def test_duplicate_request_id_is_rejected(self):
        request_id = "R1-2-DUPLICATE-001"

        ProcessedRequest.objects.create(
            request_id=request_id
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ProcessedRequest.objects.create(
                    request_id=request_id
                )

    def test_different_request_ids_are_allowed(self):
        first = ProcessedRequest.objects.create(
            request_id="R1-2-UNIQUE-001"
        )
        second = ProcessedRequest.objects.create(
            request_id="R1-2-UNIQUE-002"
        )

        self.assertNotEqual(first.request_id, second.request_id)
        self.assertEqual(
            ProcessedRequest.objects.count(), 2
        )



from concurrent.futures import ThreadPoolExecutor
from django.db import IntegrityError, OperationalError, connections, transaction
from django.test import TransactionTestCase
from app.models import ProcessedRequest


class R12ReplayConcurrencyTests(TransactionTestCase):

    def test_two_verifiers_share_processed_ids(self):
        request_id = "R12-MULTI-VERIFIER-001"

        # First verifier claims the request ID.
        ProcessedRequest.objects.create(request_id=request_id)

        # Simulate a separate verifier using another DB connection.
        connections.close_all()

        self.assertTrue(
            ProcessedRequest.objects.filter(
                request_id=request_id
            ).exists()
        )

        # Second verifier must not claim the same identifier.
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ProcessedRequest.objects.create(
                    request_id=request_id
                )

    def test_concurrent_duplicate_requests(self):
        request_id = "R12-CONCURRENT-001"

        def claim_request(_):
            connections.close_all()

            try:
                with transaction.atomic():
                    ProcessedRequest.objects.create(
                        request_id=request_id
                    )
                return "ACCEPTED"

            except IntegrityError:
                return "DUPLICATE_REJECTED"

            except OperationalError:
                return "DATABASE_LOCKED"

            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(claim_request, range(5)))

        print("Concurrent Results:", results)

        self.assertEqual(
            results.count("ACCEPTED"), 1
        )

        self.assertEqual(
            ProcessedRequest.objects.filter(
                request_id=request_id
            ).count(),
            1
        )

        self.assertEqual(
            len(results), 5
        )




import uuid
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from .models import (
    Users,
    Agent,
    PoCAProof,
    MithrilBatch,
    BlockchainTransaction,
)
from .batch_processor import MithrilBatchProcessor


class R25FailureRecoveryTests(TestCase):

    def setUp(self):
        # Create isolated test user and registered agent.
        self.user = Users.objects.create(
            username="r25_test_user",
            email="r25_test@example.com",
            password="test-only-password",
        )

        self.agent = Agent.objects.create(
            agent_id="AGT-R25",
            name="R25 Test Agent",
            description="Recovery test agent",
            llm_provider="ollama",
            model_name="test-model",
            api_key_encrypted="",
            did="did:secureai:r25test",
            public_key="test-public-key",
            private_key_encrypted="test-private-key",
            model_hash="test-model-hash",
            registered_by=self.user,
        )

        # Create five pending PoCA proof fixtures.
        self.proofs = []

        for i in range(5):
            proof = PoCAProof.objects.create(
                proof_id=f"R25-PROOF-{i+1}",
                agent=self.agent,
                submitted_by=self.user,
                query_text=f"Recovery test query {i+1}",
                ai_response="Test response",
                context_hash=f"test-context-{i+1}",
                model_hash=self.agent.model_hash,
                safety_score=0.90,
                attestation_timestamp=timezone.now(),
                signature=f"test-signature-{i+1}",
                accepted_at=timezone.now(),
                is_batched=False,
            )
            self.proofs.append(proof)

        # Mock external cryptographic and registry operations.
        # The tests focus on recovery state transitions,
        # not on cryptographic correctness.
        patchers = [
            patch(
                "app.batch_processor.retrieveData",
                return_value=[],
            ),
            patch(
                "app.batch_processor.verify_poca_signature_with_registry",
                return_value=True,
            ),
            patch(
                "app.batch_processor.build_merkle_tree",
                return_value={"root": "r25-test-merkle-root"},
            ),
            patch(
                "app.batch_processor.generate_aggregated_signature",
                return_value="r25-test-batch-digest",
            ),
            patch(
                "app.batch_processor.generate_batch_id",
                side_effect=lambda: (
                    "BATCH-" + uuid.uuid4().hex[:12]
                ),
            ),
        ]

        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def assert_proofs_pending(self):
        for proof in self.proofs:
            proof.refresh_from_db()
            self.assertFalse(proof.is_batched)
            self.assertIsNone(proof.batch_id)

    def assert_proofs_anchored(self):
        for proof in self.proofs:
            proof.refresh_from_db()
            self.assertTrue(proof.is_batched)
            self.assertIsNotNone(proof.batch_id)
            self.assertEqual(proof.batch.status, "anchored")

    def test_01_failed_anchor_releases_proofs(self):
        """Failed anchoring must release all reserved proofs."""

        with patch.object(
            MithrilBatchProcessor,
            "anchor_batch",
            return_value=(False, None, None, None),
        ):
            batch, message = MithrilBatchProcessor.create_batch()

        self.assertIsNone(batch)
        self.assertEqual(
            MithrilBatch.objects.filter(status="failed").count(),
            1,
        )
        self.assertEqual(
            BlockchainTransaction.objects.filter(
                tx_type="batch_anchor",
                status="failed",
            ).count(),
            1,
        )
        self.assert_proofs_pending()

    def test_02_retry_after_failure_succeeds(self):
        """Released proofs should anchor after blockchain recovery."""

        with patch.object(
            MithrilBatchProcessor,
            "anchor_batch",
            side_effect=[
                (False, None, None, None),
                ("unused", None, None, None),
            ],
        ) as anchor_mock:
            # First call fails.
            batch, message = MithrilBatchProcessor.create_batch()
            self.assertIsNone(batch)
            self.assert_proofs_pending()

            # Replace the next mocked response with success.
            anchor_mock.side_effect = None
            anchor_mock.return_value = (
                True,
                "0x" + "ab" * 32,
                101,
                322321,
            )

            batch, message = MithrilBatchProcessor.create_batch()

        self.assertIsNotNone(batch)
        batch.refresh_from_db()
        self.assertEqual(batch.status, "anchored")
        self.assert_proofs_anchored()

        self.assertEqual(
            BlockchainTransaction.objects.filter(
                tx_type="batch_anchor",
                status="success",
            ).count(),
            1,
        )

    def test_03_repeated_failures_do_not_duplicate_anchor(self):
        """Repeated failures followed by recovery must not double-anchor."""

        with patch.object(
            MithrilBatchProcessor,
            "anchor_batch",
            side_effect=[
                (False, None, None, None),
                (False, None, None, None),
                (False, None, None, None),
                (True, "0x" + "cd" * 32, 102, 322321),
            ],
        ) as anchor_mock:

            # Three controlled failed attempts.
            for attempt in range(3):
                batch, message = MithrilBatchProcessor.create_batch()
                self.assertIsNone(batch)
                self.assert_proofs_pending()

            # Fourth attempt succeeds.
            batch, message = MithrilBatchProcessor.create_batch()

            self.assertIsNotNone(batch)
            self.assertEqual(anchor_mock.call_count, 4)

            # Nothing should remain to anchor again.
            extra_batch, extra_message = (
                MithrilBatchProcessor.create_batch()
            )

        self.assertIsNone(extra_batch)
        self.assert_proofs_anchored()

        self.assertEqual(
            MithrilBatch.objects.filter(status="anchored").count(),
            1,
        )
        self.assertEqual(
            MithrilBatch.objects.filter(status="failed").count(),
            3,
        )
        self.assertEqual(
            BlockchainTransaction.objects.filter(
                tx_type="batch_anchor",
                status="success",
            ).count(),
            1,
        )
        self.assertEqual(
            BlockchainTransaction.objects.filter(
                tx_type="batch_anchor",
                status="failed",
            ).count(),
            3,
        )

        # All five proofs belong to exactly one anchored batch.
        anchored_ids = {
            proof.batch_id for proof in self.proofs
        }
        self.assertEqual(len(anchored_ids), 1)
        self.assertEqual(
            next(iter(anchored_ids)),
            batch.pk,
        )



