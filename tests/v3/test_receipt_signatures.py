import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from sis.errors import InvalidInput
from sis.v3 import signatures
from sis.vault_storage import assert_private_acl, create_private_file
from sis.v3.contracts import ContractError, TaskEnvelopeV1
from sis.v3.policy import AuthorizationDenied
from sis.v3.runner import LocalSubprocessExecutor, ResourceLimits
from sis.v3.verifier import (
    EvaluationRejected,
    EvaluatorKeyStore,
    JournalIntegrityError,
    OutcomeVerifier,
    verify_receipt_signature,
)


PY = sys.executable
ACCEPTANCE = b"import calc\nassert calc.scale(3, 4) == 12\nassert calc.scale(-2, 6) == -12\nprint('ok')\n"


def make_task(task_id="task-scale", base_commit=None):
    return TaskEnvelopeV1(
        schema_version=1,
        task_id=task_id,
        repo_snapshot_digest="0" * 64,
        base_commit=base_commit,
        task_statement_digest="1" * 64,
        permitted_commands=("run-tests",),
        isolation_profile="unverified_local",
        time_budget_seconds=300,
        token_budget=10_000,
        tool_budget=50,
        actor_id="agent-1",
        evaluator_task_ref=task_id,
    )


class VerifierFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.submission = root / "submission"
        self.submission.mkdir()
        (self.submission / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n", encoding="utf-8"
        )
        self.executor = LocalSubprocessExecutor(root / "agent-exec", use_seatbelt=False)
        self.eval_executor = LocalSubprocessExecutor(root / "eval-exec", use_seatbelt=False)
        self.key_dir = root / "evaluator-keys"
        self.registry_dir = root / "evaluator-registry"
        self.verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.key_dir,
            registry_dir=self.registry_dir,
        )
        self.verifier.register_task(
            actor_role="evaluator",
            task_id="task-scale",
            criterion_version="acceptance-v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE},
        )

    def evaluate(self, task=None, nonce="nonce-1", role="evaluator", submission=None):
        return self.verifier.evaluate(
            actor_role=role,
            task=task or make_task(),
            submission_dir=submission or self.submission,
            evaluation_nonce=nonce,
        )



class SignaturePrimitiveTests(unittest.TestCase):
    def test_rfc8032_known_answer(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        public = signatures.public_key(seed)
        self.assertEqual(
            public.hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        expected = (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertEqual(signatures.sign(seed, b"").hex(), expected)
        self.assertTrue(signatures.verify(bytes.fromhex(expected), b"", public))

    def test_malformed_signature_inputs_fail_closed(self):
        seed, public = signatures.generate_keypair()
        signature = signatures.sign(seed, b"data")
        self.assertFalse(signatures.verify(signature, b"other", public))
        self.assertFalse(signatures.verify(signature[:-1], b"data", public))
        self.assertFalse(signatures.verify(signature, b"data", public[:-1]))
        self.assertFalse(signatures.verify("x" * 64, b"data", public))
        self.assertFalse(signatures.verify(signature, b"data", b"\xff" * 32))
        with self.assertRaises(ValueError):
            signatures.sign(b"short", b"data")

    def test_cryptography_backend_agrees_when_installed(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
                Ed25519PublicKey,
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
            )
        except ModuleNotFoundError:
            self.skipTest("cryptography package not installed")
        seed, public = signatures.generate_keypair()
        reference = Ed25519PrivateKey.from_private_bytes(seed)
        reference_public = reference.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.assertEqual(reference_public, public)
        foreign_signature = reference.sign(b"cross-check")
        self.assertTrue(signatures.verify(foreign_signature, b"cross-check", public))
        own_signature = signatures.sign(seed, b"cross-check")
        Ed25519PublicKey.from_public_bytes(public).verify(own_signature, b"cross-check")


class EvaluatorLimitsTests(unittest.TestCase):
    def test_evaluator_limits_are_configurable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executor = LocalSubprocessExecutor(
                root / "exec", use_seatbelt=False)
            default = OutcomeVerifier(
                executor=executor, key_dir=root / "keys",
                registry_dir=root / "registry")
            self.assertEqual(default.limits.process_count, 64)
            relaxed = OutcomeVerifier(
                executor=executor, key_dir=root / "relaxed-keys",
                registry_dir=root / "relaxed-registry",
                limits=ResourceLimits(wall_seconds=90, process_count=None))
            self.assertIsNone(relaxed.limits.process_count)
            self.assertEqual(relaxed.limits.wall_seconds, 90)


class EvaluatorKeyCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_existing_empty_or_malformed_seed_fails_closed_unchanged(self):
        for bad in (b"", b"short"):
            with self.subTest(bad=bad):
                key_dir = self.root / f"keys-{len(bad)}"
                store = EvaluatorKeyStore(key_dir)
                # An existing seed file — created privately, as the
                # keystore itself would — is never treated as absent
                # and never replaced: malformed material fails closed.
                create_private_file(store.seed_path, bad, "evaluator seed")
                with self.assertRaises(JournalIntegrityError):
                    EvaluatorKeyStore(key_dir).load_or_create()
                self.assertEqual(store.seed_path.read_bytes(), bad)

    def test_losing_creator_cannot_replace_seed(self):
        winner = EvaluatorKeyStore(self.root / "keys")
        seed, _ = winner.load_or_create()
        public_bytes = winner.public_path.read_bytes()
        # A second keystore losing the exclusive-create race must fail
        # closed without touching the winner's material or identity.
        loser = EvaluatorKeyStore(self.root / "keys")
        with self.assertRaises(FileExistsError):
            loser._publish_seed(b"x" * 32, b"y" * 32)
        self.assertEqual(winner.seed_path.read_bytes(), seed)
        self.assertEqual(winner.public_path.read_bytes(), public_bytes)
        reloaded = EvaluatorKeyStore(self.root / "keys")
        self.assertEqual(reloaded.load_or_create()[0], seed)

    def test_missing_public_record_is_recreated_from_the_seed(self):
        store = EvaluatorKeyStore(self.root / "keys")
        seed, public = store.load_or_create()
        # A crash between the seed create and the public write leaves the
        # export missing. The seed is the authority, so the record is
        # rebuilt without changing identity.
        store.public_path.unlink()
        reloaded = EvaluatorKeyStore(self.root / "keys")
        self.assertEqual(reloaded.load_or_create(), (seed, public))
        self.assertEqual(store.public_path.read_bytes(), public)

    def test_existing_public_record_is_never_overwritten(self):
        store = EvaluatorKeyStore(self.root / "keys")
        seed, public = store.load_or_create()
        store.public_path.write_bytes(b"z" * 32)
        # The repair fills a hole; it never replaces a record that already
        # holds a full key, so an inconsistency stays visible.
        reloaded = EvaluatorKeyStore(self.root / "keys")
        self.assertEqual(reloaded.load_or_create(), (seed, public))
        self.assertEqual(store.public_path.read_bytes(), b"z" * 32)

    def test_existing_public_key_directory_is_rejected_not_repaired(self):
        if os.name != "posix":
            self.skipTest("POSIX permission semantics")
        key_dir = self.root / "keys"
        key_dir.mkdir()
        os.chmod(key_dir, 0o755)
        with self.assertRaises(InvalidInput):
            EvaluatorKeyStore(key_dir)
        # Rejected, never repaired in place: the mode stays as found.
        self.assertEqual(stat.S_IMODE(key_dir.lstat().st_mode), 0o755)

    def test_symlinked_key_directory_is_rejected(self):
        if os.name != "posix":
            self.skipTest("POSIX symlink semantics")
        real = self.root / "real"
        real.mkdir(0o700)
        link = self.root / "keys"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(InvalidInput):
            EvaluatorKeyStore(link)
        self.assertEqual(real.lstat().st_mode & 0o777, 0o700)

    def test_concurrent_creators_publish_single_identity(self):
        key_dir = self.root / "keys"
        barrier = threading.Barrier(3)
        outcomes = {}

        def create(index):
            try:
                barrier.wait(timeout=10)
                # Construct inside the race: a real second evaluator
                # creates the key directory as well as the seed.
                store = EvaluatorKeyStore(key_dir)
                outcomes[index] = store.load_or_create()[0]
            except Exception as error:  # surfaced by the assertions below
                outcomes[index] = error

        threads = [threading.Thread(target=create, args=(i,))
                   for i in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=20)
        # Both creators succeed and converge on the one published
        # identity: the loser waits out the winner's payload write
        # instead of failing on a half-created seed.
        self.assertEqual(len(outcomes), 2)
        for index, value in outcomes.items():
            self.assertIsInstance(
                value, bytes, f"creator {index} failed: {value!r}")
        self.assertEqual(len(set(outcomes.values())), 1)
        self.assertEqual((key_dir / "ed25519.seed").read_bytes(),
                         outcomes[0])
        self.assertEqual(EvaluatorKeyStore(key_dir).load_or_create()[0],
                         outcomes[0])


class VerifierCustodyTests(VerifierFixture):
    def test_signed_receipt_round_trips_and_verifies_offline(self):
        receipt = self.evaluate()
        self.assertEqual(receipt.outcome, "pass")
        self.assertTrue(self.verifier.verify_receipt(receipt))
        record = self.verifier.public_key_record()
        self.assertEqual(record["key_id"], receipt.signer_key_id)
        self.assertTrue(verify_receipt_signature(receipt, record["public_key"]))
        self.assertTrue((self.key_dir / "ed25519.seed").is_file())
        if os.name == "posix":
            self.assertEqual(
                (self.key_dir / "ed25519.seed").stat().st_mode & 0o777,
                0o600)
        else:
            # POSIX mode bits cannot express Windows privacy: the seed
            # and its directory must carry a DACL limited to this
            # user, SYSTEM, and Administrators — the same inspection the
            # evaluator vault enforces.
            assert_private_acl(
                self.key_dir / "ed25519.seed", "evaluator seed")
            assert_private_acl(self.key_dir, "evaluator key directory")

    def test_tampered_receipt_body_fails_verification(self):
        receipt = self.evaluate()
        forged = receipt.to_dict()
        forged["outcome"] = "fail"
        forged["evaluated_repo_digest"] = "9" * 64
        self.assertFalse(self.verifier.verify_receipt(forged))
        self.assertFalse(
            verify_receipt_signature(forged, self.verifier.public_key_record()["public_key"])
        )

    def test_wrong_key_and_unknown_signer_fail(self):
        receipt = self.evaluate()
        other_verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=Path(self.temp.name) / "other-keys",
            registry_dir=Path(self.temp.name) / "other-registry",
        )
        self.assertFalse(other_verifier.verify_receipt(receipt))
        forged = receipt.to_dict()
        forged["signer_key_id"] = "key-does-not-exist"
        self.assertFalse(self.verifier.verify_receipt(forged))

    def test_replayed_nonce_and_duplicate_evaluation_are_rejected(self):
        self.evaluate(nonce="attempt-1")
        with self.assertRaisesRegex(EvaluationRejected, "replayed_nonce"):
            self.evaluate(nonce="attempt-1")
        with self.assertRaisesRegex(EvaluationRejected, "duplicate_evaluation"):
            self.evaluate(nonce="attempt-2")

    def test_nonce_reuse_survives_verifier_restart(self):
        self.evaluate(nonce="attempt-9")
        restarted = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.key_dir,
            registry_dir=self.registry_dir,
        )
        with self.assertRaisesRegex(EvaluationRejected, "replayed_nonce"):
            restarted.evaluate(
                actor_role="evaluator",
                task=make_task(),
                submission_dir=self.submission,
                evaluation_nonce="attempt-9",
            )

    def test_unregistered_task_and_source_mismatch_rejected(self):
        with self.assertRaisesRegex(EvaluationRejected, "unregistered_task"):
            self.evaluate(task=make_task(task_id="unregistered"))
        self.verifier.register_task(
            actor_role="evaluator",
            task_id="task-pinned",
            criterion_version="v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE},
            base_commit="a" * 40,
        )
        with self.assertRaisesRegex(EvaluationRejected, "source_mismatch"):
            self.evaluate(task=make_task(task_id="task-pinned", base_commit="b" * 40))
        with self.assertRaisesRegex(EvaluationRejected, "source_mismatch"):
            self.evaluate(task=make_task(task_id="task-pinned", base_commit=None))

    def test_agent_and_other_roles_cannot_evaluate(self):
        for role in ("agent", "runner", "learner", "operator", "forged"):
            with self.subTest(role=role):
                with self.assertRaises(AuthorizationDenied):
                    self.evaluate(role=role)

    def test_failing_submission_produces_signed_fail_receipt(self):
        buggy = Path(self.temp.name) / "buggy"
        shutil.copytree(self.submission, buggy)
        (buggy / "calc.py").write_text("def scale(a, b):\n    return a - b\n")
        receipt = self.evaluate(submission=buggy)
        self.assertEqual(receipt.outcome, "fail")
        self.assertTrue(self.verifier.verify_receipt(receipt))

    def test_changed_task_commitment_conflicts(self):
        with self.assertRaisesRegex(EvaluationRejected, "task_registration_conflict"):
            self.verifier.register_task(
                actor_role="evaluator",
                task_id="task-scale",
                criterion_version="acceptance-v2",
                argv=(PY, "different.py"),
            )

    def test_statement_digest_binding_is_enforced(self):
        digest = "a" * 64
        self.verifier.register_task(
            actor_role="evaluator",
            task_id="task-bound",
            criterion_version="v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE},
            statement_digest=digest,
        )
        bound = TaskEnvelopeV1.from_dict(
            {**make_task(task_id="task-bound").to_dict(),
             "task_statement_digest": digest})
        self.assertEqual(self.evaluate(task=bound).outcome, "pass")
        mismatched = TaskEnvelopeV1.from_dict(
            {**bound.to_dict(), "task_statement_digest": "b" * 64})
        with self.assertRaisesRegex(EvaluationRejected, "statement_mismatch"):
            self.evaluate(task=mismatched, nonce="nonce-2")
        restarted = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.key_dir,
            registry_dir=self.registry_dir,
        )
        with self.assertRaisesRegex(EvaluationRejected, "statement_mismatch"):
            restarted.evaluate(
                actor_role="evaluator", task=mismatched,
                submission_dir=self.submission, evaluation_nonce="nonce-3")
        with self.assertRaisesRegex(EvaluationRejected, "task_registration_conflict"):
            self.verifier.register_task(
                actor_role="evaluator", task_id="task-bound",
                criterion_version="v1", argv=(PY, "acceptance.py"),
                files={"acceptance.py": ACCEPTANCE},
                statement_digest="c" * 64)
        with self.assertRaises(ContractError):
            self.verifier.register_task(
                actor_role="evaluator", task_id="task-bad-digest",
                criterion_version="v1", argv=(PY, "acceptance.py"),
                statement_digest="not-a-digest")

    def test_corrupt_journal_fails_closed_on_restart(self):
        self.evaluate()
        journal = self.registry_dir / "receipts.jsonl"
        journal.write_bytes(b"{corrupt\n")
        with self.assertRaises(JournalIntegrityError):
            OutcomeVerifier(
                executor=self.eval_executor,
                key_dir=self.key_dir,
                registry_dir=self.registry_dir,
            )


class BackendDispatchTests(unittest.TestCase):
    """Active backend is reported; vendored path stays wire-compatible."""

    def test_backend_reports_active_provider(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.assertEqual(signatures.backend(), "vendored-python")
        else:
            self.assertEqual(signatures.backend(), "cryptography")

    def test_vendored_fallback_interoperates_with_active_backend(self):
        seed = bytes(range(32))
        self.assertEqual(signatures.public_key(seed), signatures._py_public_key(seed))
        message = b"sis-v3 test message"
        self.assertEqual(
            signatures.sign(seed, message), signatures._py_sign(seed, message)
        )
        sig = signatures._py_sign(seed, message)
        self.assertTrue(signatures.verify(sig, message, signatures.public_key(seed)))
        sig2 = signatures.sign(seed, message)
        self.assertTrue(
            signatures._py_verify(sig2, message, signatures._py_public_key(seed))
        )

    def test_persisted_receipt_reloads_by_digest(self):
        class _Fixture(VerifierFixture):
            def runTest(self):
                receipt = self.evaluate()
                loaded = self.verifier.load_receipt(receipt.digest)
                self.assertEqual(loaded, receipt)
                fresh = OutcomeVerifier(
                    executor=self.eval_executor,
                    key_dir=self.key_dir,
                    registry_dir=self.registry_dir,
                )
                self.assertEqual(fresh.load_receipt(receipt.digest), receipt)

        _Fixture("runTest")()


if __name__ == "__main__":
    unittest.main()


class FailureClassRegistryTests(VerifierFixture):
    def test_failure_class_is_registered_and_persisted(self):
        self.assertIsNone(self.verifier.failure_class_for("task-scale"))
        self.verifier.register_task(
            actor_role="evaluator", task_id="task-money",
            criterion_version="acceptance-v1", argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE},
            failure_class="convention_unknown:money")
        self.assertEqual(self.verifier.failure_class_for("task-money"),
                         "convention_unknown:money")
        reloaded = OutcomeVerifier(
            executor=self.eval_executor, key_dir=self.key_dir,
            registry_dir=self.registry_dir)
        self.assertEqual(reloaded.failure_class_for("task-money"),
                         "convention_unknown:money")
        self.assertIsNone(reloaded.failure_class_for("task-scale"))

    def test_conflicting_failure_class_is_rejected(self):
        kwargs = dict(
            actor_role="evaluator", task_id="task-money",
            criterion_version="acceptance-v1", argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE})
        self.verifier.register_task(**kwargs, failure_class="class-a")
        with self.assertRaises(EvaluationRejected):
            self.verifier.register_task(**kwargs, failure_class="class-b")

    def test_malformed_failure_class_is_rejected(self):
        with self.assertRaises(ContractError):
            self.verifier.register_task(
                actor_role="evaluator", task_id="task-bad",
                criterion_version="acceptance-v1", argv=(PY, "acceptance.py"),
                files={"acceptance.py": ACCEPTANCE},
                failure_class="bad\x00class")


class ReceiptFailureClassTests(VerifierFixture):
    def test_failure_class_is_signed_and_persisted(self):
        self.verifier.register_task(
            actor_role="evaluator", task_id="task-money",
            criterion_version="acceptance-v1", argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE},
            failure_class="convention_unknown:money")
        receipt = self.evaluate(task=make_task("task-money"),
                                nonce="nonce-failure-class")
        self.assertEqual(receipt.failure_class, "convention_unknown:money")
        self.assertTrue(verify_receipt_signature(
            receipt, self.verifier.keystore.public.hex()))
        reloaded = OutcomeVerifier(
            executor=self.eval_executor, key_dir=self.key_dir,
            registry_dir=self.registry_dir)
        self.assertEqual(
            reloaded.load_receipt(receipt.digest).failure_class,
            "convention_unknown:money")

    def test_receipt_without_failure_class_keeps_historical_form(self):
        receipt = self.evaluate(nonce="nonce-legacy-form")
        self.assertIsNone(receipt.failure_class)
        self.assertNotIn("failure_class", receipt.to_dict())
        self.assertTrue(verify_receipt_signature(
            receipt, self.verifier.keystore.public.hex()))
