"""Independent outcome evaluation and signed receipts (SIS3-006).

The verifier is the only component that turns a submission into a labeled
outcome. It owns its task registry, its signing key, and its receipt journal
under directories the caller dedicates to evaluator custody; ``evaluate``
re-digests the submitted repository itself, replays registered acceptance
material into a fresh evaluator-owned workspace, and signs the resulting
``OutcomeReceiptV1`` (development) or ``OutcomeReceiptV2`` (production,
binding execution and isolation evidence) over the canonical payload.

Custody model: ``key_dir`` holds the Ed25519 seed (mode 0700/0600 on POSIX,
a DACL restricted to the evaluator account and SYSTEM on Windows) and must
be a distinct directory from the episode store and the agent workspace. The
public key record is separately exportable, so third parties can verify
receipts offline without touching the private key.

Rejected evidence: unregistered or mismatched tasks, source-commit mismatch,
replayed evaluation nonces, duplicate evaluations of the same tree, malformed
or corrupt journals, and forged signatures. Rejection raises
:class:`EvaluationRejected` with a stable ``reason`` code.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import signatures
from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    OutcomeReceiptV2,
    TaskEnvelopeV1,
    canonical_digest,
    canonical_json,
    loads_json,
    parse_outcome_receipt,
)
from .evaluation_runtime import (
    EVALUATOR_BOOTSTRAP_ERROR,
    INFRASTRUCTURE_ERROR,
    SANDBOX_FAILURE,
    EvaluationRuntimeProfile,
    bootstrap_check,
    classify_execution,
    classify_production_execution,
)
from .isolation import (
    ProductionIsolationPolicy,
)
from .policy import require_permission
from .runner import (
    CommandSpec,
    ResourceLimits,
    WorkspaceExecutor,
    normalize_private_files,
    tree_digest,
)
from .split_harness import MARKER_SPLIT, is_python_command
from ..vault_storage import (
    assert_private_acl,
    create_private_file,
    ensure_private_directory,
)

_SIGNATURE_DOMAIN = b"sis-v3:outcome_receipt:1\0"
_SIGNATURE_DOMAIN_V2 = b"sis-v3:outcome_receipt:2\0"

_DIGEST = re.compile(r"[0-9a-f]{64}")

# Fields every journal line must carry before it can corroborate anything.
# Entries written by older evaluators may lack the newer optional keys;
# those are handled as unverified rather than rejected.
_JOURNAL_REQUIRED_FIELDS = frozenset({
    "receipt_digest", "receipt_id", "task_id", "evaluated_repo_digest",
    "criterion_version", "outcome", "execution_digest", "nonce", "issued_at",
})
_JOURNAL_STRING_FIELDS = (
    "receipt_id", "task_id", "criterion_version", "outcome", "nonce", "issued_at",
)

# A losing seed creator can observe the exclusively-created file before
# the winner's 32 bytes are written through it. Waiting briefly for the
# payload turns that race into a wait instead of a spurious integrity
# failure; a file that never reaches 32 bytes still fails closed.
_SEED_READ_ATTEMPTS = 50
_SEED_READ_DELAY_SECONDS = 0.01


class EvaluationRejected(RuntimeError):
    """The evaluator refuses to produce a receipt for this submission."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


class JournalIntegrityError(RuntimeError):
    """The evaluator's own receipt journal is unreadable or corrupt."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_receipt(value) -> OutcomeReceiptV1 | OutcomeReceiptV2:
    """Dispatch a stored receipt on its signed field set."""
    return parse_outcome_receipt(value)


def _receipt_domain(record) -> bytes:
    return (_SIGNATURE_DOMAIN_V2 if isinstance(record, OutcomeReceiptV2)
            else _SIGNATURE_DOMAIN)


class EvaluatorKeyStore:
    """Loads or creates an Ed25519 seed under evaluator-only permissions."""

    def __init__(self, key_dir: str | Path) -> None:
        self.key_dir = Path(key_dir)
        # The key directory is created private (0700 on POSIX, a
        # protected DACL on Windows). A pre-existing directory is only
        # ever verified, never re-permissioned: repairing the mode of a
        # location this process did not create would silently claim
        # custody of someone else's directory. Windows privacy is the
        # DACL, which chmod/open mode bits cannot express.
        ensure_private_directory(self.key_dir, "evaluator key directory")
        self.seed_path = self.key_dir / "ed25519.seed"
        self.public_path = self.key_dir / "ed25519.pub"
        self._seed: bytes | None = None
        self._public: bytes | None = None

    def load_or_create(self) -> tuple[bytes, bytes]:
        """Return ``(seed, public_key)``, generating and persisting if absent."""
        try:
            seed, public = signatures.generate_keypair()
            self._publish_seed(seed, public)
        except FileExistsError:
            # An existing seed is only ever read, never created,
            # replaced, or re-ACL'd: losing an exclusive-create race
            # must not overwrite another creator's material or
            # identity, and existing empty or malformed material fails
            # closed in place.
            seed, public = self._read_published_seed()
        self._seed, self._public = seed, public
        return seed, public

    def _read_published_seed(self) -> tuple[bytes, bytes]:
        """Read a seed another creator published, waiting for its payload.

        ``O_EXCL``/``CREATE_NEW`` publish the seed *name* before the
        bytes land, so a concurrent loser may open a zero-length file.
        The bounded retry makes simultaneous evaluator starts succeed
        with one shared identity instead of one of them failing; a file
        that never reaches 32 bytes (a crash-truncated seed, an empty
        file) still fails closed.
        """
        for attempt in range(_SEED_READ_ATTEMPTS):
            if self.seed_path.is_file():
                assert_private_acl(self.seed_path, "evaluator seed")
                existing = self.seed_path.read_bytes()
                if len(existing) == 32:
                    public = signatures.public_key(existing)
                    self._ensure_public_record(public)
                    return existing, public
            elif self.seed_path.exists() or self.seed_path.is_symlink():
                raise JournalIntegrityError(
                    "evaluator seed file is malformed")
            if attempt + 1 < _SEED_READ_ATTEMPTS:
                time.sleep(_SEED_READ_DELAY_SECONDS)
        raise JournalIntegrityError("evaluator seed file is malformed")

    def _ensure_public_record(self, public: bytes) -> None:
        """Recreate the exported public key when a partial publish left it absent.

        A crash between the seed create and the public write leaves
        receipts working — the public key is derived from the seed —
        while the export is missing. Recreating it is idempotent and
        cannot change identity. A record that already holds a full key
        is never rewritten: this repair fills a hole, it does not
        overwrite another creator's material.
        """
        try:
            existing = self.public_path.read_bytes()
        except FileNotFoundError:
            existing = b""
        if len(existing) == 32:
            return
        self._write_public_record(public)

    def _write_public_record(self, public: bytes) -> None:
        self.public_path.write_bytes(public)
        if os.name != "nt":
            os.chmod(self.public_path, 0o644)

    def _publish_seed(self, seed: bytes, public: bytes) -> None:
        """Publish a fresh seed; ``FileExistsError`` if the name is taken.

        The seed file is created exclusively — ``O_EXCL`` on POSIX,
        ``CREATE_NEW`` plus a protected DACL on Windows — so seed bytes
        only ever land in a file this call created with owner-only
        access. The name claim is atomic; the payload follows through
        that same exclusively-created file, and a concurrent reader
        waits for it (:meth:`_read_published_seed`). Nothing is written
        to ``public_path`` unless the seed creation itself wins.
        """
        create_private_file(self.seed_path, seed, "evaluator seed")
        self._write_public_record(public)

    @property
    def key_id(self) -> str:
        if self._public is None:
            self.load_or_create()
        return "key-" + hashlib.sha256(self._public).hexdigest()[:24]

    @property
    def public(self) -> bytes:
        if self._public is None:
            self.load_or_create()
        return self._public


@dataclass(frozen=True)
class RegisteredTask:
    task_id: str
    criterion_version: str
    argv: tuple[str, ...]
    files: Mapping[str, bytes]
    base_commit: str | None
    suite_commitment: str
    statement_digest: str | None = None
    failure_class: str | None = None
    custody: str = "shared"


def _suite_commitment(
    *,
    task_id: str,
    criterion_version: str,
    argv,
    files: Mapping[str, bytes],
    base_commit: str | None,
    failure_class: str | None,
    custody: str,
) -> str:
    """The commitment a registration binds for its task identity.

    Shared custody is the historical default and is not named in the
    payload, so a registration that predates the field keeps its
    commitment. Registry load uses the same function to recover custody
    for a row written before it was persisted.
    """
    payload = {
        "task_id": task_id,
        "criterion_version": criterion_version,
        "argv": list(argv),
        "files": {name: hashlib.sha256(data).hexdigest()
                  for name, data in sorted(files.items())},
        "base_commit": base_commit,
    }
    if failure_class is not None:
        # Bound only when declared, so existing registrations keep their
        # historical commitments.
        payload["failure_class"] = failure_class
    if custody != "shared":
        payload["custody"] = custody
    return canonical_digest("test_suite", 1, payload)


def _recover_custody(item: dict, files: Mapping[str, bytes]) -> str:
    """Recover custody for a registry row written before it was persisted.

    Returning the shared default for a split row would silently downgrade
    the boundary the registration was meant to hold, and the worker
    reloads the registry in every child process. The commitment names
    custody only when it is not shared, so matching both variants
    recovers the original mode without trusting an absent field.
    """
    for candidate in ("shared", "split"):
        if _suite_commitment(
            task_id=item["task_id"],
            criterion_version=item["criterion_version"],
            argv=tuple(item["argv"]),
            files=files,
            base_commit=item["base_commit"],
            failure_class=item.get("failure_class"),
            custody=candidate,
        ) == item["suite_commitment"]:
            return candidate
    raise JournalIntegrityError(
        "task registry custody cannot be recovered from its commitment")


class OutcomeVerifier:
    """Produces signed outcome receipts; never trusts submitter-reported results."""

    def __init__(
        self,
        *,
        executor: WorkspaceExecutor,
        key_dir: str | Path,
        registry_dir: str | Path,
        identity: str = "sis-v3-evaluator",
        trusted_keys: Mapping[str, str] | None = None,
        limits: ResourceLimits | None = None,
        runtime_profile: EvaluationRuntimeProfile | None = None,
        protected_paths=(),
        isolation_policy: ProductionIsolationPolicy | None = None,
        require_split_custody: bool = False,
    ) -> None:
        self.executor = executor
        self.identity = identity
        # A deployment that requires split custody cannot be served by a
        # backend with no second principal. Refuse construction rather
        # than accepting registrations that could only fail later.
        if (require_split_custody
                and not getattr(executor, "supports_split_custody", False)):
            raise ContractError("split_custody_required_but_unavailable")
        self.require_split_custody = bool(require_split_custody)
        self.runtime_profile = runtime_profile or EvaluationRuntimeProfile()
        if (isolation_policy is not None
                and not isinstance(isolation_policy, ProductionIsolationPolicy)):
            raise ContractError(
                "isolation_policy must be a ProductionIsolationPolicy")
        self.isolation_policy = isolation_policy
        # Acceptance-suite resource envelope. The 2 GiB default covers
        # pytest plus plugin imports; a meta-test that runs the submitted
        # suite in a nested process needs process_count=None on platforms
        # where RLIMIT_NPROC counts every process of the user.
        self.limits = limits or self.runtime_profile.task_limits
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.keystore = EvaluatorKeyStore(key_dir)
        self.keystore.load_or_create()
        # Hostile submitted code must not read signing material, the
        # evaluator's task registry or sealed datasets. The local
        # executor enforces this with seatbelt when available; elsewhere
        # the receipt records that isolation is unverified.
        protect = getattr(self.executor, "protect", None)
        if callable(protect):
            protect(self.keystore.key_dir)
            protect(self.registry_dir)
            for path in protected_paths:
                protect(path)
        self._bootstrap = None
        self.last_outcome_class: str | None = None
        self.last_bootstrap = None
        self._tasks_path = self.registry_dir / "tasks.json"
        self._journal_path = self.registry_dir / "receipts.jsonl"
        self._tasks: dict[str, RegisteredTask] = {}
        self._nonces: set[str] = set()
        self._evaluated: set[tuple[str, str, str]] = set()
        # Journal entries whose persisted receipt was re-authenticated on
        # load. Only these may corroborate an execution digest.
        self._verified_receipts: set[str] = set()
        self._journal_by_digest: dict[str, dict] = {}
        for public_hex in (trusted_keys or {}).values():
            if not (isinstance(public_hex, str)
                    and re.fullmatch(r"[0-9a-f]{64}", public_hex)
                    and signatures.is_valid_public_key(
                        bytes.fromhex(public_hex))):
                raise ContractError("trusted_public_key_invalid")
        self._trusted: dict[str, str] = dict(trusted_keys or {})
        self._trusted[self.keystore.key_id] = self.keystore.public.hex()
        self._load_state()

    def register_task(
        self,
        *,
        actor_role: str,
        task_id: str,
        criterion_version: str,
        argv: tuple[str, ...] | list[str],
        files: Mapping[str, bytes] | None = None,
        base_commit: str | None = None,
        statement_digest: str | None = None,
        failure_class: str | None = None,
        custody: str = "shared",
    ) -> RegisteredTask:
        """Record evaluator-private acceptance material for a task identity.

        ``custody="split"`` runs the acceptance command in the evaluator's
        process and reaches submitted code only through an out-of-process
        proxy, so a submission cannot read the tests it is graded against.
        The backend must support it; evaluation fails closed otherwise.
        A verifier constructed with ``require_split_custody=True`` refuses
        to register private acceptance files under shared custody.
        """
        require_permission(actor_role, "outcome:evaluate")
        if custody not in ("shared", "split"):
            raise ContractError("custody must be 'shared' or 'split'")
        if statement_digest is not None and not (
            isinstance(statement_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", statement_digest)
        ):
            raise ContractError("statement_digest must be a lowercase SHA-256 hex digest")
        if failure_class is not None and not (
            isinstance(failure_class, str)
            and 0 < len(failure_class) <= 128
            and not any(ord(ch) < 32 for ch in failure_class)
        ):
            raise ContractError(
                "failure_class must be a bounded printable string")
        command = CommandSpec(argv=tuple(argv))
        # The same bounds the executor enforces when staging private material
        # are enforced here, so an over-bound registration fails at
        # registration instead of surfacing as an infrastructure error.
        material = normalize_private_files(dict(files or {}))
        if self.require_split_custody and material and custody != "split":
            raise ContractError(
                "split_custody_required_for_private_material")
        if custody == "split" and not material:
            raise ContractError(
                "split custody requires registered acceptance files")
        if custody == "split" and not is_python_command(command.argv):
            # The split harness is a Python bootstrap. Refusing here keeps
            # a non-Python command from being handed the bootstrap and
            # scored as if the submission had failed.
            raise ContractError(
                "split custody requires a Python acceptance command")
        commitment = _suite_commitment(
            task_id=task_id,
            criterion_version=criterion_version,
            argv=command.argv,
            files=material,
            base_commit=base_commit,
            failure_class=failure_class,
            custody=custody,
        )
        task = RegisteredTask(
            task_id=task_id,
            criterion_version=criterion_version,
            argv=command.argv,
            files=material,
            base_commit=base_commit,
            suite_commitment=commitment,
            statement_digest=statement_digest,
            failure_class=failure_class,
            custody=custody,
        )
        existing = self._tasks.get(task_id)
        if existing is not None:
            if (existing.suite_commitment != task.suite_commitment or
                    existing.statement_digest != task.statement_digest or
                    existing.failure_class != task.failure_class or
                    existing.custody != task.custody):
                raise EvaluationRejected("task_registration_conflict", task_id)
            return existing
        self._tasks[task_id] = task
        self._persist_tasks()
        return task

    def registered_task(self, task_id: str) -> RegisteredTask | None:
        """The evaluator's private registration for a task identity, if any.

        Memory lineage uses this to prove an experience points at a task
        this evaluator actually registered, not just at a receipt that
        names a task ID.
        """
        if not isinstance(task_id, str):
            return None
        return self._tasks.get(task_id)

    def failure_class_for(self, task_id: str) -> str | None:
        """The trusted failure class registered for a task identity."""
        task = self.registered_task(task_id)
        return task.failure_class if task is not None else None

    def bootstrap(self):
        """Run the evaluator bootstrap probe once (cached)."""
        if self._bootstrap is None:
            from .evaluation_runtime import BootstrapResult
            try:
                self.runtime_profile.assert_pinned()
            except Exception as exc:
                self._bootstrap = BootstrapResult(
                    ok=False, reason="runtime_pin_mismatch",
                    detail=f"{type(exc).__name__}: {exc}")
            else:
                # The bootstrap base tree must not live under the
                # protected registry/key directories: workspace
                # preparation rejects any source tree that overlaps
                # evaluator material.
                self._bootstrap = bootstrap_check(
                    self.executor, self.runtime_profile)
        self.last_bootstrap = self._bootstrap
        return self._bootstrap

    def evaluate(
        self,
        *,
        actor_role: str,
        task: TaskEnvelopeV1,
        submission_dir: str | Path,
        evaluation_nonce: str,
        attempt_id: str | None = None,
        isolation_attestation=None,
        isolation_attestation_resolver=None,
    ) -> OutcomeReceiptV1 | OutcomeReceiptV2:
        """Independently evaluate a submission tree and sign the outcome.

        A verifier constructed with a ``ProductionIsolationPolicy``
        requires a separately signed ``IsolationAttestationV1`` for the
        exact execution receipt. The attestation is issued after the
        execution, so callers either pass it explicitly or supply
        ``isolation_attestation_resolver(receipt)``, which fetches it by
        the receipt the worker actually produced. Missing or invalid
        containment evidence rejects the evaluation instead of issuing a
        pass/fail receipt, and the signed outcome is an
        ``OutcomeReceiptV2`` binding the execution, attestation, runtime,
        protocol, worker and sandbox policy digests. Development
        verifiers keep issuing V1.
        """
        if (isolation_attestation_resolver is not None
                and not callable(isolation_attestation_resolver)):
            raise ContractError(
                "isolation_attestation_resolver must be callable")
        require_permission(actor_role, "outcome:evaluate")
        if not isinstance(task, TaskEnvelopeV1):
            task = TaskEnvelopeV1.from_dict(task)
        task_ref = task.evaluator_task_ref or task.task_id
        registration = self._tasks.get(task_ref)
        if registration is None:
            raise EvaluationRejected("unregistered_task", task_ref)
        if registration.base_commit and registration.base_commit != task.base_commit:
            raise EvaluationRejected("source_mismatch", task.base_commit or "none")
        if (registration.statement_digest is not None and
                registration.statement_digest != task.task_statement_digest):
            raise EvaluationRejected("statement_mismatch", task.task_id)
        if (self.require_split_custody and registration.files
                and registration.custody != "split"):
            # A registration can predate the policy. It still hides
            # acceptance material, so it must not run beside the tests.
            self.last_outcome_class = EVALUATOR_BOOTSTRAP_ERROR
            raise EvaluationRejected(
                "split_custody_required", registration.task_id)
        if (self.isolation_policy is not None
                and task.isolation_profile == "unverified_local"):
            raise EvaluationRejected(
                "production_requires_qualified_task_profile")
        if self.isolation_policy is not None:
            if (not isinstance(attempt_id, str) or not attempt_id.strip()
                    or len(attempt_id) > 128):
                raise EvaluationRejected("missing_attempt_id")
        if not isinstance(evaluation_nonce, str) or not evaluation_nonce.strip() or len(evaluation_nonce) > 128:
            raise EvaluationRejected("missing_nonce")
        if evaluation_nonce in self._nonces:
            raise EvaluationRejected("replayed_nonce", evaluation_nonce)

        submission = Path(submission_dir)
        if not submission.is_dir():
            raise EvaluationRejected("submission_missing", str(submission))
        evaluated_repo_digest = tree_digest(submission)
        marker = (registration.task_id, evaluated_repo_digest, registration.criterion_version)
        if marker in self._evaluated:
            raise EvaluationRejected("duplicate_evaluation", registration.task_id)

        bootstrap = self.bootstrap()
        if not bootstrap.ok:
            self.last_outcome_class = EVALUATOR_BOOTSTRAP_ERROR
            raise EvaluationRejected(
                "evaluator_bootstrap_error", bootstrap.reason)

        split = registration.custody == "split"
        if split and not getattr(self.executor, "supports_split_custody", False):
            # A split task must never silently fall back to shared custody:
            # that is the configuration the registration was meant to avoid.
            self.last_outcome_class = EVALUATOR_BOOTSTRAP_ERROR
            raise EvaluationRejected(
                "split_custody_unavailable",
                type(self.executor).__name__)
        argv = registration.argv
        if len(argv) >= 3 and argv[1] == "-m" and argv[2] == "pytest":
            argv = self.runtime_profile.pytest_argv(argv)
        workspace = self.executor.prepare(submission, label="eval")
        try:
            private_files = dict(registration.files)
            # A backend that supports private material stages it outside the
            # submission tree. Only a legacy backend without that capability
            # still writes acceptance files into the workspace being graded.
            separated = bool(private_files) and bool(
                getattr(self.executor, "supports_private_material", False))
            if private_files and not separated:
                for name, data in private_files.items():
                    target = workspace.path / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
            spec = CommandSpec(
                argv=argv, limits=self.limits,
                env=self.runtime_profile.environment())
            if split:
                receipt_exec = self.executor.run(
                    workspace, spec, private_files=private_files,
                    split_custody=True)
            elif separated:
                receipt_exec = self.executor.run(
                    workspace, spec, private_files=private_files)
            else:
                receipt_exec = self.executor.run(workspace, spec)
        except Exception as exc:
            if str(exc).startswith("split_custody_"):
                # The harness itself could not be established; the exit
                # status says nothing about the submission.
                self.last_outcome_class = EVALUATOR_BOOTSTRAP_ERROR
                raise EvaluationRejected(
                    "split_custody_unavailable",
                    f"{type(exc).__name__}: {exc}") from exc
            self.last_outcome_class = INFRASTRUCTURE_ERROR
            raise EvaluationRejected(
                "evaluator_infrastructure_error",
                f"{type(exc).__name__}: {exc}") from exc
        finally:
            # Cleanup failure must not replace the classified outcome;
            # the workspace is disposable either way.
            try:
                self.executor.destroy(workspace)
            except Exception:
                pass

        if split and MARKER_SPLIT not in (receipt_exec.security_errors or ()):
            # The executor did not record the split it was asked for, so
            # the tests may have run beside the submission.
            self.last_outcome_class = SANDBOX_FAILURE
            raise EvaluationRejected("split_custody_unverified",
                                     receipt_exec.execution_id)
        stderr_tail = ""
        output = getattr(self.executor, "output", None)
        if callable(output):
            try:
                _, stderr = output(receipt_exec.execution_id)
                stderr_tail = stderr.decode("utf-8", "replace")[-800:]
            except Exception:
                pass
        verification = None
        if self.isolation_policy is not None:
            attestation = isolation_attestation
            if attestation is None and isolation_attestation_resolver is not None:
                try:
                    attestation = isolation_attestation_resolver(receipt_exec)
                except Exception as exc:
                    self.last_outcome_class = SANDBOX_FAILURE
                    raise EvaluationRejected(
                        "isolation_attestation_unavailable",
                        f"{type(exc).__name__}: {exc}") from exc
            if attestation is None:
                self.last_outcome_class = SANDBOX_FAILURE
                raise EvaluationRejected("isolation_attestation_required")
            classification = classify_production_execution(
                receipt_exec, attestation, self.isolation_policy,
                bootstrap_ok=True, stderr_tail=stderr_tail)
            verification = classification.verification
            if not verification.ok:
                self.last_outcome_class = SANDBOX_FAILURE
                raise EvaluationRejected(
                    "isolation_unverified", verification.reason)
            outcome_class = classification.outcome_class
        else:
            outcome_class = classify_execution(
                receipt_exec, bootstrap_ok=True, stderr_tail=stderr_tail)
        self.last_outcome_class = outcome_class
        if outcome_class == "TASK_PASS":
            outcome = "pass"
        elif outcome_class == "TASK_FAIL":
            outcome = "fail"
        else:
            # Bootstrap/resource/timeout/sandbox/infrastructure failures
            # are not evidence that the candidate is ineffective.
            outcome = "error"

        common = {
            "schema_version": 1,
            "receipt_id": "rcpt-" + secrets.token_hex(12),
            "evaluator_identity": self.identity,
            "task_id": registration.task_id,
            "evaluated_repo_digest": evaluated_repo_digest,
            "test_suite_commitment": registration.suite_commitment,
            "criterion_version": registration.criterion_version,
            "outcome": outcome,
            "regression_evidence": [],
            "signer_key_id": self.keystore.key_id,
        }
        if registration.failure_class is not None:
            # Bound into the signed payload so a scope grant can check that
            # the witness belongs to the procedure's failure class.
            common["failure_class"] = registration.failure_class
        seed = self.keystore._seed or self.keystore.load_or_create()[0]
        if self.isolation_policy is not None:
            protocol_digest = canonical_digest("evaluation_protocol", 1, {
                "task_id": registration.task_id,
                "criterion_version": registration.criterion_version,
                "test_suite_commitment": registration.suite_commitment,
                "base_commit": registration.base_commit,
                "statement_digest": registration.statement_digest,
                "evaluator_identity": self.identity,
            })
            unsigned = {
                **common,
                "attempt_id": attempt_id,
                "execution_receipt_digest": receipt_exec.digest,
                "isolation_attestation_digest": verification.attestation_digest,
                "evaluator_runtime_digest": self.runtime_profile.digest,
                "evaluation_protocol_digest": protocol_digest,
                "worker_identity": receipt_exec.worker_identity,
                "sandbox_policy_digest": verification.policy_digest,
            }
            signature = signatures.sign(
                seed, _SIGNATURE_DOMAIN_V2 + canonical_json(unsigned)).hex()
            receipt = OutcomeReceiptV2.from_dict(
                {**unsigned, "signature": signature})
        else:
            signature = signatures.sign(
                seed, _SIGNATURE_DOMAIN + canonical_json(common)).hex()
            receipt = OutcomeReceiptV1.from_dict(
                {**common, "signature": signature})
        self._record(receipt, evaluation_nonce, receipt_exec.digest,
                     outcome_class=outcome_class,
                     runtime_digest=self.runtime_profile.digest,
                     bootstrap_digest=bootstrap.import_receipt_digest)
        return receipt

    def verify_receipt(self, receipt: OutcomeReceiptV1 | OutcomeReceiptV2 | Mapping) -> bool:
        """Verify a receipt's signature against the trusted key registry."""
        try:
            record = _parse_receipt(receipt)
        except (ContractError, TypeError, KeyError):
            return False
        public_hex = self._trusted.get(record.signer_key_id)
        if public_hex is None:
            return False
        return verify_receipt_signature(record, public_hex)

    def public_key_record(self) -> dict[str, str]:
        """Export the public verification material; never the seed."""
        return {"key_id": self.keystore.key_id, "public_key": self.keystore.public.hex()}

    def issued_receipts(self) -> list[str]:
        return [entry["receipt_digest"] for entry in self._journal]

    def load_receipt(self, receipt_digest: str) -> OutcomeReceiptV1 | OutcomeReceiptV2:
        """Reload a persisted signed receipt by its canonical digest.

        The artifact must hash to the address it was stored under. A
        signature that verifies over a *different* evaluation proves
        nothing about this one, so a mismatch means the receipt store
        returned the wrong artifact and fails closed as journal
        corruption.
        """
        if not isinstance(receipt_digest, str) or not _DIGEST.fullmatch(receipt_digest):
            raise ContractError("receipt reference must be a lowercase SHA-256 digest")
        path = self.registry_dir / "receipts" / f"{receipt_digest}.json"
        try:
            receipt = _parse_receipt(loads_json(path.read_bytes()))
        except OSError as exc:
            raise JournalIntegrityError("receipt_missing") from exc
        except ContractError as exc:
            raise JournalIntegrityError("receipt_malformed") from exc
        if receipt.digest != receipt_digest:
            raise JournalIntegrityError("receipt_digest_mismatch")
        return receipt

    def execution_digest_for(self, receipt_digest: str) -> str | None:
        """The execution receipt digest journaled for one outcome receipt.

        The journal entry is written by this evaluator at receipt issue,
        so it binds an outcome receipt to the exact execution that
        produced it — the linkage experience-evidence verification needs.
        An entry whose persisted receipt could not be re-authenticated on
        load (missing artifact, untrusted signer, or a format that never
        recorded the linkage) is unverified and yields ``None``.
        """
        if receipt_digest not in self._verified_receipts:
            return None
        entry = self._journal_by_digest.get(receipt_digest)
        return entry["execution_digest"] if entry is not None else None

    def _record(self, receipt: OutcomeReceiptV1, nonce: str,
                execution_digest: str, *, outcome_class: str | None = None,
                runtime_digest: str | None = None,
                bootstrap_digest: str | None = None) -> None:
        entry = {
            "receipt_digest": receipt.digest,
            "receipt_id": receipt.receipt_id,
            "task_id": receipt.task_id,
            "attempt_id": getattr(receipt, "attempt_id", None),
            "evaluated_repo_digest": receipt.evaluated_repo_digest,
            "criterion_version": receipt.criterion_version,
            "outcome": receipt.outcome,
            "execution_digest": execution_digest,
            "worker_identity": getattr(receipt, "worker_identity", None),
            "signer_key_id": receipt.signer_key_id,
            "nonce": nonce,
            "issued_at": _utcnow(),
            "outcome_class": outcome_class or (
                "TASK_PASS" if receipt.outcome == "pass"
                else "TASK_FAIL" if receipt.outcome == "fail"
                else "INFRASTRUCTURE_ERROR"),
            "runtime_digest": runtime_digest,
            "bootstrap_digest": bootstrap_digest,
        }
        with open(self._journal_path, "ab") as handle:
            handle.write(canonical_json(entry) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        receipts_dir = self.registry_dir / "receipts"
        receipts_dir.mkdir(exist_ok=True)
        receipt_path = receipts_dir / f"{receipt.digest}.json"
        if not receipt_path.exists():
            fd, tmp = tempfile.mkstemp(dir=receipts_dir, prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(receipt.canonical_bytes())
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, receipt_path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        self._nonces.add(nonce)
        self._evaluated.add(
            (receipt.task_id, receipt.evaluated_repo_digest, receipt.criterion_version)
        )
        self._journal.append(entry)
        self._journal_by_digest[entry["receipt_digest"]] = entry
        # This evaluator signed the receipt and wrote the artifact, so the
        # entry it just journaled is bound to an authenticated artifact.
        self._verified_receipts.add(entry["receipt_digest"])

    def _load_state(self) -> None:
        self._journal: list[dict] = []
        if self._tasks_path.exists():
            try:
                document = json.loads(self._tasks_path.read_bytes())
            except (OSError, json.JSONDecodeError) as exc:
                raise JournalIntegrityError("task registry is unreadable") from exc
            if not isinstance(document, dict) or set(document) != {"schema_version", "tasks"}:
                raise JournalIntegrityError("task registry has an unexpected shape")
            for item in document["tasks"]:
                files = {name: bytes.fromhex(data)
                         for name, data in item["files"].items()}
                custody = item.get("custody")
                if custody is None:
                    custody = _recover_custody(item, files)
                elif custody not in ("shared", "split"):
                    raise JournalIntegrityError(
                        "task registry has an invalid custody mode")
                else:
                    # A declared mode must still agree with the
                    # commitment: editing custody in the registry cannot
                    # downgrade a split task to shared.
                    expected = _suite_commitment(
                        task_id=item["task_id"],
                        criterion_version=item["criterion_version"],
                        argv=tuple(item["argv"]),
                        files=files,
                        base_commit=item["base_commit"],
                        failure_class=item.get("failure_class"),
                        custody=custody,
                    )
                    if expected != item["suite_commitment"]:
                        raise JournalIntegrityError(
                            "task registry commitment does not match"
                            " its registration")
                task = RegisteredTask(
                    task_id=item["task_id"],
                    criterion_version=item["criterion_version"],
                    argv=tuple(item["argv"]),
                    files=files,
                    base_commit=item["base_commit"],
                    suite_commitment=item["suite_commitment"],
                    statement_digest=item.get("statement_digest"),
                    failure_class=item.get("failure_class"),
                    custody=custody,
                )
                self._tasks[task.task_id] = task
        if self._journal_path.exists():
            with open(self._journal_path, "rb") as handle:
                for position, raw in enumerate(handle):
                    try:
                        entry = json.loads(raw.rstrip(b"\n"))
                    except json.JSONDecodeError as exc:
                        raise JournalIntegrityError(f"receipt journal line {position} is corrupt") from exc
                    entry = self._validate_journal_entry(entry, position)
                    if entry["receipt_digest"] in self._journal_by_digest:
                        raise JournalIntegrityError(
                            f"receipt journal line {position} duplicates a receipt")
                    if entry["nonce"] in self._nonces:
                        raise JournalIntegrityError(
                            f"receipt journal line {position} replays a nonce")
                    self._journal.append(entry)
                    self._journal_by_digest[entry["receipt_digest"]] = entry
                    self._nonces.add(entry["nonce"])
                    self._evaluated.add(
                        (entry["task_id"], entry["evaluated_repo_digest"], entry["criterion_version"])
                    )
                    if self._bind_journal_entry(entry, position):
                        self._verified_receipts.add(entry["receipt_digest"])

    def _validate_journal_entry(self, entry: object, position: int) -> dict:
        """Reject a journal line that is not a well-formed receipt record."""
        if not isinstance(entry, dict):
            raise JournalIntegrityError(
                f"receipt journal line {position} is not an object")
        missing = sorted(_JOURNAL_REQUIRED_FIELDS - set(entry))
        if missing:
            raise JournalIntegrityError(
                f"receipt journal line {position} is missing {missing[0]}")
        for field in ("receipt_digest", "evaluated_repo_digest", "execution_digest"):
            value = entry[field]
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise JournalIntegrityError(
                    f"receipt journal line {position} has an invalid {field}")
        for field in _JOURNAL_STRING_FIELDS:
            value = entry[field]
            if not isinstance(value, str) or not value:
                raise JournalIntegrityError(
                    f"receipt journal line {position} has an invalid {field}")
        signer = entry.get("signer_key_id")
        if signer is not None and (not isinstance(signer, str) or not signer):
            raise JournalIntegrityError(
                f"receipt journal line {position} has an invalid signer_key_id")
        return entry

    def _bind_journal_entry(self, entry: dict, position: int) -> bool:
        """Bind one journal line to its persisted, signed receipt.

        Returns ``True`` only when the journaled identity and the signed
        artifact agree and the artifact authenticates under a currently
        trusted key. A missing artifact (a crash between the journal
        append and the receipt write) or a rotated-out signer is left
        unverified; it is still listed, but it can never corroborate an
        execution digest. A present-but-inconsistent artifact is
        corruption and fails closed.
        """
        path = self.registry_dir / "receipts" / f"{entry['receipt_digest']}.json"
        try:
            artifact = _parse_receipt(loads_json(path.read_bytes()))
        except FileNotFoundError:
            return False
        except (OSError, ContractError) as exc:
            raise JournalIntegrityError(
                f"receipt journal line {position} has an unreadable receipt") from exc
        if artifact.digest != entry["receipt_digest"]:
            raise JournalIntegrityError("receipt_digest_mismatch")
        for field in (
            "receipt_id", "task_id", "evaluated_repo_digest",
            "criterion_version", "outcome",
        ):
            if getattr(artifact, field) != entry[field]:
                raise JournalIntegrityError("receipt_journal_mismatch")
        signer = entry.get("signer_key_id")
        if signer is not None and signer != artifact.signer_key_id:
            raise JournalIntegrityError("receipt_journal_mismatch")
        attempt = getattr(artifact, "attempt_id", None)
        if attempt is not None and entry.get("attempt_id") not in (None, attempt):
            raise JournalIntegrityError("receipt_journal_mismatch")
        execution = getattr(artifact, "execution_receipt_digest", None)
        if execution is not None and execution != entry["execution_digest"]:
            raise JournalIntegrityError("receipt_journal_mismatch")
        worker = getattr(artifact, "worker_identity", None)
        if worker is not None and entry.get("worker_identity") not in (None, worker):
            raise JournalIntegrityError("receipt_journal_mismatch")
        public_hex = self._trusted.get(artifact.signer_key_id)
        if public_hex is None:
            return False
        if not verify_receipt_signature(artifact, public_hex):
            raise JournalIntegrityError(
                f"receipt journal line {position} has an unauthentic receipt")
        return True

    def _persist_tasks(self) -> None:
        document = {
            "schema_version": 1,
            "tasks": [
                {
                    "task_id": task.task_id,
                    "criterion_version": task.criterion_version,
                    "argv": list(task.argv),
                    "files": {name: data.hex() for name, data in sorted(task.files.items())},
                    "base_commit": task.base_commit,
                    "suite_commitment": task.suite_commitment,
                    "statement_digest": task.statement_digest,
                    "failure_class": task.failure_class,
                    "custody": task.custody,
                }
                for task in sorted(self._tasks.values(), key=lambda t: t.task_id)
            ],
        }
        payload = canonical_json(document)
        fd, tmp = tempfile.mkstemp(dir=self.registry_dir, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._tasks_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def verify_receipt_signature(
    receipt: OutcomeReceiptV1 | OutcomeReceiptV2 | Mapping,
    public_key_hex: str,
) -> bool:
    """Offline receipt check: signature over canonical payload, public key only."""
    try:
        record = _parse_receipt(receipt)
    except (ContractError, TypeError, KeyError):
        return False
    if not isinstance(public_key_hex, str) or len(public_key_hex) != 64:
        return False
    try:
        public = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(record.signature)
    except ValueError:
        return False
    unsigned = record.to_dict()
    unsigned.pop("signature")
    return signatures.verify(
        signature, _receipt_domain(record) + canonical_json(unsigned), public)


@dataclass(frozen=True)
class ExpectedProtocol:
    """Precommitted evaluation protocol a receipt must bind to (SIS-311).

    Any field set to a value must match the receipt exactly; fields left as
    ``None`` are unconstrained. This is how promotion binds evidence to the
    task identity, criterion version, suite commitment, repository, and
    evaluator identity it precommitted to — never inferred from the receipt.
    """

    task_id: str | None = None
    criterion_version: str | None = None
    test_suite_commitment: str | None = None
    evaluated_repo_digest: str | None = None
    evaluator_identity: str | None = None


def verify_and_resolve_receipt(
    digest: str,
    resolver,
    *,
    trusted_keys: Mapping[str, str],
    revoked_keys: frozenset[str] | set[str] = frozenset(),
    protocol: ExpectedProtocol | None = None,
) -> OutcomeReceiptV1:
    """Load a receipt through an untrusted resolver and verify its authority.

    The resolver is transport only — this function re-derives the canonical
    digest, re-verifies the Ed25519 signature under the receipt domain, and
    binds the receipt to the precommitted evaluation protocol. Every failure
    raises ``EvaluationRejected`` with a stable reason code; nothing the
    resolver returns is ever trusted on its own.
    """
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise EvaluationRejected("receipt_digest_invalid", repr(digest)[:80])
    try:
        raw = resolver(digest)
    except EvaluationRejected:
        raise
    except (RuntimeError, ContractError, OSError) as exc:
        raise EvaluationRejected("receipt_unresolvable", digest) from exc
    try:
        receipt = _parse_receipt(raw)
    except (ContractError, TypeError, KeyError) as exc:
        raise EvaluationRejected("receipt_malformed", digest) from exc
    if receipt.digest != digest:
        raise EvaluationRejected("receipt_digest_mismatch", digest)
    if receipt.signer_key_id in revoked_keys:
        raise EvaluationRejected("signer_revoked", receipt.signer_key_id)
    public_hex = trusted_keys.get(receipt.signer_key_id)
    if public_hex is None:
        raise EvaluationRejected("untrusted_signer", receipt.signer_key_id)
    if not verify_receipt_signature(receipt, public_hex):
        raise EvaluationRejected("receipt_signature_invalid", digest)
    if protocol is not None:
        for field in (
            "task_id", "criterion_version", "test_suite_commitment",
            "evaluated_repo_digest", "evaluator_identity",
        ):
            expected = getattr(protocol, field)
            if expected is not None and getattr(receipt, field) != expected:
                raise EvaluationRejected(
                    "protocol_binding_mismatch", f"{field}: expected {expected}"
                )
    return receipt
