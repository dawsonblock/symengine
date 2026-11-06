"""Governed procedure lifecycle: draft→candidate→evaluated→qualified→suspended→retired (SIS3-011).

Every transition produces a signed ``PromotionDecisionV2`` that requires
operator authority (role gate + operator signature or token digest) and, for
the ``evaluated``/``qualified`` edges, verified outcome receipts plus an
evaluator Ed25519 signature over the decision payload.

Persistence is a single transactional authority store
(:class:`sis.v3.authority_db.AuthorityDB`): the verified decision and the
materialized revision commit in one SQLite transaction — they become visible
together or not at all. There is no journaled-then-materialized gap, no
recovery replay that can mint state, and no second writable catalog. Chain
heads are re-checked inside the write transaction, so a stale controller or
concurrent writer is rejected atomically.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import threading
from collections.abc import Callable, Mapping
from dataclasses import replace

from . import signatures
from .authority_db import AuthorityDB, AuthorityError
from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    ProcedureRecordV1,
    PromotionDecisionV1,
    PromotionDecisionV2,
    RevocationV1,
    canonical_digest,
    canonical_json,
)
from .policy import require_permission
from .verifier import (
    EvaluationRejected,
    ExpectedProtocol,
    verify_and_resolve_receipt,
)

_SIGNATURE_DOMAIN = b"sis-v3:promotion_decision:1\0"
_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"candidate", "retired"}),
    "candidate": frozenset({"evaluated", "retired"}),
    "evaluated": frozenset({"qualified", "suspended", "retired"}),
    "qualified": frozenset({"suspended", "retired"}),
    "suspended": frozenset({"qualified", "retired"}),
    "retired": frozenset(),
}


class PromotionRejected(RuntimeError):
    """A transition lacks authority, evidence, or a legal status edge."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def verify_decision_v2(
    decision: PromotionDecisionV2,
    statuses: dict[str, str],
    qualified: set[str],
    *,
    trusted: Mapping[str, str],
    operator_keys: Mapping[str, str],
    token_digest: str | None,
) -> list[str]:
    """Re-verify one V2 decision against replayed state.

    Checks evaluator signature, operator authorization, transition legality,
    status monotonicity and qualified-head arithmetic — the same checks the
    controller ran live, recomputable over committed rows by the store or the
    migration tool. ``statuses``/``qualified`` are mutated to include the
    decision's effect.
    """
    problems: list[str] = []
    base = decision.to_dict()
    base.pop("evaluator_signature")
    base.pop("operator_authorization")
    body = _SIGNATURE_DOMAIN + canonical_json(base)
    if decision.new_status in {"qualified", "evaluated"} and \
            decision.evaluator_signature == "not-required":
        problems.append("evaluator_signature_required")
    elif decision.evaluator_signature != "not-required":
        try:
            key_id, sig_hex = decision.evaluator_signature.split(":", 1)
            if key_id not in trusted or not signatures.verify(
                bytes.fromhex(sig_hex), body, bytes.fromhex(trusted[key_id])
            ):
                problems.append("evaluator_signature_invalid")
        except (ValueError, TypeError):
            problems.append("evaluator_signature_malformed")
    auth = decision.operator_authorization
    if auth.startswith("ed25519:"):
        try:
            _, key_id, sig_hex = auth.split(":", 2)
            signed = _SIGNATURE_DOMAIN + canonical_json(
                {**base, "evaluator_signature": decision.evaluator_signature})
            if key_id not in operator_keys or not signatures.verify(
                bytes.fromhex(sig_hex), signed, bytes.fromhex(operator_keys[key_id])
            ):
                problems.append("operator_signature_invalid")
        except (ValueError, TypeError):
            problems.append("operator_authorization_malformed")
    elif auth != f"operator_token_sha256:{token_digest}":
        problems.append("operator_authorization_mismatch")
    if decision.prior_status not in _TRANSITIONS or \
            decision.new_status not in _TRANSITIONS[decision.prior_status]:
        problems.append("illegal_transition")
    if statuses.get(decision.candidate_digest, decision.prior_status) != decision.prior_status:
        problems.append("nonmonotonic_status")
    expected_old = canonical_digest(
        "qualified_catalog", 1, {"head": sorted(qualified)})
    if decision.old_qualified_head not in {expected_old, None}:
        problems.append("old_head_mismatch")
    if decision.prior_status == "qualified":
        qualified.discard(decision.candidate_digest)
    if decision.new_status == "qualified":
        qualified.add(decision.new_record_digest)
    expected_new = canonical_digest(
        "qualified_catalog", 1, {"head": sorted(qualified)})
    if decision.new_qualified_head is not None and \
            decision.new_qualified_head != expected_new:
        problems.append("new_head_mismatch")
    statuses[decision.new_record_digest] = decision.new_status
    statuses.pop(decision.candidate_digest, None)
    return problems


class PromotionController:
    """Signed-decision authority over an ``AuthorityDB`` transactional store."""

    def __init__(
        self,
        store: AuthorityDB,
        log_dir=None,
        *,
        operator_token_digest: str | None,
        trusted_evaluator_keys: Mapping[str, str],
        receipt_resolver: Callable[[str], OutcomeReceiptV1] | None = None,
        min_pass_receipts: int = 1,
        min_distinct_repos: int = 1,
        expected_protocol: ExpectedProtocol | None = None,
        revoked_evaluator_keys: frozenset[str] | set[str] = frozenset(),
        policy_version: str = "promotion-policy-v1",
        trusted_operator_keys: Mapping[str, str] | None = None,
    ) -> None:
        if log_dir is not None:
            raise ContractError(
                "legacy JSONL decision journals are no longer a write target; "
                "pass an AuthorityDB and use tools/migrate_authority.py to "
                "import existing journals"
            )
        if not isinstance(store, AuthorityDB):
            raise ContractError(
                "PromotionController requires an AuthorityDB authority store; "
                "bare ProcedureStore data is intake, never authority"
            )
        if operator_token_digest is not None and not (
            isinstance(operator_token_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", operator_token_digest)
        ):
            raise ContractError("operator_token_digest must be a SHA-256 hex digest")
        if type(min_pass_receipts) is not int or min_pass_receipts < 1:
            raise ContractError("min_pass_receipts must be positive")
        if type(min_distinct_repos) is not int or min_distinct_repos < 1:
            raise ContractError("min_distinct_repos must be positive")
        if expected_protocol is not None and not isinstance(expected_protocol, ExpectedProtocol):
            raise ContractError("expected_protocol must be an ExpectedProtocol")
        self.store = store
        self._token_digest = operator_token_digest
        self._operator_keys = dict(trusted_operator_keys or {})
        self._trusted = dict(trusted_evaluator_keys)
        self._resolve_receipt = receipt_resolver
        self._min_receipts = min_pass_receipts
        self._min_repos = min_distinct_repos
        self._protocol = expected_protocol
        self._revoked_eval_keys = set(revoked_evaluator_keys)
        self.policy_version = policy_version
        self._prior: str | None = None
        self._decisions: list[PromotionDecisionV1 | PromotionDecisionV2] = []
        self._projected: dict[str, str] = {}  # record_digest -> decided status
        self._lock = threading.Lock()
        self.store._bind_authority(self)
        self._load()

    def transition(
        self,
        procedure_id: str,
        new_status: str,
        *,
        actor_role: str,
        actor_identity: str,
        operator_token: str | None = None,
        receipt_digests: tuple[str, ...] = (),
        evaluator_signer: Callable[[bytes], tuple[str, str]] | None = None,
        operator_signer: Callable[[bytes], tuple[str, str]] | None = None,
        rollback_ref: str | None = None,
        expected_old_head: str | None = None,
    ) -> PromotionDecisionV2:
        """Move a procedure along a legal edge under full authority.

        The complete post-state — new record digest and expected qualified
        head — is computed *before* either signature, so both signatures bind
        the exact committed outcome. The decision and its materialized
        revision commit in one database transaction; a stale head or forged
        post-state aborts the whole transaction.
        """
        require_permission(actor_role, "promotion:approve")
        with self._lock:
            self._check_fresh_authority()
            record = self.store.get(procedure_id)
            if new_status not in _TRANSITIONS.get(record.status, frozenset()):
                raise PromotionRejected(
                    "illegal_transition", f"{record.status} -> {new_status}"
                )
            verified_receipts = self._verify_receipts(receipt_digests)
            if new_status == "qualified":
                # Qualification and requalification (suspended -> qualified)
                # both run the full evidence check — no transition exception.
                self._require_qualification_evidence(verified_receipts)
            if new_status == "evaluated" and not verified_receipts:
                raise PromotionRejected(
                    "missing_receipts", "evaluation requires verified receipts"
                )

            old_head = self.store.qualified_head_digest()
            if expected_old_head is not None and expected_old_head != old_head:
                raise PromotionRejected(
                    "stale_qualified_head",
                    f"expected {expected_old_head}, actual {old_head}",
                )
            next_revision = replace(
                record, revision=record.revision + 1, status=new_status
            )
            expected_new_head = self._simulate_head(record, next_revision)
            unsigned = {
                "schema_version": 1,
                "decision_id": "dec-" + secrets.token_hex(12),
                "candidate_digest": record.digest,
                "new_record_digest": next_revision.digest,
                "evaluation_protocol_digest": canonical_digest(
                    "evaluation_protocol", 1,
                    {"policy_version": self.policy_version,
                     "min_pass_receipts": self._min_receipts},
                ),
                "receipt_refs": list(dict.fromkeys(r.digest for r in verified_receipts)) or ["0" * 64],
                "actor_identity": actor_identity,
                "approved": True,
                "policy_version": self.policy_version,
                "prior_status": record.status,
                "new_status": new_status,
                "old_qualified_head": old_head,
                "new_qualified_head": expected_new_head,
                "rollback_ref": rollback_ref,
            }
            body = _SIGNATURE_DOMAIN + canonical_json(unsigned)
            if new_status in {"qualified", "evaluated"}:
                if evaluator_signer is None:
                    raise PromotionRejected("evaluator_signature_required")
                key_id, sig_hex = evaluator_signer(body)
                if key_id not in self._trusted or not signatures.verify(
                    bytes.fromhex(sig_hex), body,
                    bytes.fromhex(self._trusted[key_id]),
                ):
                    raise PromotionRejected("evaluator_signature_invalid")
                unsigned["evaluator_signature"] = f"{key_id}:{sig_hex}"
            else:
                unsigned["evaluator_signature"] = "not-required"
            unsigned["operator_authorization"] = self._authorize_operator(
                unsigned, operator_signer, operator_token
            )

            decision = PromotionDecisionV2.from_dict(unsigned)
            try:
                self.store.commit_transition(
                    decision=decision,
                    record=next_revision,
                    expected_prior_decision_digest=self._prior,
                    expected_new_qualified_head=expected_new_head,
                    receipts=verified_receipts,
                    authority=self,
                )
            except AuthorityError as exc:
                raise PromotionRejected("authority_commit_failed", str(exc)) from exc
            self._prior = decision.digest
            self._decisions.append(decision)
            self._projected.pop(decision.candidate_digest, None)
            self._projected[decision.new_record_digest] = decision.new_status
            actual_head = self.store.qualified_head_digest()
            if actual_head != expected_new_head:
                raise PromotionRejected(
                    "qualified_head_divergence",
                    f"declared {expected_new_head}, actual {actual_head}",
                )
            return decision

    def _check_fresh_authority(self) -> None:
        """Prevent writes from a stale in-memory controller or damaged state.

        The committed chain head is re-read and fully re-verified before every
        transition; the commit transaction then rechecks the head under the
        write lock, so a concurrent commit can never slip through this gap.
        """
        if self.store.decision_head() != self._prior:
            raise PromotionRejected("stale_controller")
        result = self.verify()
        if not result["ok"]:
            raise PromotionRejected("authority_state_invalid", ",".join(result["problems"][:5]))

    def qualified_head(self) -> str:
        return self.store.qualified_head_digest()

    def decisions(self) -> list[PromotionDecisionV1]:
        return list(self._decisions)

    def projected_statuses(self) -> dict[str, str]:
        """The decision-backed status map — the catalog's authority view."""
        return dict(self._projected)

    def revoke(
        self,
        revocation: RevocationV1,
        *,
        actor_role: str,
        actor_identity: str,
        operator_token: str | None = None,
        verifier=None,
    ) -> list[str]:
        """Commit a signed revocation and enforce it (PR-04).

        The mandatory ``verifier`` (``RevocationAuthority.verify``) runs
        inside the commit transaction — unsigned or forged revocations
        never land. Effects by kind:

        - ``record``/``grant`` — committed row is honored by the serving
          boundary on the next request (denylist / grant stop).
        - ``receipt`` — additionally cascades: every qualified record
          citing the revoked evidence is suspended via a real signed
          suspension decision, and grants citing it stop permitting.
        - ``signer`` — the evaluator key id stops being trusted for new
          decisions immediately.

        Returns the suspension decision ids produced by the cascade.
        """
        require_permission(actor_role, "promotion:approve")
        if verifier is None or not callable(verifier):
            raise ContractError("revocation_verifier_required")
        self.store.commit_revocation(
            revocation=revocation, authority=self, verifier=verifier)
        suspended: list[str] = []
        if revocation.kind == "receipt":
            from .catalog import Catalog
            suspended = Catalog(self.store).cascade_suspend(
                revocation.target_digest,
                lambda pid: self.transition(
                    pid, "suspended", actor_role=actor_role,
                    actor_identity=actor_identity,
                    operator_token=operator_token,
                ).decision_id,
            )
        elif revocation.kind == "signer":
            self._revoked_eval_keys.add(revocation.target_id)
        return suspended

    def verify(self, *, check_projection: bool = True) -> dict:
        """Replay committed decisions: signatures, chain continuity, projection."""
        structural = self.store.verify()
        problems: list[str] = list(structural["problems"])
        if problems:
            # Structural corruption (digests, chain links, undecodable rows,
            # unauthorized revisions) means nothing downstream can be trusted;
            # replaying parsed decisions over it would itself be unsafe.
            return {"ok": False, "entries": structural.get("entries", 0),
                    "legacy_v1": 0, "head": structural.get("head"),
                    "problems": problems}
        statuses: dict[str, str] = {}
        qualified: set[str] = set()
        count = 0
        legacy = 0
        head: str | None = None
        for decision in self.store.decisions():
            count += 1
            head = decision.digest
            if isinstance(decision, PromotionDecisionV1):
                legacy += 1  # legacy entries: structural checks only
            else:
                problems.extend(
                    p + f"_at_{count - 1}" for p in verify_decision_v2(
                        decision, statuses, qualified,
                        trusted=self._trusted,
                        operator_keys=self._operator_keys,
                        token_digest=self._token_digest,
                    )
                )
        if not problems and check_projection:
            problems.extend(self._projection_drift(qualified, statuses))
        return {"ok": not problems, "entries": count, "legacy_v1": legacy,
                "head": head, "problems": problems}

    def _projection_drift(self, qualified, statuses) -> list[str]:
        """Report committed catalog state the decisions cannot account for."""
        problems: list[str] = []
        projected_q = {r.digest for r in self.store.by_status("qualified")}
        if projected_q != qualified:
            problems.append("qualified_projection_drift")
        # Every committed decision must have materialized its new record —
        # atomic commits make this a tamper/corruption check, not crash repair.
        latest = {r.digest: r.status for r in self.store.all_latest()}
        for digest, status in statuses.items():
            if latest.get(digest) != status:
                problems.append("decision_materialization_drift")
                break
        return problems

    def _authorize_operator(
        self,
        unsigned: dict,
        operator_signer: Callable[[bytes], tuple[str, str]] | None,
        operator_token: str | None,
    ) -> str:
        """Authorize via operator Ed25519 signature, else shared token digest."""
        payload = _SIGNATURE_DOMAIN + canonical_json(unsigned)
        if operator_signer is not None:
            key_id, sig_hex = operator_signer(payload)
            trusted = self._operator_keys.get(key_id)
            if trusted is None or not signatures.verify(
                bytes.fromhex(sig_hex), payload, bytes.fromhex(trusted)
            ):
                raise PromotionRejected("operator_signature_invalid")
            return f"ed25519:{key_id}:{sig_hex}"
        if operator_token is not None and self._token_digest is not None:
            if hashlib.sha256(operator_token.encode()).hexdigest() == self._token_digest:
                return "operator_token_sha256:" + self._token_digest
        raise PromotionRejected("operator_authorization_failed")

    def _verify_receipts(self, digests: tuple[str, ...]) -> list[OutcomeReceiptV1]:
        """Resolve then verify every referenced receipt; resolver is transport."""
        receipts = []
        for digest in dict.fromkeys(digests):
            if self._resolve_receipt is None:
                raise PromotionRejected("no_receipt_resolver_configured")
            try:
                receipts.append(verify_and_resolve_receipt(
                    digest,
                    self._resolve_receipt,
                    trusted_keys=self._trusted,
                    revoked_keys=self._revoked_eval_keys,
                    protocol=self._protocol,
                ))
            except EvaluationRejected as exc:
                raise PromotionRejected(exc.reason, str(exc)) from exc
        return receipts

    def _simulate_head(
        self, record: ProcedureRecordV1, next_revision: ProcedureRecordV1
    ) -> str:
        """Project the qualified head as if ``next_revision`` were applied."""
        digests = {
            r.digest for r in self.store.by_status("qualified")
            if r.procedure_id != record.procedure_id
        }
        if next_revision.status == "qualified":
            digests.add(next_revision.digest)
        return canonical_digest("qualified_catalog", 1, {"head": sorted(digests)})

    def _require_qualification_evidence(self, receipts: list[OutcomeReceiptV1]) -> None:
        """Count independent evidence units — never raw outcome strings.

        Cloned receipts collapse to the same (task, repo) unit and cannot
        inflate the count. ``min_distinct_repos`` counts distinct evaluated
        *tree* digests — a proxy for repository disjointness, not proof of
        it: two different submissions to the same repository still digest
        differently. Genuine repository disjointness must be established
        through evaluator task-registration lineage, outside this gate.
        """
        pass_receipts = [r for r in receipts if r.outcome == "pass"]
        units = {(r.task_id, r.evaluated_repo_digest) for r in pass_receipts}
        repos = {r.evaluated_repo_digest for r in pass_receipts}
        if len(units) < self._min_receipts or len(repos) < self._min_repos:
            raise PromotionRejected(
                "insufficient_evidence",
                f"need {self._min_receipts} distinct pass task(s) across "
                f"{self._min_repos} repositories, have {len(units)}/{len(repos)}",
            )

    def _load(self) -> None:
        """Populate controller state from committed decisions; fail closed."""
        report = self.verify()
        if not report["ok"]:
            raise PromotionRejected(
                "authority_state_invalid", ",".join(report["problems"][:8])
            )
        for decision in self.store.decisions():
            self._decisions.append(decision)
            if isinstance(decision, PromotionDecisionV2):
                self._projected.pop(decision.candidate_digest, None)
                self._projected[decision.new_record_digest] = decision.new_status
            self._prior = decision.digest


def operator_token_digest(token: str) -> str:
    """Derive the configured operator token digest (never log the token)."""
    if not isinstance(token, str) or len(token) < 16:
        raise ContractError("operator token must be at least 16 characters")
    return hashlib.sha256(token.encode()).hexdigest()
