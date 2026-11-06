"""Candidate-specific evaluation certificates and qualification policy.

Revision 4 could bind a receipt to a candidate, but it could not prove
that the candidate was actually delivered during the evaluation, and a
campaign that reported ``conforms=false`` still qualified candidates.
This module closes both gaps:

- :class:`EvaluationCertificateV1` is an evaluator-signed certificate
  binding the candidate artifact, the *delivery* of that artifact, the
  baseline/agent configuration, the preregistered protocol and task set,
  per-task receipts and delivery attestations, the statistical result,
  negative transfer, protocol conformance, the qualification policy and
  an explicit evidence class.
- :class:`QualificationPolicy` states exactly what may authorize
  production promotion. Only ``confirmatory`` evidence that meets the
  preregistered sample size, protocol conformance and statistical bar
  can pass.
- :class:`QualificationValidator` re-derives every mandatory check from
  the signed artifacts. A forged ``conforms=true`` flag is not enough:
  the executed task count, receipt set, protocol sample size and
  delivery attestations are recomputed.

Exploratory and demonstration runs remain first-class evidence. They are
stored and reported; they simply cannot create production-qualified
guidance.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Mapping, Sequence

from . import signatures
from .contracts import (
    CandidateDeliveryAttestationV1,
    CandidateV1,
    ContractError,
    EvaluationCertificateV1,
    canonical_digest,
    canonical_json,
)

EVIDENCE_CLASSES = ("exploratory", "demonstration", "confirmatory", "invalid")
PRODUCTION_EVIDENCE_CLASS = "confirmatory"
CERTIFICATE_DOMAIN = b"sis-v3:evaluation_certificate:1\0"
DELIVERY_DOMAIN = b"sis-v3:candidate_delivery:1\0"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CertificateError(RuntimeError):
    """A certificate, delivery attestation or policy is unusable."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _parse_instant(value: str) -> datetime:
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _digest(value, name):
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise CertificateError("digest_invalid", name)


def delivery_digest(
    *, candidate_digest: str, content_digest: str, task_id: str,
    guidance_digest: str,
) -> str:
    """Digest of one exact candidate delivery for one task."""
    return canonical_digest("candidate_delivery", 1, {
        "candidate_digest": candidate_digest,
        "content_digest": content_digest,
        "task_id": task_id,
        "guidance_digest": guidance_digest,
    })


def aggregate_delivery_digest(entries: Sequence[Mapping]) -> str:
    """Digest over the per-task delivery digests of one evaluation."""
    return canonical_digest("candidate_delivery_set", 1, {
        "deliveries": [
            {"task_id": item["task_id"],
             "delivery_digest": item["delivery_digest"]}
            for item in sorted(entries, key=lambda i: i["task_id"])
        ],
    })


def certificate_body(certificate: EvaluationCertificateV1 | Mapping) -> bytes:
    body = certificate.to_dict() if isinstance(
        certificate, EvaluationCertificateV1) else dict(certificate)
    body.pop("signature", None)
    return CERTIFICATE_DOMAIN + canonical_json(body)


def delivery_body(attestation: CandidateDeliveryAttestationV1 | Mapping) -> bytes:
    body = attestation.to_dict() if isinstance(
        attestation, CandidateDeliveryAttestationV1) else dict(attestation)
    body.pop("signature", None)
    return DELIVERY_DOMAIN + canonical_json(body)


def sign_certificate(seed: bytes, **fields) -> EvaluationCertificateV1:
    fields.setdefault("schema_version", 1)
    unsigned = {k: v for k, v in fields.items() if k != "signature"}
    signature = signatures.sign(seed, certificate_body(unsigned)).hex()
    return EvaluationCertificateV1.from_dict(
        {**unsigned, "signature": signature})


def verify_certificate(
    certificate: EvaluationCertificateV1, public_hex: str
) -> bool:
    try:
        return signatures.verify(
            bytes.fromhex(certificate.signature),
            certificate_body(certificate), bytes.fromhex(public_hex))
    except (ValueError, TypeError):
        return False


def sign_delivery(
    seed: bytes, **fields
) -> CandidateDeliveryAttestationV1:
    fields.setdefault("schema_version", 1)
    unsigned = {k: v for k, v in fields.items() if k != "signature"}
    signature = signatures.sign(seed, delivery_body(unsigned)).hex()
    return CandidateDeliveryAttestationV1.from_dict(
        {**unsigned, "signature": signature})


def verify_delivery(
    attestation: CandidateDeliveryAttestationV1, public_hex: str
) -> bool:
    try:
        return signatures.verify(
            bytes.fromhex(attestation.signature),
            delivery_body(attestation), bytes.fromhex(public_hex))
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class QualificationPolicy:
    """The explicit bar for production qualification.

    ``required_evidence_class`` must be ``confirmatory`` for production.
    ``min_sample_size`` is an absolute floor; the preregistered protocol
    may require more, and the validator enforces both.
    """

    policy_version: str
    primary_metric: str
    min_sample_size: int
    required_protocol_digest: str | None = None
    required_preregistration_digest: str | None = None
    required_evidence_class: str = PRODUCTION_EVIDENCE_CLASS
    partition: str = "holdout"
    confidence_milli: int = 950
    min_effect_milli: int = 1
    require_positive_interval: bool = True
    max_negative_transfer_rate_milli: int = 0
    max_regressions: int = 0
    require_delivery_attestation: bool = True
    authorized_repository_digests: tuple[str, ...] = ()
    authorized_task_ids: tuple[str, ...] = ()
    require_protocol_conformance: bool = True

    def __post_init__(self) -> None:
        if self.required_evidence_class not in EVIDENCE_CLASSES:
            raise CertificateError("policy_evidence_class_invalid")
        if self.partition not in {"development", "holdout", "monitoring"}:
            raise CertificateError("policy_partition_invalid")
        if type(self.min_sample_size) is not int or self.min_sample_size < 1:
            raise CertificateError("policy_min_sample_size_invalid")
        if not (0 <= self.confidence_milli <= 1000):
            raise CertificateError("policy_confidence_invalid")
        if type(self.min_effect_milli) is not int:
            raise CertificateError("policy_min_effect_invalid")
        if not (0 <= self.max_negative_transfer_rate_milli <= 1000):
            raise CertificateError("policy_negative_transfer_invalid")
        if type(self.max_regressions) is not int or self.max_regressions < 0:
            raise CertificateError("policy_max_regressions_invalid")
        for name in ("required_protocol_digest",
                     "required_preregistration_digest"):
            value = getattr(self, name)
            if value is not None and not (
                    isinstance(value, str) and _HEX.fullmatch(value)):
                raise CertificateError("policy_digest_invalid", name)
        for value in self.authorized_repository_digests:
            _digest(value, "authorized_repository_digests[]")
        for value in self.authorized_task_ids:
            if not isinstance(value, str) or not value:
                raise CertificateError("policy_task_id_invalid")

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "policy_version": self.policy_version,
            "primary_metric": self.primary_metric,
            "min_sample_size": self.min_sample_size,
            "required_protocol_digest": self.required_protocol_digest,
            "required_preregistration_digest":
                self.required_preregistration_digest,
            "required_evidence_class": self.required_evidence_class,
            "partition": self.partition,
            "confidence_milli": self.confidence_milli,
            "min_effect_milli": self.min_effect_milli,
            "require_positive_interval": self.require_positive_interval,
            "max_negative_transfer_rate_milli":
                self.max_negative_transfer_rate_milli,
            "max_regressions": self.max_regressions,
            "require_delivery_attestation": self.require_delivery_attestation,
            "authorized_repository_digests":
                list(self.authorized_repository_digests),
            "authorized_task_ids": list(self.authorized_task_ids),
            "require_protocol_conformance": self.require_protocol_conformance,
        }

    @property
    def digest(self) -> str:
        return canonical_digest("qualification_policy", 1, self.to_dict())


class ProtocolRegistry:
    """Trusted, preregistered protocol documents indexed by digest."""

    def __init__(self) -> None:
        self._by_digest: dict[str, dict] = {}

    def register(self, protocol: Mapping) -> str:
        digest = protocol.get("protocol_digest")
        if not (isinstance(digest, str) and _HEX.fullmatch(digest)):
            raise CertificateError("protocol_digest_invalid")
        body = {k: v for k, v in protocol.items() if k != "protocol_digest"}
        expected = canonical_digest("eval_protocol", 1, _normalize(body))
        if expected != digest:
            raise CertificateError("protocol_digest_mismatch")
        existing = self._by_digest.get(digest)
        if existing is not None and existing != dict(protocol):
            raise CertificateError("protocol_digest_alias_conflict")
        self._by_digest[digest] = dict(protocol)
        return digest

    def resolve(self, digest: str) -> dict | None:
        return self._by_digest.get(digest)

    def __len__(self) -> int:
        return len(self._by_digest)


def _normalize(value):
    """Normalize floats the same way ``governed_eval.preregister`` does."""
    import json
    return json.loads(json.dumps(value, sort_keys=True),
                      parse_float=lambda v: f"float:{v}")


class EvaluationCertificateAuthority:
    """Issue and verify evaluator-signed certificates."""

    def __init__(self, *, trusted_evaluator_keys: dict[str, str]) -> None:
        if not trusted_evaluator_keys:
            raise CertificateError("trusted_evaluator_keys_required")
        for key_id, public_hex in trusted_evaluator_keys.items():
            if not (isinstance(public_hex, str)
                    and _SHA256.fullmatch(public_hex)):
                raise CertificateError("evaluator_public_key_invalid")
        self._keys = dict(trusted_evaluator_keys)

    def issue(self, seed: bytes, *, signer_key_id: str, **fields):
        if signer_key_id not in self._keys:
            raise CertificateError("signer_key_not_trusted")
        certificate = sign_certificate(
            seed, signer_key_id=signer_key_id, **fields)
        if not self.verify(certificate):
            raise CertificateError("issued_certificate_did_not_verify")
        return certificate

    def verify(self, certificate: EvaluationCertificateV1) -> bool:
        public_hex = self._keys.get(certificate.signer_key_id)
        return bool(public_hex and verify_certificate(certificate, public_hex))

    def resolve(self, certificate_digest: str,
                resolver: Callable[[str], EvaluationCertificateV1]) -> EvaluationCertificateV1:
        certificate = resolver(certificate_digest)
        if certificate.digest != certificate_digest:
            raise CertificateError("certificate_digest_mismatch")
        if not self.verify(certificate):
            raise CertificateError("certificate_signature_invalid")
        return certificate


class DeliveryAttestationAuthority:
    """Issue and verify harness-signed candidate-delivery attestations."""

    def __init__(self, *, trusted_harness_keys: dict[str, str]) -> None:
        if not trusted_harness_keys:
            raise CertificateError("trusted_harness_keys_required")
        for key_id, public_hex in trusted_harness_keys.items():
            if not (isinstance(public_hex, str)
                    and _SHA256.fullmatch(public_hex)):
                raise CertificateError("harness_public_key_invalid")
        self._keys = dict(trusted_harness_keys)

    def issue(self, seed: bytes, *, signer_key_id: str, **fields):
        if signer_key_id not in self._keys:
            raise CertificateError("signer_key_not_trusted")
        attestation = sign_delivery(
            seed, signer_key_id=signer_key_id, **fields)
        if not self.verify(attestation):
            raise CertificateError("issued_attestation_did_not_verify")
        return attestation

    def verify(self, attestation: CandidateDeliveryAttestationV1) -> bool:
        public_hex = self._keys.get(attestation.signer_key_id)
        return bool(public_hex and verify_delivery(attestation, public_hex))

    def resolve(self, delivery_digest_value: str,
                resolver: Callable[[str], CandidateDeliveryAttestationV1]
                ) -> CandidateDeliveryAttestationV1:
        attestation = resolver(delivery_digest_value)
        if attestation.delivery_digest != delivery_digest_value:
            raise CertificateError("delivery_digest_mismatch")
        if not self.verify(attestation):
            raise CertificateError("delivery_signature_invalid")
        return attestation


@dataclass(frozen=True)
class QualificationValidation:
    ok: bool
    failures: tuple[str, ...]
    checks: Mapping[str, bool] = field(default_factory=dict)

    def require_ok(self) -> "QualificationValidation":
        if not self.ok:
            raise CertificateError(
                "qualification_rejected", ",".join(self.failures))
        return self

    def as_dict(self) -> dict:
        return {"ok": self.ok, "failures": list(self.failures),
                "checks": dict(self.checks)}


class QualificationValidator:
    """Re-derive every mandatory qualification check from signed data."""

    def __init__(
        self,
        policy: QualificationPolicy,
        *,
        certificate_authority: EvaluationCertificateAuthority,
        delivery_authority: DeliveryAttestationAuthority | None,
        protocol_registry: ProtocolRegistry,
        receipt_resolver: Callable[[str], object] | None = None,
        delivery_resolver: Callable[
            [str], CandidateDeliveryAttestationV1] | None = None,
        revoked_certificates=frozenset(),
        certificate_status: Callable[[str], str] | None = None,
        now: Callable[[], str] = _utcnow,
    ) -> None:
        self.policy = policy
        self._certificates = certificate_authority
        self._deliveries = delivery_authority
        self._protocols = protocol_registry
        self._receipts = receipt_resolver
        self._delivery_resolver = delivery_resolver
        if policy.required_evidence_class == PRODUCTION_EVIDENCE_CLASS \
                and receipt_resolver is None:
            raise CertificateError("receipt_resolver_required")
        self._revoked = frozenset(revoked_certificates)
        self._status = certificate_status
        self._now = now

    def validate(
        self,
        certificate: EvaluationCertificateV1,
        candidate: CandidateV1,
    ) -> QualificationValidation:
        failures: list[str] = []
        checks: dict[str, bool] = {}

        def check(name: str, condition: bool) -> None:
            checks[name] = bool(condition)
            if not condition:
                failures.append(name)

        check("certificate_signature",
              self._certificates.verify(certificate))
        check("evidence_class_confirmatory",
              certificate.evidence_class == self.policy.required_evidence_class)
        check("candidate_id", certificate.candidate_id == candidate.candidate_id)
        check("candidate_digest", certificate.candidate_digest == candidate.digest)
        check("candidate_content_digest",
              certificate.candidate_content_digest == candidate.content_digest)
        check("policy_digest",
              certificate.qualification_policy_digest == self.policy.digest)
        check("partition", certificate.partition == self.policy.partition)
        check("certificate_not_revoked",
              certificate.digest not in self._revoked
              and (self._status is None
                   or self._status(certificate.digest) not in
                   {"revoked", "superseded", "invalid"}))
        check("certificate_not_expired", self._not_expired(certificate))

        protocol = self._protocols.resolve(
            certificate.evaluation_protocol_digest)
        check("protocol_known", protocol is not None)
        if self.policy.required_protocol_digest is not None:
            check("protocol_matches_policy",
                  certificate.evaluation_protocol_digest
                  == self.policy.required_protocol_digest)
        if self.policy.required_preregistration_digest is not None:
            check("preregistration_matches_policy",
                  certificate.preregistration_digest
                  == self.policy.required_preregistration_digest)
        if protocol is not None:
            check("preregistration_matches_protocol",
                  certificate.preregistration_digest
                  == protocol.get("protocol_digest"))
            declared = protocol.get("sample_size")
            check("sample_count_meets_protocol",
                  type(declared) is int
                  and certificate.sample_count >= declared)
            check("protocol_primary_metric",
                  certificate.primary_metric == protocol.get("primary_metric"))
            check("protocol_conformance_declared",
                  certificate.protocol_conformance.get("conforms") is True)
            check("protocol_conformance_task_count",
                  certificate.protocol_conformance.get(
                      "executed_task_count") == len(
                          certificate.individual_task_receipts))
            check("protocol_conformance_declared_sample",
                  certificate.protocol_conformance.get(
                      "declared_sample_size") == declared)
            check("protocol_conformance_no_mismatches",
                  not certificate.protocol_conformance.get("mismatches"))
        check("sample_count_meets_policy",
              certificate.sample_count >= self.policy.min_sample_size)
        receipts = certificate.individual_task_receipts
        check("receipt_count_matches_sample",
              len(receipts) == certificate.sample_count)
        task_ids = [item["task_id"] for item in receipts]
        check("task_ids_unique", len(set(task_ids)) == len(task_ids))
        check("receipts_are_holdout",
              all(item.get("outcome") in {"pass", "fail", "partial", "error"}
                  for item in receipts))
        check("authorized_task_scope",
              not self.policy.authorized_task_ids
              or set(task_ids) <= set(self.policy.authorized_task_ids))
        check("repository_snapshots_present",
              bool(certificate.repository_snapshot_digests))
        check("authorized_repository_scope",
              not self.policy.authorized_repository_digests
              or set(certificate.repository_snapshot_digests)
              <= set(self.policy.authorized_repository_digests))
        security = candidate.payload.get("security", {})
        check("candidate_security_auto_qualification_allowed",
              not (isinstance(security, Mapping)
                   and security.get("auto_qualification_allowed") is False))

        interval = certificate.confidence_interval
        check("confidence_level",
              interval.get("confidence_milli", 0)
              >= self.policy.confidence_milli)
        check("effect_size",
              interval.get("point_estimate_milli", 0)
              >= self.policy.min_effect_milli)
        if self.policy.require_positive_interval:
            check("positive_interval",
                  interval.get("lower_milli", -1) > 0)
        negative = certificate.negative_transfer_results
        check("negative_transfer_rate",
              negative.get("rate_milli", 1001)
              <= self.policy.max_negative_transfer_rate_milli)
        check("regressions", negative.get("regressions", 1)
              <= self.policy.max_regressions)

        if self.policy.require_delivery_attestation:
            delivery_ok, delivery_detail = self._verify_deliveries(
                certificate, candidate)
            check("delivery_attestation", delivery_ok)
            if not delivery_ok:
                failures.append("delivery_attestation:" + delivery_detail)
            check("aggregate_delivery_digest",
                  certificate.candidate_delivery_digest
                  == aggregate_delivery_digest(receipts))
        if self._receipts is not None:
            check("receipts_authenticate",
                  self._verify_receipts(certificate))
            check("receipt_repository_scope",
                  self._verify_receipt_repositories(certificate))

        return QualificationValidation(
            ok=not failures, failures=tuple(failures), checks=checks)

    def _not_expired(self, certificate: EvaluationCertificateV1) -> bool:
        if certificate.expires_at is None:
            return True
        try:
            return _parse_instant(certificate.expires_at) > \
                _parse_instant(self._now())
        except (TypeError, ValueError):
            return False

    def _verify_deliveries(
        self, certificate: EvaluationCertificateV1, candidate: CandidateV1
    ) -> tuple[bool, str]:
        if self._deliveries is None or self._delivery_resolver is None:
            return False, "delivery_authority_unconfigured"
        try:
            for item in certificate.individual_task_receipts:
                attestation = self._deliveries.resolve(
                    item["delivery_digest"], self._delivery_resolver)
                if attestation.digest != item.get("attestation_digest"):
                    return False, "attestation_digest_mismatch"
                if attestation.delivery_digest != item["delivery_digest"]:
                    return False, "delivery_digest_mismatch"
                if attestation.candidate_id != candidate.candidate_id:
                    return False, "candidate_id_mismatch"
                if attestation.candidate_digest != candidate.digest:
                    return False, "candidate_digest_mismatch"
                if attestation.content_digest != candidate.content_digest:
                    return False, "content_digest_mismatch"
                if attestation.task_id != item["task_id"]:
                    return False, "task_id_mismatch"
                if attestation.receipt_digest != item["receipt_digest"]:
                    return False, "receipt_digest_mismatch"
        except (CertificateError, KeyError) as exc:
            return False, str(exc)
        return True, ""

    def _verify_receipts(
        self, certificate: EvaluationCertificateV1
    ) -> bool:
        try:
            for item in certificate.individual_task_receipts:
                receipt = self._receipts(item["receipt_digest"])
                if receipt is None:
                    return False
                if getattr(receipt, "task_id", None) != item["task_id"]:
                    return False
                if getattr(receipt, "outcome", None) != item["outcome"]:
                    return False
        except Exception:
            return False
        return True

    def _verify_receipt_repositories(
        self, certificate: EvaluationCertificateV1
    ) -> bool:
        """Every receipt must name a repository the certificate binds."""
        allowed = set(certificate.repository_snapshot_digests)
        if not allowed:
            return False
        try:
            for item in certificate.individual_task_receipts:
                receipt = self._receipts(item["receipt_digest"])
                repository = getattr(
                    receipt, "evaluated_repo_digest", None)
                if repository not in allowed:
                    return False
        except Exception:
            return False
        return True


def _missing_delivery(digest: str):
    raise CertificateError("delivery_attestation_missing", digest)


__all__ = [
    "CERTIFICATE_DOMAIN",
    "CertificateError",
    "DeliveryAttestationAuthority",
    "EVIDENCE_CLASSES",
    "EvaluationCertificateAuthority",
    "PRODUCTION_EVIDENCE_CLASS",
    "ProtocolRegistry",
    "QualificationPolicy",
    "QualificationValidation",
    "QualificationValidator",
    "aggregate_delivery_digest",
    "certificate_body",
    "delivery_body",
    "delivery_digest",
    "sign_certificate",
    "sign_delivery",
    "verify_certificate",
    "verify_delivery",
]
