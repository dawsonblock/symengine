"""Production composition root for the v3 serving boundary.

Everything a production guidance decision depends on is assembled here,
from one JSON configuration, and nowhere else:

- the candidate registry with its signed decision/evidence authorities,
  pinned evaluation protocol and certificate qualification policy;
- independent evidence custody (signed revocation/supersession logs and
  signed dependency links);
- the signed authority checkpoint store and its verifier
  (``production_serving``);
- the shared control plane (SQLite path or PostgreSQL DSN);
- the trusted repository registry and the execution-identity authority;
- optionally, the trusted :class:`AuthorityJournal` publisher, when this
  process holds the authority signing key;
- the authenticated :class:`V3ServingService` in front of a production
  :class:`GovernedServingGateway`.

The configuration carries only public trust anchors and file locations.
Secrets (API bearer tokens, the optional authority signing seed) are read
from files named in the configuration. Every production input is
mandatory; a missing or malformed one raises :class:`BootstrapError`
before anything is served.
"""
from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any, Mapping

from .candidate_authority import (CandidateDecisionAuthority,
                                  CandidateEvidenceAuthority)
from .candidates import CandidateRegistry
from .checkpoints import (AuthorityJournal, AuthorityStateVerifier,
                          FileAuthorityCheckpointStore)
from .contracts import (CandidateDeliveryAttestationV1, ContractError,
                        parse_outcome_receipt)
from .control_plane import open_control_plane
from .evaluation_certificate import (DeliveryAttestationAuthority,
                                     EvaluationCertificateAuthority,
                                     ProtocolRegistry, QualificationPolicy,
                                     QualificationValidator)
from .evidence_custody import EvidenceCustodyError, EvidenceCustodyStore
from .execution_identity import ExecutionIdentityAuthority
from .repository_registry import RepositoryRegistry
from .serving import GovernedServingGateway
from .serving_service import V3ServingService
from .verifier import verify_receipt_signature

_REQUIRED = (
    "candidate_database",
    "custody_root",
    "custody_revocation_keys",
    "checkpoint_store",
    "authority_keys",
    "authority_epoch",
    "authority_policy_version",
    "control_plane",
    "repository_registry",
    "repository_registry_public_key",
    "execution_identity_keys",
    "evaluator_keys",
    "operator_keys",
    "certificate_keys",
    "delivery_keys",
    "evaluation_protocol",
    "qualification_policy",
    "api_keys_file",
)


class BootstrapError(RuntimeError):
    """The v3 production configuration is incomplete or invalid."""


class V3Runtime:
    """The composed stack; ``close()`` releases its durable handles."""

    def __init__(self, *, service, gateway, registry, custody,
                 control_plane, journal=None) -> None:
        self.service = service
        self.gateway = gateway
        self.registry = registry
        self.custody = custody
        self.control_plane = control_plane
        self.journal = journal

    def close(self) -> None:
        self.registry.close()
        self.control_plane.close()


def _keys(config: Mapping, name: str) -> dict[str, str]:
    value = config.get(name)
    if not isinstance(value, Mapping) or not value or not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in value.items()):
        raise BootstrapError(f"v3_config_invalid:{name}")
    return dict(value)


def _path(config: Mapping, name: str, base: Path) -> Path:
    value = config.get(name)
    if not isinstance(value, str) or not value:
        raise BootstrapError(f"v3_config_invalid:{name}")
    path = Path(value)
    return path if path.is_absolute() else base / path


def _json_file(path: Path, name: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BootstrapError(f"v3_config_unreadable:{name}") from exc


def _policy(value) -> QualificationPolicy:
    if not isinstance(value, Mapping):
        raise BootstrapError("v3_config_invalid:qualification_policy")
    allowed = {f.name for f in fields(QualificationPolicy)}
    body = {k: v for k, v in value.items() if k != "schema_version"}
    unknown = sorted(set(body) - allowed)
    if unknown:
        raise BootstrapError(
            "v3_config_invalid:qualification_policy:" + ",".join(unknown))
    for name in ("authorized_repository_digests", "authorized_task_ids"):
        if name in body:
            body[name] = tuple(body[name])
    try:
        return QualificationPolicy(**body)
    except Exception as exc:  # noqa: BLE001 - surfaced as config error
        raise BootstrapError(
            "v3_config_invalid:qualification_policy") from exc


class _CustodyReceipts:
    """Resolve evaluator receipts from custody and re-authenticate them."""

    def __init__(self, custody: EvidenceCustodyStore,
                 evaluator_keys: Mapping[str, str]) -> None:
        self._custody = custody
        self._keys = dict(evaluator_keys)

    def __call__(self, digest: str):
        try:
            receipt = parse_outcome_receipt(self._custody.get(digest))
        except (EvidenceCustodyError, ContractError) as exc:
            raise ValueError("receipt_unavailable") from exc
        public_hex = self._keys.get(receipt.signer_key_id)
        if public_hex is None or not verify_receipt_signature(
                receipt, public_hex):
            raise ValueError("receipt_signature_invalid")
        if receipt.digest != digest:
            raise ValueError("receipt_digest_mismatch")
        return receipt


class _CustodyDeliveries:
    """Resolve delivery attestations stored in custody by delivery digest.

    The validator re-verifies each attestation's harness signature; this
    index only locates it. It is rebuilt on a miss so attestations added
    after start-up are found.
    """

    def __init__(self, custody: EvidenceCustodyStore) -> None:
        self._custody = custody
        self._index: dict[str, str] = {}

    def _rebuild(self) -> None:
        index: dict[str, str] = {}
        for digest in self._custody.object_digests():
            try:
                body = self._custody.get(digest)
            except EvidenceCustodyError:
                continue
            if isinstance(body, dict) and "delivery_digest" in body \
                    and "attestation_id" in body:
                index[body["delivery_digest"]] = digest
        self._index = index

    def __call__(self, delivery_digest: str) -> CandidateDeliveryAttestationV1:
        if delivery_digest not in self._index:
            self._rebuild()
        digest = self._index.get(delivery_digest)
        if digest is None:
            raise KeyError(delivery_digest)
        attestation = CandidateDeliveryAttestationV1.from_dict(
            self._custody.get(digest))
        if attestation.digest != digest:
            raise KeyError(delivery_digest)
        return attestation


def build_v3_runtime(config: Mapping[str, Any], *,
                     base_dir: str | Path | None = None) -> V3Runtime:
    """Compose the production v3 serving stack, failing closed."""
    if not isinstance(config, Mapping):
        raise BootstrapError("v3_config_invalid")
    missing = [name for name in _REQUIRED if config.get(name) in (None, "")]
    if missing:
        raise BootstrapError("v3_config_missing:" + ",".join(missing))
    base = Path(base_dir) if base_dir is not None else Path.cwd()

    candidate_db = _path(config, "candidate_database", base)
    custody = EvidenceCustodyStore(
        _path(config, "custody_root", base),
        trusted_revocation_keys=_keys(config, "custody_revocation_keys"),
        candidate_database_path=candidate_db,
        require_signed_links=True)

    authority_keys = _keys(config, "authority_keys")
    store = FileAuthorityCheckpointStore(
        _path(config, "checkpoint_store", base),
        trusted_authority_keys=authority_keys,
        candidate_database_path=candidate_db)
    epoch = config.get("authority_epoch")
    if type(epoch) is not int or epoch < 1:
        raise BootstrapError("v3_config_invalid:authority_epoch")
    policy_version = config.get("authority_policy_version")
    if not isinstance(policy_version, str):
        raise BootstrapError("v3_config_invalid:authority_policy_version")
    verifier = AuthorityStateVerifier(
        store, trusted_authority_keys=authority_keys,
        expected_epoch=epoch, expected_policy_version=policy_version,
        max_checkpoint_age_seconds=config.get("max_checkpoint_age_seconds"))

    protocol = config.get("evaluation_protocol")
    if isinstance(protocol, str):
        protocol = _json_file(_path(config, "evaluation_protocol", base),
                              "evaluation_protocol")
    protocols = ProtocolRegistry()
    try:
        protocol_digest = protocols.register(protocol)
    except Exception as exc:  # noqa: BLE001
        raise BootstrapError("v3_config_invalid:evaluation_protocol") from exc

    evaluator_keys = _keys(config, "evaluator_keys")
    receipts = _CustodyReceipts(custody, evaluator_keys)
    deliveries = _CustodyDeliveries(custody)
    validator = QualificationValidator(
        _policy(config.get("qualification_policy")),
        certificate_authority=EvaluationCertificateAuthority(
            trusted_evaluator_keys=_keys(config, "certificate_keys")),
        delivery_authority=DeliveryAttestationAuthority(
            trusted_harness_keys=_keys(config, "delivery_keys")),
        protocol_registry=protocols,
        receipt_resolver=receipts,
        delivery_resolver=deliveries,
        certificate_status=custody.status)

    registry = CandidateRegistry(
        candidate_db,
        receipt_authority=receipts,
        evidence_authority=CandidateEvidenceAuthority(
            trusted_evaluator_keys=evaluator_keys),
        decision_authority=CandidateDecisionAuthority(
            trusted_operator_keys=_keys(config, "operator_keys")),
        expected_evaluation_protocol_digest=protocol_digest,
        checkpoint_verifier=verifier,
        production_serving=True,
        qualification_policy=validator.policy,
        qualification_validator=validator,
        evidence_custody=custody,
        require_evidence_custody=True)
    control_plane = None
    try:
        control_plane = open_control_plane(
            config["control_plane"]
            if str(config["control_plane"]).startswith(
                ("postgresql://", "postgres://"))
            else _path(config, "control_plane", base))
        journal = None
        signer = config.get("authority_signer")
        if signer is not None:
            if not isinstance(signer, Mapping):
                raise BootstrapError("v3_config_invalid:authority_signer")
            seed_hex = _path(signer, "seed_file", base).read_text(
                encoding="utf-8").strip()
            try:
                seed = bytes.fromhex(seed_hex)
            except ValueError as exc:
                raise BootstrapError(
                    "v3_config_invalid:authority_signer") from exc
            key_id = signer.get("key_id")
            if key_id not in authority_keys:
                raise BootstrapError(
                    "v3_config_invalid:authority_signer:key_id")
            journal = AuthorityJournal(
                registry, store, signer_seed=seed, signer_key_id=key_id,
                issuer_identity=str(signer.get("issuer_identity")
                                    or "authority"),
                authority_epoch=epoch, policy_version=policy_version,
                control_plane=control_plane)
            registry.bind_authority_journal(journal)
            custody.bind_on_change(journal.publish)

        repositories = RepositoryRegistry.load(
            _path(config, "repository_registry", base),
            registry_public_hex=config["repository_registry_public_key"])
        identities = ExecutionIdentityAuthority(
            trusted_harness_keys=_keys(config, "execution_identity_keys"),
            repository_registry=repositories)
        gateway = GovernedServingGateway(
            registry, repository_registry=repositories, production=True,
            execution_identity_authority=identities,
            receipt_authority=receipts, control_plane=control_plane)
        api_keys = _json_file(_path(config, "api_keys_file", base),
                              "api_keys_file")
        if not isinstance(api_keys, Mapping):
            raise BootstrapError("v3_config_invalid:api_keys_file")
        service = V3ServingService(gateway, api_keys=api_keys)
        # Production readiness is checked before the first request: an
        # unanchored or rolled-back authority must not even start.
        health = gateway.health()
        if not health["checks"].get("authority", {}).get("ok"):
            raise BootstrapError(
                "v3_authority_not_ready:"
                + str(health["checks"].get("authority")))
    except BaseException:
        registry.close()
        if control_plane is not None:
            control_plane.close()
        raise
    return V3Runtime(service=service, gateway=gateway, registry=registry,
                     custody=custody, control_plane=control_plane,
                     journal=journal)


def build_v3_service(config: Mapping[str, Any] | str | Path, *,
                     base_dir: str | Path | None = None) -> V3ServingService:
    """Build the production :class:`V3ServingService` from a config.

    ``config`` is a mapping or the path of a JSON file; relative paths in
    a file are resolved against the file's directory.
    """
    if isinstance(config, (str, Path)):
        path = Path(config)
        loaded = _json_file(path, "v3_config")
        return build_v3_runtime(
            loaded, base_dir=base_dir or path.resolve().parent).service
    return build_v3_runtime(config, base_dir=base_dir).service


__all__ = ["BootstrapError", "V3Runtime", "build_v3_runtime",
           "build_v3_service"]
