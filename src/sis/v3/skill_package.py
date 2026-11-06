"""vskill-style skill packaging (SIS v3.3, milestone 8).

A minimal compatible distribution adapter — packaging only, never a
promotion authority:

- Export writes an immutable bundle: ``manifest.json`` (identity,
  version, provenance, compatibility, scan results), ``payload.json``
  (canonical ``CandidateV1`` bytes) and ``SHA256SUMS`` over both.
- Import re-verifies every declared hash *and* re-derives the candidate
  digest from the payload itself — a bundle whose manifest lies about
  its content fails closed.
- Imported skills enter the candidate registry at PROPOSED. A package
  scan that passes, a manifest that asserts qualification, or a trusted
  transport — none of these confers SIS qualification.
- Revocation checking is the caller's responsibility wherever a trusted
  authority connection exists; the bundle format carries the digests
  that check needs.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .candidates import CandidateRegistry
from .contracts import CandidateV1, ContractError, canonical_json, loads_json

_MANIFEST_KEYS = {
    "schema_version", "format", "name", "version", "candidate_id",
    "candidate_type", "candidate_digest", "provenance",
    "compatibility", "scan_findings", "created_at",
}
_FORMAT = "sis-skill-bundle/1"
_DANGEROUS = re.compile(
    r"(;|&&|\|\||`|\$\(|>\s*/|\brm\s+-rf\b|\bcurl\b|\bwget\b|\bsudo\b"
    r"|\bchmod\b|\beval\b|\bexec\b|\bbase64\b|\bpowershell\b)", re.I)


class PackageError(RuntimeError):
    """A skill bundle is malformed, tampered, or cannot be installed."""


def security_scan(candidate: CandidateV1) -> list[str]:
    """Static advisory scan of payload text; never implies qualification."""
    findings: list[str] = []
    texts: list[str] = []
    payload = candidate.payload
    for key in ("steps", "lesson"):
        value = payload.get(key)
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, (list, tuple)):
            texts.extend(v for v in value if isinstance(v, str))
    for text in texts:
        hits = sorted({m.group(0) for m in _DANGEROUS.finditer(text)})
        if hits:
            findings.append(
                f"suspicious_tokens:{','.join(hits[:6])}")
        if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
            findings.append("control_characters_present")
    return findings


def export_bundle(
    candidate: CandidateV1,
    out_dir: str | Path,
    *,
    name: str | None = None,
    version: str = "1.0.0",
    qualification_status: str = "proposed",
    compatibility: dict | None = None,
    created_at: str | None = None,
) -> Path:
    """Write an immutable skill bundle; returns the bundle directory."""
    if not isinstance(candidate, CandidateV1):
        candidate = CandidateV1.from_dict(candidate)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=False)
    payload_bytes = candidate.canonical_bytes()
    manifest = {
        "schema_version": 1,
        "format": _FORMAT,
        "name": name or candidate.candidate_id,
        "version": version,
        "candidate_id": candidate.candidate_id,
        "candidate_type": candidate.candidate_type,
        "candidate_digest": candidate.digest,
        "provenance": {
            "generator_identity": candidate.generator_identity,
            "source_episode_ids": list(candidate.source_episode_ids),
            "parent_candidate_ids": list(candidate.parent_candidate_ids),
            "sis_qualification_status": qualification_status,
        },
        "compatibility": dict(compatibility or {"sis": ">=3.3.0"}),
        "scan_findings": security_scan(candidate),
        "created_at": created_at or _now(),
    }
    manifest_bytes = canonical_json(manifest)
    sums = (
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json\n"
        f"{hashlib.sha256(payload_bytes).hexdigest()}  payload.json\n"
    ).encode("utf-8")
    (out / "manifest.json").write_bytes(manifest_bytes)
    (out / "payload.json").write_bytes(payload_bytes)
    (out / "SHA256SUMS").write_bytes(sums)
    return out


def _read_sums(bundle: Path) -> dict[str, str]:
    try:
        raw = (bundle / "SHA256SUMS").read_text(encoding="utf-8")
    except OSError as exc:
        raise PackageError("sha256sums_missing") from exc
    out: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            raise PackageError("sha256sums_malformed")
        out[parts[1].strip()] = parts[0]
    return out


def verify_install(bundle: str | Path) -> dict:
    """Re-verify a bundle's declared hashes and payload identity.

    Returns {"ok": bool, "problems": [...]}. Fails closed: any
    missing/mismatched/unverifiable element is a problem.
    """
    bundle = Path(bundle)
    problems: list[str] = []
    try:
        sums = _read_sums(bundle)
    except PackageError as exc:
        return {"ok": False, "problems": [str(exc)]}
    for name in ("manifest.json", "payload.json"):
        expected = sums.get(name)
        if expected is None:
            problems.append(f"undeclared_hash:{name}")
            continue
        try:
            actual = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        except OSError:
            problems.append(f"missing_file:{name}")
            continue
        if actual != expected:
            problems.append(f"hash_mismatch:{name}")
    extra = {p.name for p in bundle.iterdir() if p.is_file()} - {
        "manifest.json", "payload.json", "SHA256SUMS"}
    if extra:
        problems.append(f"unexpected_files:{sorted(extra)[:4]}")
    manifest = None
    manifest_ok = False
    try:
        manifest = loads_json((bundle / "manifest.json").read_bytes())
        if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
            problems.append("manifest_schema_mismatch")
        elif manifest.get("format") != _FORMAT:
            problems.append("manifest_format_unsupported")
        else:
            manifest_ok = True
    except (ContractError, OSError):
        problems.append("manifest_unreadable")
    try:
        candidate = CandidateV1.from_dict(
            loads_json((bundle / "payload.json").read_bytes()))
        if manifest_ok:
            if manifest.get("candidate_digest") != candidate.digest:
                problems.append("candidate_digest_mismatch")
            if manifest.get("candidate_id") != candidate.candidate_id:
                problems.append("candidate_id_mismatch")
    except (ContractError, OSError):
        problems.append("payload_unreadable")
    return {"ok": not problems, "problems": problems}


def import_bundle(
    bundle: str | Path,
    registry: CandidateRegistry,
    *,
    actor_role: str,
) -> str:
    """Verify and register a bundle's candidate at PROPOSED.

    The manifest's ``sis_qualification_status`` claim is ignored by
    design — imported skills are always unqualified candidates.
    """
    result = verify_install(bundle)
    if not result["ok"]:
        raise PackageError(
            "bundle_verification_failed:" + ",".join(result["problems"]))
    payload = (Path(bundle) / "payload.json").read_bytes()
    candidate = CandidateV1.from_dict(loads_json(payload))
    return registry.submit(candidate, actor_role=actor_role)


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
