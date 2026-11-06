"""Base-digest-locked, byte-preserving patch proposals (SIS3-008).

A proposal is an immutable artifact, never a write command. ``propose_edit``
operates on raw bytes: the target file's digest is computed and locked into
the proposal, the ``old`` span must occur exactly once, and only that span is
replaced — every other byte (comments, formatting, Unicode, CRLF/LF line
endings, other files) is preserved by construction. The unified diff and the
patched content are returned for artifact storage alongside the
``PatchProposalV1`` record; nothing here writes to the repository.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .contracts import ContractError, PatchProposalV1, canonical_digest

_MAX_FILE_BYTES = 4 << 20
_MAX_SPAN_BYTES = 1 << 20
_SAFE_PATH = re.compile(r"^(?!/)(?![A-Za-z]:)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.@/-]{1,512}$")


class PatchError(RuntimeError):
    """The proposal cannot be constructed without violating preservation."""


@dataclass(frozen=True)
class PatchResult:
    """A proposal plus the bytes needed to review and replay it."""

    proposal: PatchProposalV1
    patched_content: bytes
    unified_diff: bytes


def _validate_path(target_path: str) -> None:
    if not isinstance(target_path, str) or not _SAFE_PATH.fullmatch(target_path):
        raise ContractError("target_path must be a normalized relative path")
    if any(part in {"", ".", ".."} for part in target_path.split("/")):
        raise ContractError("target_path must be a normalized relative path")


def span_fingerprint(target_path: str, old: bytes, offset: int) -> str:
    """Deterministic fingerprint of the exact byte span being replaced."""
    return canonical_digest("span_fingerprint", 1, {
        "target_path": target_path,
        "old_sha256": hashlib.sha256(old).hexdigest(),
        "offset": offset,
    })


def propose_edit(
    base_dir: str | Path,
    target_path: str,
    old: bytes,
    new: bytes,
    *,
    proposer_id: str,
    purpose: str,
    procedure_ids: tuple[str, ...] = (),
    precondition_evidence_refs: tuple[str, ...] = (),
) -> PatchResult:
    """Construct a proposal replacing the unique ``old`` span with ``new``.

    Rejects missing files, ambiguous (nonunique) spans, missing spans,
    oversized content, and identity edits. ``source_blob_digest`` locks the
    proposal to exactly the input file bytes observed here.
    """
    _validate_path(target_path)
    if not isinstance(old, bytes) or not old or len(old) > _MAX_SPAN_BYTES:
        raise PatchError("old span must be nonempty bounded bytes")
    if not isinstance(new, bytes) or len(new) > _MAX_SPAN_BYTES:
        raise PatchError("new span must be bounded bytes")
    if old == new:
        raise PatchError("identity edits are not valid proposals")

    root = Path(base_dir).resolve()
    target = (root / target_path).resolve()
    if root not in target.parents:
        raise PatchError("target escapes the base directory")
    try:
        content = target.read_bytes()
    except OSError as exc:
        raise PatchError("target file is unreadable") from exc
    if len(content) > _MAX_FILE_BYTES:
        raise PatchError("target file exceeds the patch bound")

    first = content.find(old)
    if first < 0:
        raise PatchError("old span not found in target")
    if content.find(old, first + 1) >= 0:
        raise PatchError("old span is not unique in target")

    patched = content[:first] + new + content[first + len(old):]
    # Preservation invariant: everything outside the span is byte-identical.
    assert patched[:first] == content[:first]
    assert patched[first + len(new):] == content[first + len(old):]

    diff = _unified_diff(content, patched, target_path)
    proposal = PatchProposalV1(
        schema_version=1,
        source_blob_digest=hashlib.sha256(content).hexdigest(),
        target_path=target_path,
        exact_span_fingerprint=span_fingerprint(target_path, old, first),
        generated_diff_digest=hashlib.sha256(diff).hexdigest(),
        purpose=purpose,
        procedure_ids=tuple(procedure_ids),
        precondition_evidence_refs=tuple(precondition_evidence_refs),
        proposer_id=proposer_id,
    )
    return PatchResult(proposal=proposal, patched_content=patched, unified_diff=diff)


def verify_proposal(
    base_dir: str | Path,
    proposal: PatchProposalV1,
    patched_content: bytes,
    diff: bytes,
) -> dict:
    """Re-check a stored proposal against the base tree and its artifacts."""
    _validate_path(proposal.target_path)
    problems: list[str] = []
    root = Path(base_dir).resolve()
    target = (root / proposal.target_path).resolve()
    try:
        content = target.read_bytes()
    except OSError:
        content = b""
        problems.append("target_unreadable")
    if content and hashlib.sha256(content).hexdigest() != proposal.source_blob_digest:
        problems.append("source_mismatch")
    if hashlib.sha256(diff).hexdigest() != proposal.generated_diff_digest:
        problems.append("diff_mismatch")
    if len(patched_content) > _MAX_FILE_BYTES:
        problems.append("patched_content_too_large")
    if patched_content == content:
        problems.append("patched_content_is_identity")
    return {"ok": not problems, "problems": problems}


def _unified_diff(old: bytes, new: bytes, path: str) -> bytes:
    try:
        old_lines = old.decode("utf-8").splitlines(keepends=True)
        new_lines = new.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return b"binary content differs\n"
    diff = difflib.unified_diff(
        old_lines, new_lines,
        fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
    )
    text = "".join(line if line.endswith("\n") else line + "\n" for line in diff)
    return text.encode("utf-8")
