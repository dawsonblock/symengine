"""Ingest real agent skills as unqualified SIS candidates (v3.3, M10).

A skill is a directory with ``SKILL.md`` (YAML frontmatter plus a
Markdown body) and optional ``references/``, ``scripts/`` and
``assets/`` files — the format used by the vskill and skills catalogs.
This module turns one into a bounded ``CandidateV1`` of type
``skill_bundle`` and submits it at PROPOSED.

The ingester is a packaging adapter, never a promotion authority:

- parsing is bounded and dependency-free (no YAML library, no code
  execution, no network);
- only regular UTF-8 files inside the skill directory are read; symlinks,
  traversal, hidden files, oversized bodies and oversized resource sets
  are refused;
- resource files are recorded by digest and size, never inlined, because
  the candidate record is capped at 64 KiB;
- scan findings are advisory and reported, never a qualification;
- a status claimed by the source (frontmatter or bundle manifest) is
  ignored — every ingested skill enters at PROPOSED;
- the candidate id is derived from name + content digest, so re-ingesting
  identical content is a no-op and changed content is a new candidate.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .candidates import (CandidateConflict, CandidateRegistry,
                         content_digest)
from .contracts import CandidateV1, ContractError, canonical_digest, loads_json
from .skill_markdown import (MarkdownError, ParsedSkillMarkdown,
                             parse_markdown)
from .skill_package import PackageError, import_bundle

SKILL_FILE = "SKILL.md"
FORMAT = "sis-skill/1"
MANIFEST_VERSION = 1
PARSER_VERSION = "sis-markdown/1"
SCANNER_VERSION = "sis-skill-scan/1"

MAX_FRONTMATTER_BYTES = 8 * 1024
# Large but bounded: the full body digest is preserved, but only the
# first bounded instruction window is inlined into the 64 KiB candidate.
MAX_BODY_BYTES = 96 * 1024
CHUNK_CHARS = 4000
MAX_INSTRUCTION_CHUNKS = 8
MAX_RESOURCES = 64
MAX_RESOURCE_BYTES = 16 * 1024 * 1024
MAX_RESOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_RESOURCE_PATH = 256
MAX_STEPS = 32
MAX_STEP_CHARS = 320
MAX_SCAN_SKILLS = 500
MAX_DEPTH = 6

_KEY = re.compile(r"^([A-Za-z0-9_-]{1,64}):[ \t]*(.*)$")
_LIST_ITEM = re.compile(r"^(?:[-*+]|\d{1,3}[.)])[ \t]+(.+)$")
_SLUG = re.compile(r"[^a-z0-9]+")
_EXEC = re.compile(
    r"(\brm\s+-rf\b|\bcurl\s|\bwget\s|\bsudo\s|\bchmod\s"
    r"|\beval\s*[\(\"'$]|\bexec\s*[\(\"'$]|\bbase64\s+-d"
    r"|\bpowershell\b|\bsh\s+-c\b|>\s*/)", re.I)
_INJECTION = re.compile(
    r"(ignore (all )?(previous|prior|above) instructions"
    r"|disregard (the )?(system|previous) (prompt|instructions)"
    r"|you are now\b|act as (the )?system"
    r"|reveal (the )?(system prompt|api key|secret)"
    r"|exfiltrat\w*|do not (tell|inform) the user"
    r"|<\|?(system|im_start)\|?>)", re.I)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class SkillIngestError(RuntimeError):
    """A skill cannot be read, parsed, or registered as a candidate."""


class SkillDiscoveryIncomplete(SkillIngestError):
    """Enumeration hit the bound before the tree was exhausted.

    The caller must never treat a truncated catalog as complete. Either
    paginate with ``discover_skills_page`` or set an explicit limit and
    record the incomplete result.
    """

    def __init__(self, scanned: int, limit: int, next_offset: int) -> None:
        self.scanned = scanned
        self.limit = limit
        self.next_offset = next_offset
        super().__init__(
            f"skill_discovery_incomplete:scanned={scanned}"
            f" limit={limit} next_offset={next_offset}")


class SkillIngestReport(list):
    """Per-skill ingestion results plus explicit discovery completeness."""

    def __init__(self, entries, *, discovery: dict) -> None:
        super().__init__(entries)
        self.discovery = discovery

    @property
    def complete(self) -> bool:
        return bool(self.discovery.get("complete"))


class SkillDiscoveryResult(list):
    """List-compatible discovery result with explicit completeness."""

    def __init__(self, skills, *, scanned: int, limit: int, offset: int,
                 complete: bool) -> None:
        super().__init__(skills)
        self.scanned = scanned
        self.limit = limit
        self.offset = offset
        self.complete = complete
        self.truncated = not complete
        self.next_offset = offset + len(self) if not complete else None

    def as_dict(self) -> dict:
        return {
            "skills": [str(path) for path in self],
            "scanned": self.scanned,
            "limit": self.limit,
            "offset": self.offset,
            "complete": self.complete,
            "truncated": self.truncated,
            "next_offset": self.next_offset,
        }


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _mtime(path: Path) -> str:
    return datetime.fromtimestamp(
        path.stat().st_mtime, timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")


def _check_text(text: str, name: str) -> str:
    if _CONTROL.search(text):
        raise SkillIngestError(f"{name}_control_characters")
    return text


def _parse_frontmatter(header: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    index = 0
    while index < len(header):
        line = header[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace() or line.lstrip().startswith("-"):
            # Nested YAML is not interpreted; the body carries the content.
            continue
        match = _KEY.match(line)
        if match is None:
            raise SkillIngestError("skill_frontmatter_malformed")
        key, value = match.group(1), match.group(2).strip()
        if value in (">", "|", ">-", "|-", ">+", "|+"):
            # Folded/literal block scalar: take the indented continuation.
            block: list[str] = []
            while index < len(header) and (
                    header[index][:1].isspace() or not header[index].strip()):
                block.append(header[index].strip())
                index += 1
            joiner = "\n" if value.startswith("|") else " "
            value = joiner.join(part for part in block if part)
        elif len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key in fields:
            raise SkillIngestError("skill_frontmatter_duplicate_key")
        if len(value) > 4096:
            raise SkillIngestError("skill_frontmatter_too_large")
        fields[key] = _check_text(value, "skill_frontmatter")
        if len(fields) > 32:
            raise SkillIngestError("skill_frontmatter_too_large")
    return fields


def read_skill_name(path: str | Path) -> str | None:
    """Read only the frontmatter name; never hashes resources."""
    skill_file = Path(path) / SKILL_FILE
    if skill_file.is_symlink() or not skill_file.is_file():
        return None
    try:
        frontmatter, _ = _split_skill_text(skill_file.read_bytes())
    except (OSError, SkillIngestError):
        return None
    return frontmatter.get("name") or Path(path).name or None



def _split_skill_text(raw: bytes) -> tuple[dict[str, str], str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SkillIngestError("skill_not_utf8") from exc
    if len(raw) > MAX_FRONTMATTER_BYTES + MAX_BODY_BYTES:
        raise SkillIngestError("skill_body_too_large")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            header = "\n".join(lines[1:index]).encode("utf-8")
            if len(header) > MAX_FRONTMATTER_BYTES:
                raise SkillIngestError("skill_frontmatter_too_large")
            return _parse_frontmatter(lines[1:index]), "\n".join(
                lines[index + 1:])
    raise SkillIngestError("skill_frontmatter_unterminated")


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[*_`]", "", text)).strip()


def _chunks(body: str) -> tuple[tuple[str, ...], bool, str]:
    """Split the body into bounded chunks; never silently lose the digest.

    The full body is hashed. Only the first ``MAX_INSTRUCTION_CHUNKS``
    chunks are inlined into the 64 KiB candidate; a larger body is
    explicitly marked truncated instead of being rejected or silently
    shortened.
    """
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
    chunks: list[str] = []
    current = ""
    for paragraph in paragraphs:
        while len(paragraph) > CHUNK_CHARS:
            cut = paragraph.rfind(" ", 0, CHUNK_CHARS)
            if cut < CHUNK_CHARS // 2:
                cut = CHUNK_CHARS
            piece, paragraph = paragraph[:cut].rstrip(), \
                paragraph[cut:].lstrip()
            if current:
                chunks.append(current)
                current = ""
            chunks.append(piece)
        if not paragraph:
            continue
        if not current:
            current = paragraph
        elif len(current) + 2 + len(paragraph) <= CHUNK_CHARS:
            current = current + "\n\n" + paragraph
        else:
            chunks.append(current)
            current = paragraph
    if current:
        chunks.append(current)
    truncated = len(chunks) > MAX_INSTRUCTION_CHUNKS
    if truncated:
        chunks = chunks[:MAX_INSTRUCTION_CHUNKS]
    return (tuple(chunks), truncated,
            hashlib.sha256(body.encode("utf-8")).hexdigest())


def _severity_rank(severity: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(severity, 0)


def security_report(
    parsed: ParsedSkillMarkdown,
    instructions: tuple[str, ...],
    body: str,
) -> dict:
    """Structured, advisory security findings with explicit severity.

    Findings are evidence for review, never proof of safety. A high
    finding prevents *automatic* qualification; it does not by itself
    reject the skill, and a clean scan does not qualify one.
    """
    findings: list[dict] = []

    def add(code: str, severity: str, location: str, match: str,
            text: str) -> None:
        findings.append({
            "code": code,
            "severity": severity,
            "location": location,
            "match": match.strip()[:64],
            "text_digest": hashlib.sha256(
                text.encode("utf-8")).hexdigest(),
        })

    for step in parsed.steps:
        for match in _EXEC.finditer(step):
            add("shell_execution_token", "high", "served_step",
                match.group(0), step)
        for match in _INJECTION.finditer(step):
            add("prompt_injection_phrase", "high", "served_step",
                match.group(0), step)
    for record in parsed.instructions:
        if record.example:
            for match in _EXEC.finditer(record.text):
                add("shell_execution_token", "low", "example_command",
                    match.group(0), record.text)
            continue
        for match in _EXEC.finditer(record.text):
            add("shell_execution_token",
                "medium" if record.active else "low",
                "instruction", match.group(0), record.text)
        for match in _INJECTION.finditer(record.text):
            add("prompt_injection_phrase", "high", "instruction",
                match.group(0), record.text)
    for chunk in instructions:
        for match in _INJECTION.finditer(chunk):
            add("prompt_injection_phrase", "high", "prose",
                match.group(0), chunk)
    for match in _INJECTION.finditer(body):
        add("prompt_injection_phrase", "high", "body",
            match.group(0), match.group(0))
    for link in parsed.links:
        if link["url"].startswith("http://"):
            add("insecure_link", "medium", "link", link["url"],
                link["url"])
    for block in parsed.blocks:
        if block.kind == "html":
            add("embedded_html", "medium", "html", "<html-block>",
                block.text)
    deduped: list[dict] = []
    seen: set[tuple] = set()
    for finding in findings:
        key = (finding["code"], finding["location"], finding["match"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    highest = max((finding["severity"] for finding in deduped),
                  key=_severity_rank, default="none")
    return {
        "scanner": SCANNER_VERSION,
        "findings": deduped,
        "highest_severity": highest,
        "auto_qualification_allowed": highest != "high",
        "advisory_only": True,
    }


def scan_findings(candidate: CandidateV1) -> list[str]:
    """Backward-compatible string findings from the structured report."""
    security = candidate.payload.get("security")
    if isinstance(security, dict) and isinstance(
            security.get("findings"), list):
        return sorted({
            f"{finding.get('code')}:{finding.get('match')}"
            for finding in security["findings"]
            if isinstance(finding, dict)})
    texts = [text for text in candidate.payload.get("instructions", ())
             if isinstance(text, str)]
    texts += [text for text in candidate.payload.get("steps", ())
              if isinstance(text, str)]
    findings: set[str] = set()
    for text in texts:
        for match in _EXEC.finditer(text):
            findings.add("shell_execution_token:"
                         + match.group(0).strip().lower()[:32])
        for match in _INJECTION.finditer(text):
            findings.add("prompt_injection_phrase:"
                         + match.group(0).lower()[:64])
    return sorted(findings)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resources(root: Path) -> list[dict]:
    """Hash resource files under ``root``; contents are never inlined.

    Symlinks, traversal, hidden files, oversized files and duplicate
    (case-folded) paths are refused. Executable bits are recorded, never
    executed; installation scripts are never run during ingestion.
    """
    out: list[dict] = []
    total = 0
    seen: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for name in dirnames:
            if (base / name).is_symlink():
                raise SkillIngestError("skill_symlink_refused:" + name)
        dirnames[:] = sorted(
            name for name in dirnames if not name.startswith("."))
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            relative = path.relative_to(root).as_posix()
            if relative == SKILL_FILE or filename.startswith("."):
                continue
            if path.is_symlink() or not path.is_file():
                raise SkillIngestError("skill_symlink_refused:" + relative)
            if len(relative) > MAX_RESOURCE_PATH:
                raise SkillIngestError("skill_resource_path_too_long")
            folded = relative.casefold()
            if folded in seen:
                raise SkillIngestError(
                    "skill_duplicate_resource:" + relative)
            seen.add(folded)
            size = path.stat().st_size
            if size > MAX_RESOURCE_FILE_BYTES:
                raise SkillIngestError(
                    "skill_resource_too_large:" + relative)
            total += size
            if total > MAX_RESOURCE_BYTES:
                raise SkillIngestError("skill_resources_too_large")
            digest = _hash_file(path)
            out.append({
                "path": relative,
                "sha256": digest,
                "bytes": size,
                "executable": bool(path.stat().st_mode & 0o111),
            })
            if len(out) > MAX_RESOURCES:
                raise SkillIngestError("skill_too_many_resources")
    return out


def load_skill(path: str | Path) -> dict:
    """Parse one skill directory into a bounded, normalized source."""
    root = Path(path)
    if root.is_symlink():
        raise SkillIngestError("skill_symlink_refused")
    if not root.is_dir():
        raise SkillIngestError("skill_directory_missing")
    skill_file = root / SKILL_FILE
    if skill_file.is_symlink() or not skill_file.is_file():
        raise SkillIngestError("skill_file_missing")
    try:
        raw = skill_file.read_bytes()
    except OSError as exc:
        raise SkillIngestError("skill_file_unreadable") from exc
    frontmatter, body = _split_skill_text(raw)
    body = _check_text(body, "skill_body").strip()
    if not body:
        raise SkillIngestError("skill_body_missing")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise SkillIngestError("skill_body_too_large")
    name = frontmatter.get("name", "").strip()
    description = frontmatter.get("description", "").strip()
    if not frontmatter:
        # A body without any frontmatter is not a skill package.
        raise SkillIngestError("skill_name_missing")
    if not name:
        # Legitimate catalogs omit ``name`` and rely on the directory.
        name = root.name.strip()
    if not name:
        raise SkillIngestError("skill_name_missing")
    if not description:
        raise SkillIngestError("skill_description_missing")
    if len(name) > 128 or len(description) > 4096:
        raise SkillIngestError("skill_frontmatter_too_large")
    extras = {
        key: value for key, value in sorted(frontmatter.items())
        if key not in {"name", "description", "version"}
    }
    version = frontmatter.get("version", "").strip()
    if len(version) > 128 or len(extras) > 32 or \
            sum(len(key) + len(value) for key, value in extras.items()) > 8192:
        raise SkillIngestError("skill_frontmatter_too_large")
    try:
        parsed = parse_markdown(body)
    except MarkdownError as exc:
        raise SkillIngestError(f"skill_markdown_invalid:{exc}") from exc
    instructions, truncated, body_sha = _chunks(body)
    security = security_report(parsed, instructions, body)
    records = []
    for record in parsed.instructions:
        high_risk = bool(_EXEC.search(record.text)
                         or _INJECTION.search(record.text))
        records.append({
            "text": record.text,
            "line_start": record.line_start,
            "line_end": record.line_end,
            "section": record.section,
            "kind": record.kind,
            "active": record.active and not high_risk,
            "example": record.example,
            "truncated": record.truncated,
        })
    safe_steps = tuple(
        step for step in parsed.steps
        if not _EXEC.search(step) and not _INJECTION.search(step))
    return {
        "kind": "skill_dir",
        "name": name,
        "description": description,
        "version": version,
        "instructions": instructions,
        "instructions_truncated": truncated,
        "body_sha256": body_sha,
        "body_bytes": len(body.encode("utf-8")),
        "steps": safe_steps[:MAX_STEPS],
        "instruction_records": records,
        "examples": list(parsed.examples),
        "links": list(parsed.links),
        "headings": list(parsed.headings),
        "code_blocks": list(parsed.code_blocks),
        "sections": list(parsed.section_names),
        "security": security,
        "resources": _resources(root),
        "frontmatter": extras,
        "created_at": _mtime(skill_file),
    }


def _slug(name: str) -> str:
    slug = _SLUG.sub("-", name.lower()).strip("-")[:32].strip("-")
    return slug or "skill"


def scope_identity(scope_kind: str, scope_value: str) -> str:
    """Stable identity of an authorization scope (not of skill content)."""
    return canonical_digest("skill_scope", 1, {
        "kind": scope_kind, "value": scope_value})


def skill_candidate(
    source: dict,
    *,
    scope_kind: str,
    scope_value: str,
    target_agent: str = "agent",
    target_task_family: str = "general",
    generator_identity: str = "sis-skill-ingest",
    created_at: str | None = None,
    source_name: str | None = None,
    applicability=(),
    counterexamples=(),
) -> CandidateV1:
    """Build the PROPOSED candidate for a parsed skill source.

    The content digest binds only the parsed skill content (including the
    security assessment); the candidate id additionally binds the
    authorization scope, so identical content imported for two repository
    scopes produces two distinct candidates instead of silently reusing
    the first scope.
    """
    scope_id = scope_identity(scope_kind, scope_value)
    records = [
        {
            "text": record["text"][:256],
            "line_start": record["line_start"],
            "line_end": record["line_end"],
            "section": record["section"],
            "kind": record["kind"],
            "active": record["active"],
            "example": record["example"],
            "truncated": record["truncated"] or len(record["text"]) > 256,
        }
        for record in source.get("instruction_records", ())[:24]
    ]
    payload = {
        "format": FORMAT,
        "manifest_version": MANIFEST_VERSION,
        "parser": PARSER_VERSION,
        "name": source["name"],
        "description": source["description"],
        "version": source["version"],
        "instructions": list(source["instructions"]),
        "instructions_truncated": source["instructions_truncated"],
        "body_sha256": source["body_sha256"],
        "body_bytes": source["body_bytes"],
        "steps": list(source["steps"]),
        "markdown": {
            "instruction_records": records,
            "examples": [
                {"text": item["text"][:256],
                 "line_start": item["line_start"],
                 "line_end": item["line_end"],
                 "section": item["section"],
                 "kind": item["kind"]}
                for item in source.get("examples", ())[:16]],
            "links": [
                {"text": item["text"][:128], "url": item["url"][:256]}
                for item in source.get("links", ())[:32]],
            "headings": [
                {"level": item["level"], "text": item["text"][:128],
                 "line": item["line"]}
                for item in source.get("headings", ())[:32]],
            "code_blocks": list(source.get("code_blocks", ())[:32]),
            "sections": list(source.get("sections", ())[:16]),
        },
        "security": dict(source["security"]),
        "resources": list(source["resources"]),
        "frontmatter": dict(source["frontmatter"]),
        "source": {
            "kind": source["kind"],
            "name": source_name or source["name"],
        },
    }
    try:
        digest = content_digest("skill_bundle", payload)
        return CandidateV1(
            schema_version=1,
            candidate_id=(
                f"skill-{_slug(source['name'])}-{digest[:10]}-"
                f"{scope_id[:10]}"),
            candidate_type="skill_bundle",
            content_digest=digest,
            parent_candidate_ids=(),
            source_episode_ids=(),
            generator_identity=generator_identity,
            target_agent=target_agent,
            target_task_family=target_task_family,
            repository_scope={"kind": scope_kind, "value": scope_value},
            applicability_predicate=tuple(applicability),
            known_counterexamples=tuple(counterexamples),
            payload=payload,
            created_at=created_at or source["created_at"],
        )
    except ContractError as exc:
        raise SkillIngestError(f"skill_candidate_invalid:{exc}") from exc


def ingest_skill(
    path: str | Path,
    registry: CandidateRegistry,
    *,
    actor_role: str = "learner",
    scope_kind: str,
    scope_value: str,
    target_agent: str = "agent",
    target_task_family: str = "general",
    created_at: str | None = None,
    source_name: str | None = None,
    audit_path: str | Path | None = None,
) -> dict:
    """Parse, scan and register one skill at PROPOSED (idempotent).

    The return value keeps parsed content, candidate instructions,
    security findings and qualification state separate. High-severity
    findings set ``auto_qualification_allowed=False``; they never reject
    the artifact outright (review evidence is preserved) and a clean scan
    is never a qualification.
    """
    source = load_skill(path)
    candidate = skill_candidate(
        source, scope_kind=scope_kind, scope_value=scope_value,
        target_agent=target_agent, target_task_family=target_task_family,
        created_at=created_at, source_name=source_name)
    findings = scan_findings(candidate)
    security = dict(source["security"])
    scope_id = scope_identity(scope_kind, scope_value)
    common = {
        "candidate_id": candidate.candidate_id,
        "digest": candidate.digest,
        "content_identity": candidate.content_digest,
        "scope_identity": scope_id,
        "candidate_revision": 1,
        "name": source["name"],
        "steps": len(source["steps"]),
        "resources": len(source["resources"]),
        "scan_findings": findings,
        "security": security,
        "auto_qualification_allowed":
            security["auto_qualification_allowed"],
        "instructions_truncated": source["instructions_truncated"],
        "instruction_records": list(source["instruction_records"]),
        "qualification_state": "proposed",
    }
    existing = registry.lookup(candidate.candidate_id)
    if existing is not None:
        record, state = existing
        if record.digest != candidate.digest:
            raise SkillIngestError("scope_conflict:candidate_metadata_differs")
        entry = {**common, "status": "already_present", "state": state,
                 "qualification_state": state}
        _audit_ingestion(audit_path, entry)
        return entry
    try:
        registry.submit(candidate, actor_role=actor_role)
    except ContractError as exc:
        raise SkillIngestError(f"skill_candidate_invalid:{exc}") from exc
    entry = {**common, "status": "submitted", "state": "proposed"}
    _audit_ingestion(audit_path, entry)
    return entry


def _audit_ingestion(audit_path: str | Path | None, entry: dict) -> None:
    """Durably preserve suspicious/rejected ingestion evidence for review."""
    if audit_path is None:
        return
    path = Path(audit_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": 1,
        "kind": "skill_ingestion_evidence",
        "candidate_id": entry.get("candidate_id"),
        "digest": entry.get("digest"),
        "scope_identity": entry.get("scope_identity"),
        "status": entry.get("status"),
        "security": entry.get("security"),
    }
    with open(path, "ab") as handle:
        handle.write(json.dumps(
            record, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def discover_skills_page(
    root: str | Path,
    *,
    limit: int = MAX_SCAN_SKILLS,
    offset: int = 0,
) -> SkillDiscoveryResult:
    """Paginated discovery; the result always states whether it is complete."""
    root = Path(root)
    if type(limit) is not int or not 1 <= limit <= 100_000:
        raise SkillIngestError("skill_discovery_limit_invalid")
    if type(offset) is not int or offset < 0:
        raise SkillIngestError("skill_discovery_offset_invalid")
    if root.is_symlink():
        raise SkillIngestError("skill_symlink_refused")
    if not root.is_dir():
        raise SkillIngestError("skill_directory_missing")
    if (root / SKILL_FILE).is_file():
        skills = [root] if offset == 0 else []
        return SkillDiscoveryResult(
            skills, scanned=1, limit=limit, offset=offset, complete=True)
    found: list[Path] = []
    stop_at = offset + limit + 1
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        depth = len(base.relative_to(root).parts)
        dirnames[:] = sorted(
            name for name in dirnames
            if not name.startswith(".") and
            not (base / name).is_symlink())
        if depth > MAX_DEPTH:
            dirnames[:] = []
            continue
        if SKILL_FILE in filenames:
            found.append(base)
            if len(found) >= stop_at:
                break
    found = sorted(found)
    window = found[offset:offset + limit]
    complete = len(found) <= offset + limit
    return SkillDiscoveryResult(
        window, scanned=len(found), limit=limit, offset=offset,
        complete=complete)


def discover_skills(
    root: str | Path,
    *,
    limit: int = MAX_SCAN_SKILLS,
    offset: int = 0,
    allow_incomplete: bool = False,
) -> SkillDiscoveryResult:
    """Find skill directories; raise rather than silently truncate.

    Existing callers that only need a list still get one. A tree with
    more skills than the bound raises :class:`SkillDiscoveryIncomplete`
    unless the caller explicitly opts into an incomplete page.
    """
    result = discover_skills_page(root, limit=limit, offset=offset)
    if not result.complete and not allow_incomplete:
        raise SkillDiscoveryIncomplete(
            result.scanned, result.limit, result.next_offset)
    return result


def ingest_tree(
    root: str | Path,
    registry: CandidateRegistry,
    *,
    actor_role: str = "learner",
    scope_kind: str,
    scope_value: str,
    target_agent: str = "agent",
    target_task_family: str = "general",
    created_at: str | None = None,
    audit_path: str | Path | None = None,
    max_skills: int | None = None,
) -> SkillIngestReport:
    """Ingest every skill under ``root``; failures are recorded per skill.

    Discovery is paginated, so a tree larger than one page is never
    silently truncated. ``max_skills`` may impose an explicit hard cap;
    the report then states ``discovery.complete=False``.
    """
    root = Path(root)
    if max_skills is not None and (
            type(max_skills) is not int or max_skills < 1):
        raise SkillIngestError("skill_max_skills_invalid")
    report = SkillIngestReport([], discovery={
        "complete": True, "scanned": 0, "pages": 0,
        "limit": MAX_SCAN_SKILLS, "next_offset": None})
    offset = 0
    pages = 0
    while True:
        page = discover_skills_page(root, offset=offset)
        pages += 1
        report.discovery["pages"] = pages
        report.discovery["scanned"] = max(
            report.discovery["scanned"], page.scanned)
        for skill_dir in page:
            relative = skill_dir.relative_to(root).as_posix() \
                if skill_dir != root else skill_dir.name
            try:
                entry = ingest_skill(
                    skill_dir, registry, actor_role=actor_role,
                    scope_kind=scope_kind, scope_value=scope_value,
                    target_agent=target_agent,
                    target_task_family=target_task_family,
                    created_at=created_at, source_name=relative,
                    audit_path=audit_path)
            except (SkillIngestError, PackageError, CandidateConflict) as exc:
                report.append({"path": relative, "status": "rejected",
                               "error": str(exc)})
                _audit_ingestion(audit_path, {
                    "status": "rejected", "candidate_id": None,
                    "digest": None, "security": None,
                    "scope_identity": scope_identity(
                        scope_kind, scope_value)})
                continue
            report.append({"path": relative, **entry})
            if max_skills is not None and len(report) >= max_skills:
                report.discovery.update({
                    "complete": False,
                    "truncated": True,
                    "next_offset": offset + len(report),
                })
                return report
        if page.complete:
            report.discovery["complete"] = True
            report.discovery["truncated"] = False
            return report
        offset = page.next_offset
        report.discovery["complete"] = False
        report.discovery["truncated"] = True
        report.discovery["next_offset"] = offset


def ingest_path(
    path: str | Path,
    registry: CandidateRegistry,
    *,
    actor_role: str = "learner",
    scope_kind: str,
    scope_value: str,
    target_agent: str = "agent",
    target_task_family: str = "general",
    created_at: str | None = None,
    audit_path: str | Path | None = None,
    max_skills: int | None = None,
) -> SkillIngestReport:
    """Ingest a skill directory, a skill tree, or a vskill-style bundle."""
    path = Path(path)
    if (path / "manifest.json").is_file() and \
            (path / "payload.json").is_file():
        try:
            candidate = CandidateV1.from_dict(
                loads_json((path / "payload.json").read_bytes()))
            digest = import_bundle(path, registry, actor_role=actor_role)
        except (PackageError, ContractError, OSError) as exc:
            return SkillIngestReport(
                [{"path": path.name, "status": "rejected",
                  "error": str(exc)}],
                discovery={"complete": True, "scanned": 1, "pages": 1})
        entry = {
            "path": path.name, "status": "submitted",
            "candidate_id": candidate.candidate_id,
            "digest": digest, "state": "proposed",
            "name": candidate.candidate_id,
            "steps": len(candidate.payload.get("steps", ())),
            "resources": 0,
            "scan_findings": scan_findings(candidate),
            "security": candidate.payload.get("security"),
            "auto_qualification_allowed": (
                candidate.payload.get("security", {}) or {}).get(
                    "auto_qualification_allowed", True),
        }
        _audit_ingestion(audit_path, entry)
        return SkillIngestReport(
            [entry], discovery={"complete": True, "scanned": 1, "pages": 1})
    return ingest_tree(
        path, registry, actor_role=actor_role, scope_kind=scope_kind,
        scope_value=scope_value, target_agent=target_agent,
        target_task_family=target_task_family, created_at=created_at,
        audit_path=audit_path, max_skills=max_skills)
