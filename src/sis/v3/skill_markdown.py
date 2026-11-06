"""Bounded, structured Markdown parsing for skill instructions.

Revision 4 extracted every bullet in a ``SKILL.md`` body as an active
step, including bullets inside fenced code blocks and quoted examples.
That turns examples into guidance. This parser separates:

- headings, paragraphs, list items, fenced/indented code, blockquotes,
  tables, HTML blocks and link definitions;
- authoritative instructions (list items in workflow/usage/instruction
  sections, outside code/quotes, not command examples);
- explanatory prose, quoted examples, code, example commands and links.

Every extracted instruction keeps its source line range. The parser is
deterministic and dependency-free; it never executes or evaluates
content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

MAX_BLOCKS = 512
MAX_BLOCK_CHARS = 4_000
MAX_STEP_CHARS = 320
MAX_STEPS = 32
MAX_LINKS = 64
MAX_HEADINGS = 64

_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")
_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
_LIST = re.compile(r"^(\s{0,3})([-*+]|\d{1,3}[.)])\s+(.+)$")
_QUOTE = re.compile(r"^\s{0,3}>\s?(.*)$")
_THEMATIC = re.compile(r"^\s{0,3}((\*\s*){3,}|(-\s*){3,}|(_\s*){3,})$")
_HTML = re.compile(r"^\s{0,3}<[A-Za-z!/]")
_LINK_DEF = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*(\S+)")
_SETEXT = re.compile(r"^\s{0,3}(=+|-+)\s*$")
_TABLE_SEP = re.compile(r"^\s*\|?[\s:|-]+\|[\s:|-]*$")
_INLINE_LINK = re.compile(r"!?\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_BARE_URL = re.compile(r"https?://[^\s)>\]]+")
_INLINE_CODE = re.compile(r"`([^`]+)`")
_HTML_TAG = re.compile(r"</?[A-Za-z][^>]*>")
_EMPHASIS = re.compile(r"(\*\*|__|\*|_)")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

_SHELL_COMMANDS = frozenset({
    "git", "npm", "npx", "pnpm", "yarn", "pip", "pip3", "python",
    "python3", "pytest", "curl", "wget", "docker", "kubectl", "helm",
    "make", "cargo", "rustc", "go", "node", "deno", "bun", "bash", "sh",
    "zsh", "fish", "chmod", "chown", "sudo", "rm", "cp", "mv", "cat",
    "grep", "rg", "sed", "awk", "find", "xargs", "apt", "apt-get", "brew",
    "systemctl", "ssh", "scp", "rsync", "tar", "unzip", "zip", "openssl",
    "env", "export", "source", "cd", "ls", "mkdir", "touch", "test",
    "pytest-", "tox", "uv", "poetry", "conda", "java", "mvn", "gradle",
    "terraform", "aws", "gcloud", "az", "gh", "vercel", "netlify",
})
_INSTRUCTION_SECTIONS = (
    "workflow", "workflows", "instructions", "instruction", "usage",
    "how to use", "how this skill works", "steps", "step", "process",
    "procedure", "procedures", "checklist", "guidelines", "rules",
    "quick start", "quickstart", "task", "tasks", "approach",
    "what to assert", "seams", "control variables", "review",
)
_NON_INSTRUCTION_SECTIONS = (
    "example", "examples", "background", "why", "notes", "note",
    "references", "see also", "appendix", "changelog", "faq",
    "further reading", "history",
)


class MarkdownError(RuntimeError):
    """A Markdown document cannot be parsed within the bounded profile."""


@dataclass(frozen=True)
class MarkdownBlock:
    kind: str
    text: str
    line_start: int
    line_end: int
    section: str = "body"
    level: int | None = None
    info: str = ""
    example: bool = False
    truncated: bool = False


@dataclass(frozen=True)
class InstructionRecord:
    text: str
    line_start: int
    line_end: int
    section: str
    kind: str
    active: bool
    example: bool
    truncated: bool = False


@dataclass(frozen=True)
class ParsedSkillMarkdown:
    blocks: tuple[MarkdownBlock, ...]
    headings: tuple[dict, ...]
    instructions: tuple[InstructionRecord, ...]
    steps: tuple[str, ...]
    examples: tuple[dict, ...]
    links: tuple[dict, ...]
    code_blocks: tuple[dict, ...]
    section_names: tuple[str, ...]

    def to_payload(self) -> dict:
        return {
            "parser": "sis-markdown/1",
            "headings": list(self.headings),
            "instruction_records": [
                {
                    "text": record.text,
                    "line_start": record.line_start,
                    "line_end": record.line_end,
                    "section": record.section,
                    "kind": record.kind,
                    "active": record.active,
                    "example": record.example,
                    "truncated": record.truncated,
                }
                for record in self.instructions],
            "examples": list(self.examples),
            "links": list(self.links),
            "code_blocks": list(self.code_blocks),
            "sections": list(self.section_names),
        }


def _section_name(text: str) -> str:
    value = _EMPHASIS.sub("", text).strip().lower()
    value = re.sub(r"[^a-z0-9 ]+", " ", value)
    return re.sub(r"\s+", " ", value).strip() or "body"


def _is_non_instruction_section(section: str) -> bool:
    return any(key in section for key in _NON_INSTRUCTION_SECTIONS)


def _is_instruction_section(section: str) -> bool:
    return (not _is_non_instruction_section(section)
            and any(key in section for key in _INSTRUCTION_SECTIONS))


def _looks_like_command(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if stripped[0] in "$>":
        return True
    if stripped.startswith("```") or (
            stripped.startswith("`") and stripped.endswith("`")):
        return True
    first = re.split(r"\s+", stripped, maxsplit=1)[0].strip("`'\"")
    if first in _SHELL_COMMANDS:
        return True
    if "&&" in stripped or "||" in stripped:
        return True
    return False


def _strip_inline(text: str) -> tuple[str, list[tuple[str, str]]]:
    links: list[tuple[str, str]] = []

    def link_repl(match):
        links.append((match.group(1), match.group(2)))
        return match.group(1)

    value = _INLINE_LINK.sub(link_repl, text)
    for match in _BARE_URL.finditer(value):
        links.append((match.group(0), match.group(0)))
    value = _INLINE_CODE.sub(r"\1", value)
    value = _HTML_TAG.sub("", value)
    value = _EMPHASIS.sub("", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value, links


def _bound(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_BLOCK_CHARS:
        return text, False
    return text[:MAX_BLOCK_CHARS].rstrip(), True


def _starts_block(line: str, next_line: str | None = None) -> bool:
    return bool(
        _FENCE.match(line) or _HEADING.match(line) or _LIST.match(line)
        or _QUOTE.match(line) or _THEMATIC.match(line) or _HTML.match(line)
        or _LINK_DEF.match(line))


def parse_markdown(body: str) -> ParsedSkillMarkdown:
    """Parse one bounded Markdown body into structured blocks."""
    if _CONTROL.search(body):
        raise MarkdownError("markdown_control_characters")
    lines = body.splitlines()
    blocks: list[MarkdownBlock] = []
    headings: list[dict] = []
    links: list[tuple[str, str]] = []
    code_blocks: list[dict] = []
    section = "body"
    index = 0
    total = len(lines)

    def add(block: MarkdownBlock) -> None:
        if len(blocks) >= MAX_BLOCKS:
            raise MarkdownError("markdown_too_many_blocks")
        blocks.append(block)

    while index < total:
        line = lines[index]
        start = index + 1
        if not line.strip():
            index += 1
            continue

        fence = _FENCE.match(line)
        if fence:
            marker, info = fence.group(1), fence.group(2).strip()
            index += 1
            content: list[str] = []
            while index < total:
                closing = re.match(
                    r"^\s{0,3}" + re.escape(marker[0]) + "{" +
                    str(len(marker)) + r",}\s*$", lines[index])
                if closing:
                    index += 1
                    break
                content.append(lines[index])
                index += 1
            text, truncated = _bound("\n".join(content))
            code_blocks.append({"line_start": start,
                                "line_end": index,
                                "info": info,
                                "chars": len(text)})
            add(MarkdownBlock("code", text, start, index, section,
                              info=info, truncated=truncated))
            continue

        heading = _HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            text, heading_links = _strip_inline(heading.group(2))
            links.extend(heading_links)
            section = _section_name(text)
            headings.append({"level": level, "text": text,
                             "line": start})
            add(MarkdownBlock("heading", text, start, start, section,
                              level=level))
            index += 1
            continue

        quote = _QUOTE.match(line)
        if quote:
            content: list[str] = []
            while index < total:
                match = _QUOTE.match(lines[index])
                if not match:
                    break
                value, quote_links = _strip_inline(match.group(1))
                links.extend(quote_links)
                content.append(value)
                index += 1
            text, truncated = _bound("\n".join(content))
            add(MarkdownBlock("quote", text, start, index, section,
                              truncated=truncated))
            continue

        link_def = _LINK_DEF.match(line)
        if link_def:
            links.append((link_def.group(1), link_def.group(2)))
            add(MarkdownBlock("link_def", link_def.group(2), start, start,
                              section))
            index += 1
            continue

        if _HTML.match(line):
            content: list[str] = []
            while index < total and lines[index].strip():
                content.append(lines[index])
                index += 1
            text, truncated = _bound("\n".join(content))
            add(MarkdownBlock("html", text, start, index, section,
                              truncated=truncated))
            continue

        if _THEMATIC.match(line):
            add(MarkdownBlock("thematic_break", "", start, start, section))
            index += 1
            continue

        list_match = _LIST.match(line)
        if list_match:
            indent, marker, raw = list_match.groups()
            text, item_links = _strip_inline(raw)
            links.extend(item_links)
            text, truncated = _bound(text)
            example = _looks_like_command(text)
            add(MarkdownBlock(
                "list_item", text, start, start, section,
                example=example, truncated=truncated))
            index += 1
            continue

        # Table: a header row followed by a separator row.
        if "|" in line and index + 1 < total and \
                _TABLE_SEP.match(lines[index + 1]):
            content = [line]
            index += 1
            while index < total and lines[index].strip():
                content.append(lines[index])
                index += 1
            text, truncated = _bound("\n".join(content))
            add(MarkdownBlock("table", text, start, index, section,
                              truncated=truncated))
            continue

        # Indented code block.
        if line.startswith("    ") or line.startswith("\t"):
            content: list[str] = []
            while index < total and (
                    lines[index].startswith("    ")
                    or lines[index].startswith("\t")
                    or not lines[index].strip()):
                content.append(lines[index][4:] if
                               lines[index].startswith("    ")
                               else lines[index].lstrip("\t"))
                index += 1
            text, truncated = _bound("\n".join(content).strip("\n"))
            code_blocks.append({"line_start": start, "line_end": index,
                                "info": "indented", "chars": len(text)})
            add(MarkdownBlock("code", text, start, index, section,
                              info="indented", truncated=truncated))
            continue

        # Paragraph, possibly a setext heading.
        content = []
        while index < total and lines[index].strip():
            if index > start - 1 and _SETEXT.match(lines[index]) and content:
                marker = _SETEXT.match(lines[index]).group(1)
                level = 1 if marker.startswith("=") else 2
                text, para_links = _strip_inline(" ".join(content))
                links.extend(para_links)
                section = _section_name(text)
                headings.append({"level": level, "text": text,
                                 "line": start})
                add(MarkdownBlock("heading", text, start, index + 1,
                                  section, level=level))
                index += 1
                content = []
                break
            if index > start - 1 and _starts_block(lines[index]):
                break
            value, para_links = _strip_inline(lines[index])
            links.extend(para_links)
            content.append(value)
            index += 1
        if content:
            text, truncated = _bound(" ".join(content))
            add(MarkdownBlock("paragraph", text, start, index, section,
                              truncated=truncated))

    # Build instruction records. Only list items outside code/quotes are
    # candidates; command examples are retained but never active steps.
    records: list[InstructionRecord] = []
    for block in blocks:
        if block.kind != "list_item":
            continue
        active = (not block.example
                  and not _looks_like_command(block.text)
                  and not _is_non_instruction_section(block.section))
        records.append(InstructionRecord(
            text=block.text, line_start=block.line_start,
            line_end=block.line_end, section=block.section,
            kind="example_command" if block.example else "instruction",
            active=active, example=block.example,
            truncated=block.truncated))
    active_records = [record for record in records if record.active]
    steps = tuple(dict.fromkeys(
        record.text[:MAX_STEP_CHARS]
        for record in active_records
        if 3 <= len(record.text) <= MAX_STEP_CHARS))[:MAX_STEPS]
    if not steps and not records:
        # Prose-only skills: bounded fallback paragraphs, never code,
        # quotes, tables or HTML.
        fallback = [
            block.text for block in blocks
            if block.kind == "paragraph"
            and 12 <= len(block.text) <= MAX_STEP_CHARS
            and not _looks_like_command(block.text)]
        steps = tuple(dict.fromkeys(fallback))[:8]
    examples = tuple({
        "text": record.text,
        "line_start": record.line_start,
        "line_end": record.line_end,
        "section": record.section,
        "kind": record.kind,
    } for record in records if record.example)
    unique_links: list[dict] = []
    seen = set()
    for text, url in links:
        key = (text, url)
        if key in seen:
            continue
        seen.add(key)
        unique_links.append({"text": text, "url": url})
        if len(unique_links) >= MAX_LINKS:
            break
    section_names = tuple(dict.fromkeys(
        block.section for block in blocks))
    return ParsedSkillMarkdown(
        blocks=tuple(blocks),
        headings=tuple(headings[:MAX_HEADINGS]),
        instructions=tuple(records),
        steps=steps,
        examples=examples,
        links=tuple(unique_links),
        code_blocks=tuple(code_blocks),
        section_names=section_names,
    )


def instruction_texts(parsed: ParsedSkillMarkdown) -> Iterable[str]:
    return (record.text for record in parsed.instructions)


__all__ = [
    "InstructionRecord",
    "MarkdownBlock",
    "MarkdownError",
    "ParsedSkillMarkdown",
    "MAX_BLOCK_CHARS",
    "MAX_BLOCKS",
    "MAX_STEPS",
    "instruction_texts",
    "parse_markdown",
]
