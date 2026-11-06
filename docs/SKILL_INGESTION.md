# Skill Ingestion Hardening

## Scope-aware identity

v3.3 derived the candidate id from name + content digest. Importing the
same skill for repository family A and family B returned
`already_present` for B, silently preserving A's authorization scope.

v3.3.1 separates:

- **content identity** — `content_digest` over the parsed skill payload
  (including the deterministic security assessment);
- **scope identity** — `canonical_digest("skill_scope", 1, {kind, value})`;
- **candidate artifact id** — slug + content prefix + scope prefix;
- **candidate revision** — the immutable record itself (revision 1 for a
  newly ingested artifact).

Identical content for two scopes produces two candidates, each with its
own `repository_scope`. Re-ingesting the same content and scope is
idempotent. Re-ingesting the same id with different metadata (for
example a different target agent) raises `scope_conflict` instead of
silently reusing the first record.

## Markdown-aware extraction

`sis.v3.skill_markdown` is a bounded, dependency-free parser that
distinguishes:

- headings, paragraphs, list items, tables, HTML blocks, link
  definitions;
- fenced and indented code blocks;
- blockquotes;
- example commands;
- inline links and their targets.

Only list items outside code/quotes, not command examples, and not in
explicitly explanatory sections (`examples`, `background`, `notes`,
`references`, `appendix`, `faq`, …) become active steps. Code examples
never become executable guidance automatically. Each extracted
instruction keeps `line_start`/`line_end` and its section.

## Prompt-injection handling

Imported content is untrusted. The ingester separates:

- parsed text (`instructions`, Markdown metadata);
- candidate instructions (`steps`, `instruction_records`);
- security findings (`security.findings`, severity, location, text
  digest);
- qualification state (`proposed`, never qualified by ingestion).

High-severity findings (prompt-injection phrasing, shell tokens in
served steps) set `auto_qualification_allowed=False`. They do not reject
the artifact outright; evidence is preserved in the candidate payload
and, optionally, an ingestion audit JSONL (`--audit`). A clean scan is
never a qualification.

## Discovery completeness

`discover_skills` returns a list-compatible `SkillDiscoveryResult` with
`complete`, `truncated`, `scanned`, `limit`, `offset` and `next_offset`.
It raises `SkillDiscoveryIncomplete` rather than silently truncating at
500. `discover_skills_page` supports pagination. `ingest_tree` paginates
through every page; an explicit `max_skills` cap marks the report
incomplete.

## Compatibility and supply chain

- frontmatter: quoted values, block scalars, nested metadata, list
  values, missing optional fields, and directory-name fallback when
  `name` is omitted but a frontmatter block exists;
- bodies up to 96 KiB are accepted; the full body SHA-256 is preserved
  and the inlined instruction window is explicitly marked truncated
  after 8 chunks;
- resources: ≤64 files, ≤16 MiB total, ≤8 MiB per file, hashed by
  streaming, executable bit recorded but never executed;
- symlinks, traversal, hidden files, duplicate case-folded paths,
  oversized resources and non-UTF-8 content are refused;
- installation scripts are never run.

The vskill sample corpus was used as a compatibility check: 65 of 66
`SKILL.md` files parse; the single rejection is an `e2e` fixture with a
frontmatter block but no description and only an HTML comment body.
