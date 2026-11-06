# Skill ingestion (v3.3, M10)

Import real agent skills into the governed candidate plane. A skill is a
directory with `SKILL.md` (YAML frontmatter plus a Markdown body) and
optional `references/`, `scripts/` and `assets/` files — the layout used
by the vskill and skills catalogs. Ingestion is **packaging only**: it
creates a `CandidateV1` of type `skill_bundle` at `PROPOSED`. It never
evaluates, qualifies, or serves anything.

```text
skill directory ──parse──> bounded CandidateV1 ──learner──> PROPOSED
                                                             │
                              evaluator: holdout probe + CandidateEvidenceV1
                                                             │
                              operator: CandidateDecisionV1 ──> QUALIFIED
                                                             │
                              GovernedServingGateway ──advisory steps──> agent
```

## CLI

```bash
# one skill, or a tree of skills
python3 tools/ingest_skills.py \
    --skills skills/skills-main/skills \
    --registry candidates.db \
    --scope-kind family_id --scope-value skills \
    -o evidence/skills/ingestion.json

# parse and scan only; no registry write
python3 tools/ingest_skills.py --skills <dir> --scope-kind global --dry-run
```

Exit code is `0` when every discovered skill was accepted (submitted or
already present) and `1` when any skill was rejected; the report always
lists the per-skill reason. Re-running is idempotent: identical content
returns `already_present` with the same digest.

A skill directory, a tree of skill directories, or a vskill-style bundle
(`manifest.json` + `payload.json` + `SHA256SUMS`, see
`skill_package.py`) can be passed. Bundles are re-verified and their
candidate is imported unchanged; scope flags do not apply to them.

## Candidate shape

| field | value |
|---|---|
| `candidate_type` | `skill_bundle` |
| `candidate_id` | `skill-<slug>-<content_digest[:12]>` |
| `content_digest` | `content_digest("skill_bundle", payload)` |
| `generator_identity` | `sis-skill-ingest` (overridable) |
| `repository_scope` | caller-supplied `registry_id` / `family_id` / `global` |
| `source_episode_ids` | empty — a skill is not an evaluated episode |
| `created_at` | `SKILL.md` mtime (UTC), overridable |

Payload keys: `format` (`sis-skill/1`), `name`, `description`,
`version`, `instructions` (paragraph-aligned chunks, each ≤ 4 000 chars
because the v1 contract caps any single JSON string at 4 KiB), `steps`
(the advisory text the gateway composes), `resources` (path, sha256,
bytes — contents are never inlined), `frontmatter` (bounded scalar
extras) and `source` (kind + relative path).

## Bounds (fail closed)

| limit | value | error |
|---|---|---|
| frontmatter | 8 KiB, ≤ 32 keys, values ≤ 1 024 chars | `skill_frontmatter_*` |
| body | 24 KiB, ≤ 8 instruction chunks | `skill_body_too_large` |
| resources | 64 files, 16 MiB hashed total | `skill_too_many_resources` / `skill_resources_too_large` |
| discovery | depth 6, 500 skills | truncated silently at the cap |
| text | UTF-8, no control characters | `skill_not_utf8` / `skill_control_characters` |
| frontmatter syntax | scalar values, quoted scalars, and `>`/`|` block scalars; nested maps/lists are ignored | — |

Symlinks anywhere in a skill (the directory, `SKILL.md`, or any resource)
are refused with `skill_symlink_refused`; hidden files and directories are
ignored. Nothing is executed, imported, or fetched over the network.

## Security posture

- The ingester runs as `learner` (`candidate:write`). It holds no
  signing keys and cannot reach `promotion:approve`.
- A `qualified` status claimed by frontmatter or a bundle manifest is
  ignored: imported skills are always `PROPOSED`.
- `scan_findings` is advisory and recorded in the ingestion report. It
  flags shell-execution tokens in served steps and prompt-injection
  phrasing in the body. A clean scan is not evidence and a flagged skill
  is not refused — served text is data, never a command.
- Qualification still requires signed holdout evidence and an operator
  decision (see `SECURITY_BOUNDARIES_V3_3.md`). Most imported skills have
  no holdout task in the current fixtures and therefore remain `PROPOSED`.

## Worked holdout examples

`tools/skill_holdout.py` is the template for turning an ingested skill into
served guidance. Examples live in the `tools/skill_holdouts.py` registry
(`--list`, `--tier`, `--only`); see `SKILL_HOLDOUTS.md` for the full map.

| example | fixture (buggy state) | private acceptance test |
|---|---|---|
| `write-skills` | `SKILL.md` with no frontmatter | frontmatter has `name`/`description`, body has a heading and a bullet |
| `php2shell-check` | `FROM php:8.4-fpm` (floating, vulnerable) | `Dockerfile` pins `php:8.4.27`, `findings.md` names CVE-2026-109618 |
| `write-tests` | `calc.py` with no tests | the submitted suite passes on the original and fails on a mutated implementation |

```bash
python3 tools/skill_holdout.py \
    --skills-root ../skills/skills-main/skills \
    --skills-root "../skills/vskill-main 2/plugins" \
    -o evidence/skills/holdout.json
```

Per skill it ingests at PROPOSED, moves to EVALUATING, runs a holdout probe
with only that skill's guidance (arm E) and a no-guidance baseline (arm A),
issues `CandidateEvidenceV1` + `CandidateDecisionV1`, qualifies, serves
through the gateway, and records the outcome. The report shows `A=0, E=1`
for every example: the scripted stand-in writes the prescribed artifact only
when the served guidance carries the skill's keyword, so the contrast is
machinery evidence, not a claim about real-agent efficacy.

Keys are test custody generated per run; the acceptance tests stay with the
verifier and never enter the served repository. To add a skill, add a
`Holdout` entry in `tools/skill_holdouts.py`: fixture repo, private test,
the artifact a guided agent writes, and a keyword that appears in the
skill's own steps.

This tool is the v3 candidate holdout template. The older
`sis.skill_holdout` module and `tools/demo_skill_holdout.py` are the v2
HMAC-sealed procedural-skill holdouts; they are unrelated and are not used
by the candidate plane.

## Limits

- Step extraction is a deterministic heuristic: bullet/numbered lines,
  else the first short prose lines. It is not a semantic parse, and the
  full body is retained in `instructions` for audit.
- One skill directory is one candidate. Splitting a large skill into
  smaller skills is the supported way to stay inside the record bound.
- The candidate records resource *digests*, not contents; a deployment
  that needs the files must ship the skill directory alongside the
  registry.
- Ingestion does not schedule evaluation. Running a candidate through the
  harness, issuing `CandidateEvidenceV1` and deciding the transition are
  separate evaluator/operator steps.
