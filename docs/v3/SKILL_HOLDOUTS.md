# Skill holdout registry (v3.3, M10)

`tools/skill_holdouts.py` is the registry behind
`tools/skill_holdout.py`. Each entry is one worked example: a skill, a
fixture repo in its buggy state, an evaluator-private acceptance test, the
artifact a guided agent writes, and a keyword that appears in the skill's
own steps (the deterministic stand-in only writes the artifact when the
served guidance carries it).

Adding a skill is data only — add a `Holdout` and the tool and its tests
pick it up.

## Commands

```bash
# registry view: registered, planned tiers, excluded skills + reasons
python3 tools/skill_holdout.py --list

# every registered example (needs both catalogs)
python3 tools/skill_holdout.py \
    --skills-root ../skills/skills-main/skills \
    --skills-root "../skills/vskill-main 2/plugins" \
    -o evidence/skills/holdout.json

# one example, or one tier
python3 tools/skill_holdout.py --skills-root <root> --only write-tests -o out.json
python3 tools/skill_holdout.py --skills-root <root> --tier A -o out.json
```

Exit `0` only when every selected skill is present, qualified, verifies,
and beats the no-guidance baseline; `1` otherwise; `2` when the selection
names a planned (`holdout_not_registered`), excluded
(`holdout_excluded`) or unregistered tier (`no_registered_holdouts_in_tier`)
entry.

## Registered examples

| skill | tier | fixture (buggy state) | private test asserts | guided artifact |
|---|---|---|---|---|
| `write-skills` | A | `SKILL.md` without frontmatter | `name`/`description` frontmatter, a heading and a bullet | `SKILL.md` |
| `php2shell-check` | A | `FROM php:8.4-fpm` (floating, vulnerable) | pinned `php:8.4.27` and a findings file naming CVE-2026-109618 | `Dockerfile`, `findings.md` |
| `write-tests` | A | `calc.py` with no tests | the submitted suite passes on the original **and fails on a mutated implementation** | `test_calc.py` |

Each example ingests with its own family scope and serves through a repo in
that family, so a serve sees exactly one qualified candidate and the
"delivered steps" check is meaningful.

The `write-tests` entry is a meta-test: it copies only `calc.py` and the
submitted suite into two temp trees, replaces `calc.average` with a
floor-division mutation in one, and requires pass-then-fail. Trivial tests
(`assert True`) and suites that pin the current implementation both fail
it. Because it runs the submitted suite in a nested process, the tool
constructs the verifier with `process_count=None`; on platforms where
`RLIMIT_NPROC` counts every process of the user (macOS), the default
`64` blocks the nested fork. Production evaluators should keep the
default and use a different meta-test strategy.

## Tiers and exclusions

`--list` is authoritative. In short:

- **A** — crisp artifact, offline, objective. Registered: the three
  above. Planned: `implement-spec`, `code-review`, `agents-md-author`.
- **B** — structural report/spec artifacts, weaker but testable. Planned:
  `write-spec`, `close-spec`, `handoff-spec`, `retro`, `write-docs`,
  `audit-agents`, `audit-tests`, `audit-choices`, `audit-performance`,
  `auto-research`, `explore-unknowns`, `marketing-pages`,
  `ratchet-files`, `refactor-clean`, `review`.
- **Excluded** — with a reason each: external services (`gws`,
  `slack-messaging`, `blotato`, `apify-data-gathering`, `kie-gemini-omni`,
  `appstore`, `stripe-refund-auditor`, `survey-passing`,
  `tournament-manager`, `figma-connect`), media/visual production,
  harness-dependent skills (`codex`, `claude`, `implement-spec-with-*`,
  `eval-skills`, `preview-shots`), advisory-only skills
  (`greet-anton-abyzov`, `task-skill-announcer`), local-vault dependencies
  (`obsidian-brain`, `tax-filing`), and skills over the candidate record
  bound (`isometric-motion`, `social-media-posting`).

## Adding an entry

```python
NEW_SKILL = Holdout(
    skill="<frontmatter name>",
    task_id="task-<unique>",
    statement="<what the fixture asks for>",
    keyword="<a word that appears in the skill's steps>",
    fixture={"path": "buggy content"},
    good={"path": "what a guided agent writes"},
    test="<evaluator-private pytest source>",
    tier="A",
)
HOLDOUTS = (..., NEW_SKILL)
```

Rules:

1. The private test must fail on `fixture` alone and pass on
   `fixture + good`; the CLI tests exercise every registered entry.
2. The keyword must survive `compose_guidance` (it is the served text, not
   the whole body). If a skill edit drops it, the example stops passing —
   which is the intended drift alarm.
3. No network, no credentials, deterministic fixtures, bounded runtime.
4. One task per skill is a smoke test, not a powered measurement. Add a
   second task before treating a pass rate as evidence.

## Limits

The agent is a deterministic stand-in and the keys are test custody: this
proves the pipeline, not that a real model follows the skill. See
`V33_LIMITATIONS.md`.
