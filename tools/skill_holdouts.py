"""Holdout registry for the v3 skill qualification template.

Each entry is one worked example: a skill, a fixture repo in its buggy
state, an evaluator-private acceptance test, the artifact a guided agent
writes, and a keyword that appears in the skill's own steps (the scripted
stand-in only writes the artifact when the served guidance carries it).

Adding a skill is data only — add a ``Holdout`` here and the tool and its
tests pick it up. ``PLANNED`` records the triage for skills not yet wired;
``EXCLUDED`` records why a skill cannot be honestly tested offline.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Holdout:
    """One worked example: a skill, a fixture repo and a private test."""

    skill: str
    task_id: str
    statement: str
    keyword: str
    fixture: dict
    good: dict
    test: str
    tier: str = "A"


WRITE_SKILL = Holdout(
    skill="write-skills",
    task_id="task-write-skill",
    statement=("Write a reusable agent skill that formats currency amounts "
               "with half-up rounding and a fixed two-decimal string."),
    keyword="description",
    fixture={
        "README.md": (
            "# Currency skill\n\n"
            "Write a reusable skill for formatting money in Python.\n"
            "The skill file must be `SKILL.md` at the repo root.\n"),
        "SKILL.md": "# currency-skill\n\nDo the rounding thing.\n",
    },
    good={
        "SKILL.md": (
            "---\n"
            "name: currency-format\n"
            "description: Use when formatting currency amounts for output.\n"
            "---\n\n"
            "# Currency format\n\n"
            "## Workflow\n\n"
            "- Use Decimal with ROUND_HALF_UP.\n"
            "- Return a two-decimal string.\n"),
    },
    test=(
        "from pathlib import Path\n\n"
        "def test_frontmatter():\n"
        "    text = Path('SKILL.md').read_text()\n"
        "    assert text.startswith('---')\n"
        "    assert 'name:' in text\n"
        "    assert 'description:' in text\n\n"
        "def test_body():\n"
        "    text = Path('SKILL.md').read_text()\n"
        "    assert '## ' in text\n"
        "    assert '- ' in text\n"),
)

PHP_CHECK = Holdout(
    skill="php2shell-check",
    task_id="task-php-exposure",
    statement="Assess this service's PHP exposure and pin a fixed runtime.",
    keyword="8.4.27",
    fixture={
        "Dockerfile": "FROM php:8.4-fpm\nCOPY app /app\nWORKDIR /app\n",
        "app/index.php": "<?php echo 'ok';\n",
    },
    good={
        "Dockerfile": "FROM php:8.4.27-fpm\nCOPY app /app\nWORKDIR /app\n",
        "findings.md": (
            "# PHP exposure\n\n"
            "- php2shell: CVE-2026-109618 and CVE-2026-109619 affect every "
            "web SAPI on 8.4 below 8.4.27.\n"
            "- Pinned php:8.4.27-fpm; rebuild with --pull --no-cache and "
            "restart workers.\n"),
    },
    test=(
        "from pathlib import Path\n\n"
        "def test_pinned_fixed_tag():\n"
        "    text = Path('Dockerfile').read_text()\n"
        "    assert 'php:8.4.27' in text\n"
        "    assert 'php:8.4-fpm' not in text\n\n"
        "def test_findings_name_the_cve():\n"
        "    text = Path('findings.md').read_text()\n"
        "    assert 'CVE-2026-109618' in text\n"
        "    assert '8.4.27' in text\n"),
)

WRITE_TESTS = Holdout(
    skill="write-tests",
    task_id="task-write-tests",
    statement=("Add a test suite for average() that pins its real behavior, "
               "not the current implementation."),
    keyword="behavior",
    fixture={
        "README.md": (
            "# Calculator\n\n"
            "`calc.average(values)` returns the mean of the values.\n"
            "Add `test_calc.py` pinning its behavior.\n"),
        "calc.py": (
            "def average(values):\n"
            "    return sum(values) / len(values)\n"),
    },
    good={
        "test_calc.py": (
            "import pytest\n\n"
            "from calc import average\n\n\n"
            "def test_average_mean():\n"
            "    assert average([1, 2, 3]) == 2\n\n\n"
            "def test_average_keeps_fraction():\n"
            "    assert average([1, 2]) == 1.5\n\n\n"
            "def test_average_empty_rejected():\n"
            "    with pytest.raises(ZeroDivisionError):\n"
            "        average([])\n"),
    },
    test=(
        "import shutil\n"
        "import subprocess\n"
        "import sys\n"
        "import tempfile\n"
        "from pathlib import Path\n\n"
        "MUTATION = (\n"
        "    'def average(values):\\n'\n"
        "    '    return sum(values) // len(values)\\n')\n\n\n"
        "def _run(tree):\n"
        "    return subprocess.run(\n"
        "        [sys.executable, '-m', 'pytest', '-q',\n"
        "         '-p', 'no:cacheprovider', 'test_calc.py'],\n"
        "        cwd=tree, capture_output=True, text=True)\n\n\n"
        "def test_tests_pin_behavior():\n"
        "    tree = Path.cwd()\n"
        "    suite = tree / 'test_calc.py'\n"
        "    assert suite.is_file(), 'no test_calc.py was written'\n"
        "    assert suite.read_text().count('def test_') >= 2, (\n"
        "        'the suite needs at least two behavioral tests')\n"
        "    with tempfile.TemporaryDirectory() as temp:\n"
        "        original = Path(temp) / 'original'\n"
        "        mutated = Path(temp) / 'mutated'\n"
        "        for target in (original, mutated):\n"
        "            target.mkdir()\n"
        "            for name in ('calc.py', 'test_calc.py'):\n"
        "                shutil.copy2(tree / name, target / name)\n"
        "        (mutated / 'calc.py').write_text(MUTATION)\n"
        "        good = _run(original)\n"
        "        assert good.returncode == 0, good.stdout + good.stderr\n"
        "        bad = _run(mutated)\n"
        "        assert bad.returncode != 0, (\n"
        "            'the tests did not catch a changed implementation')\n"),
)

HOLDOUTS = (WRITE_SKILL, PHP_CHECK, WRITE_TESTS)

# Triage for skills that are testable but not wired yet.
PLANNED = {
    "implement-spec": "A",
    "code-review": "A",
    "agents-md-author": "A",
    "audit-agents": "B",
    "audit-tests": "B",
    "audit-choices": "B",
    "audit-performance": "B",
    "auto-research": "B",
    "close-spec": "B",
    "eli5": "B",
    "explore-unknowns": "B",
    "handoff-spec": "B",
    "marketing-pages": "B",
    "ratchet-files": "B",
    "refactor-clean": "B",
    "retro": "B",
    "review": "B",
    "write-docs": "B",
    "write-spec": "B",
}

# Skills that cannot be honestly tested offline, with the reason.
EXCLUDED = {
    "claude": "harness-dependent (spawns claude -p)",
    "codex": "harness-dependent (spawns the Codex CLI)",
    "implement-spec-with-codex": "harness-dependent (delegates to Codex)",
    "implement-spec-with-goal": "harness-dependent (needs the goal feature)",
    "eval-skills": "harness-dependent (runs blind subagents)",
    "preview-shots": "macOS Preview GUI only",
    "cinematic-shot": "media production; no text artifact",
    "launch-video": "media production; no text artifact",
    "renderer": "GPU/WebGPU architecture; not offline-testable",
    "xiaohei-illustrations": "image generation; no text artifact",
    "isometric-motion": "exceeds the candidate record bound (33 KB body)",
    "compare-screenshots": "browser/screenshot toolchain",
    "design-with-images": "image generation",
    "screenshot-critique": "browser/screenshot toolchain",
    "tournament-manager": "external platform (EasyChamp API)",
    "figma-connect": "external service (Figma MCP)",
    "frontend-design": "visual verification in a browser",
    "scrollcraft-layout": "visual verification in a browser",
    "task-skill-announcer": "behavioral only; no observable artifact",
    "gws": "external service (Google Workspace)",
    "apify-data-gathering": "external service (Apify)",
    "blotato": "external service (Blotato API)",
    "kie-gemini-omni": "external service (Kie AI)",
    "slack-messaging": "external service (Slack API)",
    "appstore": "external service (App Store Connect)",
    "greet-anton-abyzov": "advisory only; no observable artifact",
    "obsidian-brain": "local vault dependency",
    "stripe-refund-auditor": "external service (Stripe API)",
    "tax-filing": "external services and local data (Xero/Gmail/Drive)",
    "survey-passing": "external expert-network platforms",
    "scout": "external catalog (verified-skill.com); installs skills",
    "social-media-posting": "exceeds the record bound; external APIs",
    "skill-builder": "harness-dependent (vskill CLI/Studio or Claude)",
}


def registered_names() -> tuple[str, ...]:
    return tuple(holdout.skill for holdout in HOLDOUTS)


def by_name(name: str) -> Holdout | None:
    return next((holdout for holdout in HOLDOUTS
                 if holdout.skill == name), None)


def select(*, tier: str | None = None,
           only: str | None = None) -> tuple[Holdout, ...]:
    """Return the registered holdouts matching ``--tier``/``--only``."""
    selected = HOLDOUTS
    if tier is not None:
        selected = tuple(h for h in selected if h.tier == tier)
    if only is not None:
        selected = tuple(h for h in selected if h.skill == only)
    return selected


def describe() -> dict:
    """Machine-readable registry view for ``--list``."""
    return {
        "registered": [
            {"skill": h.skill, "tier": h.tier, "task_id": h.task_id,
             "keyword": h.keyword, "fixture_files": sorted(h.fixture),
             "guided_files": sorted(h.good)}
            for h in HOLDOUTS],
        "planned": dict(sorted(PLANNED.items())),
        "excluded": dict(sorted(EXCLUDED.items())),
    }
