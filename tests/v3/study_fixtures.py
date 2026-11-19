"""Temporary Git repositories with a bug-fix history, for study-tool tests.

Each repository has a base commit with ``N`` buggy functions and a passing
public test, then one fix commit per function that corrects it and adds a
test file covering it — the shape ``tools/import_study_tasks.py`` turns
into tasks (parent = base, the fix's test = hidden acceptance).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

GIT_IDENTITY = ("-c", "user.name=SIS", "-c", "user.email=sis@example.invalid")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True,
        text=True).stdout.strip()


def commit(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, *GIT_IDENTITY, "commit", "-qm", message)
    return git(repo, "rev-parse", "HEAD")


def buggy_source(name: str, fixed: set[int], count: int) -> str:
    lines = []
    for index in range(count):
        # The bug: a subtraction where the contract needs an addition.
        operator = "+" if index in fixed else "-"
        lines.append(
            f"def {name}_f{index}(x):\n    return x {operator} {index + 1}\n")
    return "\n\n".join(lines)


def apply_fix(workspace: Path, name: str, index: int) -> bool:
    """What a correct agent does for task ``index``: flip its operator."""
    module = workspace / f"mod_{name}.py"
    text = module.read_text()
    marker = f"def {name}_f{index}(x):\n    return x - {index + 1}\n"
    if marker not in text:
        return False
    module.write_text(text.replace(
        marker, f"def {name}_f{index}(x):\n    return x + {index + 1}\n"))
    return True


def make_bugfix_repository(path: Path, name: str, *, fixes: int = 2,
                           origin: str | None = None) -> dict:
    """Create the repository and return its commits.

    ``fix_commits[i]`` fixes ``<name>_f<i>`` (``x - (i+1)`` becomes
    ``x + (i+1)``, a single operator substitution) and adds
    ``tests/test_f<i>.py``. The checkout is left
    at the last fix with ``origin`` and a remote-tracking ref, so the
    manifest provenance checks accept it.
    """
    path.mkdir(parents=True)
    git(path, "init", "-q")
    module = f"mod_{name}.py"
    (path / module).write_text(buggy_source(name, set(), fixes))
    (path / "tests").mkdir()
    (path / "tests" / "test_public.py").write_text(
        f"from mod_{name} import {name}_f0\n\n"
        "def test_callable():\n"
        f"    assert callable({name}_f0)\n")
    base = commit(path, "Initial layout")
    fixed: set[int] = set()
    fix_commits = []
    for index in range(fixes):
        fixed.add(index)
        (path / module).write_text(buggy_source(name, fixed, fixes))
        (path / "tests" / f"test_f{index}.py").write_text(
            f"from mod_{name} import {name}_f{index}\n\n"
            f"def test_f{index}():\n"
            f"    assert {name}_f{index}(1) == {index + 2}\n")
        fix_commits.append(commit(
            path, f"Fix {name}_f{index} returning the wrong value\n\n"
                  f"{name}_f{index}(x) must return x + {index + 1}."))
    origin = origin or f"https://example.invalid/{name}.git"
    git(path, "remote", "add", "origin", origin)
    head = git(path, "rev-parse", "HEAD")
    git(path, "update-ref", "refs/remotes/origin/main", head)
    return {"path": path, "base": base, "fix_commits": fix_commits,
            "head": head, "origin": origin, "module": module}


def fix_target(prompt: str) -> tuple[str, int] | None:
    """``(name, index)`` named by an imported task's prompt, if any."""
    import re
    match = re.search(r"Fix (\w+)_f(\d+) returning", prompt)
    return (match.group(1), int(match.group(2))) if match else None


def make_plain_repository(path: Path, name: str) -> dict:
    """A one-commit repository (an induction repository with no tasks)."""
    path.mkdir(parents=True)
    git(path, "init", "-q")
    (path / f"seed_{name}.py").write_text(f"SEED = {name!r}\n")
    head = commit(path, "seed")
    origin = f"https://example.invalid/{name}.git"
    git(path, "remote", "add", "origin", origin)
    git(path, "update-ref", "refs/remotes/origin/main", head)
    return {"path": path, "head": head, "origin": origin}


def load_tool(name: str):
    """Import ``tools/<name>.py`` as a module."""
    import importlib.util
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        f"sis_tool_{name}", root / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def study_spec(*, agent_kind: str = "claude-code", tasks: int,
               budget: dict | None = None,
               kind: str = "primary_contrast_study_spec") -> dict:
    """An exploratory, powered A/E study spec without repositories yet."""
    budget = budget or {"wall_seconds": 60, "token_budget": 150_000,
                        "tool_budget": 100}
    return {
        "schema_version": 1,
        "kind": kind,
        "study_tier": "exploratory",
        "protocol": {
            "primary_metric": "paired solved_delta E vs A",
            "method": "repository_sign_flip_exact",
            "alpha": 0.05, "min_effect": 1.0, "sample_size": tasks,
            "budget": dict(budget),
            "arms": ["A", "E"] if kind == "primary_contrast_study_spec"
            else ["A", "B", "C", "D", "E"],
            "powered": True, "expected_baseline": 0.01,
            "expected_treatment": 0.99, "power": 0.8,
        },
        "agent": {"kind": agent_kind, "model": "test-model",
                  "cli_version": "2.1.328"},
        "preregistration": {"registered_at": "2026-11-14T00:00:00Z",
                            "registered_by": "test"},
        "repositories": [],
        "tasks": [],
    }


def import_repository(importer, repo_path: Path, repository_id: str, *,
                      partition: str, hidden_dir: Path, output: Path,
                      merge_into: Path | None = None,
                      learning_split: str = "training",
                      verify: str = "local") -> int:
    """Run ``tools/import_study_tasks.py`` on one repository."""
    import contextlib
    import io
    import sys
    argv = ["--repo", str(repo_path), "--repository-id", repository_id,
            "--partition", partition, "--hidden-dir", str(hidden_dir),
            "--learning-split", learning_split,
            "--verify", verify, "--python", sys.executable,
            "-o", str(output)]
    if merge_into is not None:
        argv += ["--merge-into", str(merge_into)]
    if verify == "local":
        argv.append("--allow-shared-custody")
    with contextlib.redirect_stdout(io.StringIO()):
        return importer.main(argv)


def imported_study(root: Path, *, holdout: int = 5, induction: int = 5,
                   fixes: int = 2, agent_kind: str = "claude-code") -> dict:
    """Bug-fix repositories imported into a ready-to-build study spec.

    Holdout repositories carry imported tasks (verified locally: base
    fails, fix passes); induction repositories are plain. Returns
    ``{"spec_path", "spec", "repos", "importer"}``.
    """
    import json
    importer = load_tool("import_study_tasks")
    spec_path = root / "spec.json"
    spec = study_spec(agent_kind=agent_kind, tasks=holdout * fixes)
    for index in range(induction):
        repo = make_plain_repository(root / "repos" / f"ind{index}",
                                     f"ind{index}")
        spec["repositories"].append({
            "repository_id": f"induction-{index}",
            "path": str(repo["path"]), "partition": "induction"})
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    repos = {}
    for index in range(holdout):
        name = f"hold{index}"
        repos[name] = make_bugfix_repository(
            root / "repos" / name, name, fixes=fixes)
        code = import_repository(
            importer, repos[name]["path"], f"holdout-{index}",
            partition="holdout", hidden_dir=root / "private" / name,
            output=root / "imports" / f"{name}.json", merge_into=spec_path)
        if code != 0:
            raise AssertionError(f"import of {name} failed")
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    return {"spec_path": spec_path, "spec": spec, "repos": repos,
            "importer": importer}
