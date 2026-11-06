#!/usr/bin/env python3
"""Run one live Codex CLI episode through the v3 evidence pipeline.

Copies a base fixture into a disposable directory, drives ``codex exec``
through the observation adapter, appends every normalized event to the
append-only episode store, then hands the post-run tree to the independent
OutcomeVerifier, which injects hidden acceptance tests into a fresh
evaluator-owned workspace and signs an OutcomeReceiptV1.

Usage:
    PYTHONPATH=src python3 scripts/v3/run_codex_episode.py \
        --work-root /tmp/sis-ep --fixture examples/v3/fixtures/buggy_calc \
        --evidence-root /tmp/sis-evidence

The agent never sees the hidden test file or the evaluator directories.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sis.v3.adapters.codex_cli import CodexCliAdapter, CodexCliError  # noqa: E402
from sis.v3.contracts import TaskEnvelopeV1, canonical_digest  # noqa: E402
from sis.v3.episode_store import EpisodeStore  # noqa: E402
from sis.v3.runner import tree_digest  # noqa: E402
from sis.v3.verifier import OutcomeVerifier, verify_receipt_signature  # noqa: E402

PROMPT = (
    "Read the code in this directory. One function returns a value that "
    "does not match the contract in its own docstring. Find it and fix it "
    "with the smallest possible change. Do not add dependencies, do not "
    "create new files, and do not modify README.md."
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-root", required=True, help="disposable agent workspace parent")
    parser.add_argument("--evidence-root", required=True, help="episode store + evaluator dirs")
    parser.add_argument("--fixture", default="examples/v3/fixtures/buggy_calc")
    parser.add_argument("--task-id", default="buggy-calc-001")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--model", default=None)
    args = parser.parse_args()

    fixture = Path(args.fixture).resolve()
    work_root = Path(args.work_root).resolve()
    evidence = Path(args.evidence_root).resolve()
    for path in (work_root, evidence):
        path.mkdir(parents=True, exist_ok=True)

    # Disposable agent workspace: a plain copy; the CLI is told not to run
    # repo hooks (the fixture has none) and its own sandbox confines writes.
    agent_ws = Path(tempfile.mkdtemp(prefix="agent-", dir=work_root))
    for item in fixture.iterdir():
        if item.name == "acceptance_hidden.py":
            continue  # hidden acceptance material never enters the agent view
        if item.is_file():
            shutil.copy2(item, agent_ws / item.name)

    verifier = OutcomeVerifier(
        executor=_local_executor(),
        key_dir=evidence / "evaluator-keys",
        registry_dir=evidence / "evaluator-registry",
    )
    hidden_test = (fixture / "acceptance_hidden.py").read_bytes()
    verifier.register_task(
        actor_role="evaluator",
        task_id=args.task_id,
        criterion_version="buggy-calc-acceptance-v1",
        argv=(sys.executable, "-m", "unittest", "acceptance_hidden", "-v"),
        files={"acceptance_hidden.py": hidden_test},
    )

    store = EpisodeStore(evidence / "episodes")
    task = TaskEnvelopeV1(
        schema_version=1,
        task_id=args.task_id,
        repo_snapshot_digest=tree_digest(agent_ws),
        base_commit=None,
        task_statement_digest=canonical_digest("task_statement", 1, {"prompt_sha256": hashlib.sha256(PROMPT.encode()).hexdigest()}),
        permitted_commands=("python3",),
        isolation_profile="unverified_local",
        time_budget_seconds=args.timeout,
        token_budget=1_000_000,
        tool_budget=500,
        actor_id="codex-cli",
        evaluator_task_ref=args.task_id,
    )

    events_seen = 0
    episode_id = None
    with CodexCliAdapter(wall_seconds=args.timeout) as adapter:
        turn = adapter.start_task(PROMPT, agent_ws, model=args.model, sandbox="workspace_write")
        for event in turn.events:
            episode_id = event.episode_id
            store.append_event(event)
            events_seen += 1

    if episode_id is None:
        print(json.dumps({"ok": False, "error": "no events captured"}))
        return 1

    verification = store.verify_episode(episode_id)
    anchor = store.anchor_head(episode_id, evidence / "anchors")

    receipt = verifier.evaluate(
        actor_role="evaluator",
        task=task,
        submission_dir=agent_ws,
        evaluation_nonce="nonce-" + secrets.token_hex(8),
    )
    pub = verifier.public_key_record()
    offline_ok = verify_receipt_signature(receipt, pub["public_key"])

    print(json.dumps({
        "ok": True,
        "episode_id": episode_id,
        "events": events_seen,
        "episode_verify": verification["ok"],
        "head_digest": anchor["head_digest"],
        "outcome": receipt.outcome,
        "receipt_digest": receipt.digest,
        "signer_key_id": receipt.signer_key_id,
        "signature_verified_offline": offline_ok,
        "evaluated_repo_digest": receipt.evaluated_repo_digest,
        "agent_workspace": str(agent_ws),
    }, indent=2, sort_keys=True))
    return 0


def _local_executor():
    from sis.v3.runner import LocalSubprocessExecutor
    return LocalSubprocessExecutor(use_seatbelt=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CodexCliError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        raise SystemExit(2)
