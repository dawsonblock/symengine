"""Subprocess evaluator: signing custody in a separate OS process.

``evaluate_via_subprocess`` spawns ``python -m sis.v3.evaluator_worker``
which constructs its own ``OutcomeVerifier`` inside the child, loads the
evaluator seed there, runs the acceptance command in a fresh executor
workspace, and writes the signed ``OutcomeReceiptV1`` to a caller-specified
path. The caller's process never touches the seed; memory-space separation
is real, though both processes share one OS principal — a stronger custodial
split still requires a separate service account or host.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .contracts import ContractError, OutcomeReceiptV1, TaskEnvelopeV1


class EvaluatorWorkerError(RuntimeError):
    """The worker could not produce a receipt."""


@dataclass(frozen=True)
class WorkerResult:
    receipt: OutcomeReceiptV1
    exit_status: int
    stderr_tail: str


def evaluate_via_subprocess(
    *,
    key_dir: str | Path,
    registry_dir: str | Path,
    task: TaskEnvelopeV1,
    submission_dir: str | Path,
    evaluation_nonce: str,
    executor_root: str | Path | None = None,
    timeout: int = 180,
    python: str = sys.executable,
) -> WorkerResult:
    """Evaluate a submission in a child process; returns the signed receipt."""
    if not isinstance(task, TaskEnvelopeV1):
        task = TaskEnvelopeV1.from_dict(task)
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ContractError("timeout out of range")
    for name, value in (("key_dir", key_dir), ("registry_dir", registry_dir),
                        ("submission_dir", submission_dir)):
        path = Path(value)
        if not path.is_dir():
            raise EvaluatorWorkerError(f"{name} must be an existing directory")

    out_dir = Path(tempfile.mkdtemp(prefix="eval-receipt-"))
    out_path = out_dir / "receipt.json"
    src_root = str(Path(__file__).resolve().parents[2])
    env = {"PYTHONPATH": src_root}
    for name in ("HOME", "PATH", "TMPDIR", "LANG", "SYSTEMROOT"):
        if os.environ.get(name):
            env[name] = os.environ[name]

    argv = [
        python, "-m", "sis.v3.evaluator_worker",
        "--key-dir", str(key_dir),
        "--registry-dir", str(registry_dir),
        "--submission", str(submission_dir),
        "--nonce", evaluation_nonce,
        "--receipt-out", str(out_path),
    ]
    if executor_root is not None:
        argv += ["--executor-root", str(executor_root)]
    argv += ["--task-json", "-"]  # task arrives on stdin, bounded

    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, env=env, start_new_session=True,
        )
    except OSError as exc:
        raise EvaluatorWorkerError(f"worker launch failed: {exc}") from exc
    try:
        _, stderr = proc.communicate(task.canonical_bytes(), timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()
        proc.wait()
        raise EvaluatorWorkerError("worker timed out") from None
    tail = stderr.decode("utf-8", "replace")[-512:]
    if proc.returncode != 0:
        raise EvaluatorWorkerError(f"worker exited {proc.returncode}: {tail.strip()}")
    try:
        receipt = OutcomeReceiptV1.from_json(out_path.read_bytes())
    except (OSError, ContractError) as exc:
        raise EvaluatorWorkerError("worker produced no valid receipt") from exc
    return WorkerResult(receipt=receipt, exit_status=proc.returncode, stderr_tail=tail)


def _main() -> int:
    parser = argparse.ArgumentParser(prog="sis.v3.evaluator_worker")
    parser.add_argument("--key-dir", required=True)
    parser.add_argument("--registry-dir", required=True)
    parser.add_argument("--submission", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--receipt-out", required=True)
    parser.add_argument("--executor-root", default=None)
    parser.add_argument("--task-json", required=True)
    args = parser.parse_args()

    if args.task_json == "-":
        raw = sys.stdin.buffer.read(65_537)
    else:
        raw = Path(args.task_json).read_bytes()
    task = TaskEnvelopeV1.from_json(raw)

    from .runner import LocalSubprocessExecutor
    from .verifier import EvaluationRejected, OutcomeVerifier

    executor = LocalSubprocessExecutor(args.executor_root)
    verifier = OutcomeVerifier(
        executor=executor, key_dir=args.key_dir, registry_dir=args.registry_dir,
    )
    try:
        receipt = verifier.evaluate(
            actor_role="evaluator",
            task=task,
            submission_dir=args.submission,
            evaluation_nonce=args.nonce,
        )
    except EvaluationRejected as exc:
        print(f"rejected: {exc.reason}", file=sys.stderr)
        return 2
    Path(args.receipt_out).write_bytes(receipt.canonical_bytes())
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
