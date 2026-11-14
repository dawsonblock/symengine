"""Subprocess evaluator: signing custody in a separate OS process.

``evaluate_via_subprocess`` spawns ``python -m sis.v3.evaluator_worker``
which constructs its own ``OutcomeVerifier`` inside the child, loads the
evaluator seed there, runs the acceptance command in a fresh executor
workspace, and writes the signed ``OutcomeReceiptV1``/``V2`` to a caller-specified
path. The caller's process never touches the seed; memory-space separation
is real, though both processes share one OS principal — a stronger custodial
split still requires a separate service account or host.

The worker executes submitted code in the Docker sandbox by default. Local
subprocess execution is development-only and requires an explicit
``allow_local_executor=True`` from the caller (or ``--allow-local-executor``
on the CLI).

``split_user`` (CLI ``--split-user``) configures the second numeric Docker
identity that process-split custody needs; without it the Docker backend
declares no split capability and a split task fails closed. Configuring it
also turns on ``require_split_custody`` for the worker's verifier, so a task
that hides acceptance files behind shared custody is refused instead of
graded beside the tests.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    OutcomeReceiptV2,
    TaskEnvelopeV1,
    loads_json,
    parse_outcome_receipt,
)


class EvaluatorWorkerError(RuntimeError):
    """The worker could not produce a receipt."""


@dataclass(frozen=True)
class WorkerResult:
    receipt: OutcomeReceiptV1 | OutcomeReceiptV2
    exit_status: int
    stderr_tail: str


def build_worker_executor(
    *,
    executor: str = "docker",
    executor_root: str | Path | None = None,
    sandbox_image: str | None = None,
    allow_local_executor: bool = False,
    require_image_digest: bool = True,
    split_user: str | None = None,
):
    """Construct the worker's executor; local execution is opt-in.

    Docker is the default because submitted code is hostile by assumption.
    A local subprocess is a development convenience, never a containment
    boundary, and is refused unless the caller says so explicitly.

    ``split_user`` names the second Docker identity used by process-split
    custody. The local backend's split boundary is a seatbelt read denial,
    not a second UID, so a split user is refused there rather than
    silently ignored.
    """
    if executor not in {"docker", "local"}:
        raise ContractError("executor must be 'docker' or 'local'")
    if executor == "local":
        if split_user is not None:
            raise EvaluatorWorkerError(
                "split_user_requires_docker_executor")
        if not allow_local_executor:
            raise EvaluatorWorkerError(
                "local_executor_requires_explicit_authorization")
        from .runner import LocalSubprocessExecutor
        return LocalSubprocessExecutor(executor_root)
    if not isinstance(sandbox_image, str) or not sandbox_image:
        raise EvaluatorWorkerError("sandbox_image_required")
    from .docker_sandbox import DockerSandboxExecutor
    return DockerSandboxExecutor(
        executor_root, image=sandbox_image,
        require_image_digest=require_image_digest, split_user=split_user)


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
    executor: str = "docker",
    sandbox_image: str | None = None,
    allow_local_executor: bool = False,
    require_image_digest: bool = True,
    split_user: str | None = None,
    require_split_custody: bool = False,
) -> WorkerResult:
    """Evaluate a submission in a child process; returns the signed receipt."""
    if not isinstance(task, TaskEnvelopeV1):
        task = TaskEnvelopeV1.from_dict(task)
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ContractError("timeout out of range")
    if executor not in {"docker", "local"}:
        raise ContractError("executor must be 'docker' or 'local'")
    if split_user is not None and executor != "docker":
        raise EvaluatorWorkerError("split_user_requires_docker_executor")
    if executor == "local" and not allow_local_executor:
        raise EvaluatorWorkerError(
            "local_executor_requires_explicit_authorization")
    if executor == "docker" and not sandbox_image:
        raise EvaluatorWorkerError("sandbox_image_required")
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
        "--executor", executor,
    ]
    if sandbox_image is not None:
        argv += ["--sandbox-image", sandbox_image]
    if allow_local_executor:
        argv += ["--allow-local-executor"]
    if not require_image_digest:
        argv += ["--allow-tagged-image"]
    if split_user is not None:
        argv += ["--split-user", split_user]
    if require_split_custody:
        argv += ["--require-split-custody"]
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
        receipt = parse_outcome_receipt(loads_json(out_path.read_bytes()))
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
    parser.add_argument("--executor", choices=("docker", "local"),
                        default="docker")
    parser.add_argument("--sandbox-image", default=None)
    parser.add_argument("--allow-local-executor", action="store_true")
    parser.add_argument("--allow-tagged-image", action="store_true")
    parser.add_argument("--split-user", default=None,
                        help="second numeric uid[:gid] for split custody")
    parser.add_argument("--require-split-custody", action="store_true",
                        help="refuse private acceptance material under"
                             " shared custody")
    args = parser.parse_args()

    if args.task_json == "-":
        raw = sys.stdin.buffer.read(65_537)
    else:
        raw = Path(args.task_json).read_bytes()
    task = TaskEnvelopeV1.from_json(raw)

    from .runner import RunnerError
    from .verifier import EvaluationRejected, JournalIntegrityError, OutcomeVerifier

    try:
        executor = build_worker_executor(
            executor=args.executor,
            executor_root=args.executor_root,
            sandbox_image=args.sandbox_image,
            allow_local_executor=args.allow_local_executor,
            require_image_digest=not args.allow_tagged_image,
            split_user=args.split_user,
        )
    except (ContractError, EvaluatorWorkerError, RunnerError) as exc:
        print(f"executor_unavailable: {exc}", file=sys.stderr)
        return 2
    require_split = args.require_split_custody or args.split_user is not None
    try:
        verifier = OutcomeVerifier(
            executor=executor, key_dir=args.key_dir,
            registry_dir=args.registry_dir,
            require_split_custody=require_split,
        )
    except (ContractError, JournalIntegrityError, RunnerError) as exc:
        print(f"evaluator_configuration_invalid: {exc}", file=sys.stderr)
        return 2
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
