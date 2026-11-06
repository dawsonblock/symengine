#!/usr/bin/env python3
"""Migrate V2 JSONL authority state into the transactional AuthorityDB.

Reads ``procedures.jsonl`` (catalog intake log) and ``decisions.jsonl``
(legacy signed-decision journal) and reconciles them into a single SQLite
authority store.

- ``--dry-run`` (default): analysis only — nothing is written except the
  report. Every historical qualified revision must reconcile with a verified
  decision; anything else is listed for quarantine, never grandfathered.
- ``--execute``: build the target AuthorityDB, import seeds and committed
  decisions in chain order, write quarantined rows, then run the same
  integrity + signature verification a PromotionController would on cold
  open. The run refuses to certify a store that fails verification.
- ``--cutover``: after a successful --execute, rename the legacy files to
  ``*.migrated`` and keep byte-identical copies under an immutable backup
  directory — reversible by renaming back and deleting the new database.

Reports are canonical JSON; pass ``--signing-key <hex-seed-file>`` to sign
the report with Ed25519 (required for --execute/--cutover).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sis.v3 import signatures  # noqa: E402
from sis.v3.authority_db import AuthorityDB, AuthorityError  # noqa: E402
from sis.v3.contracts import (  # noqa: E402
    ContractError,
    ProcedureRecordV1,
    PromotionDecisionV1,
    PromotionDecisionV2,
    canonical_json,
    loads_json,
)
from sis.v3.promotion import PromotionController  # noqa: E402

_SEED_STATUSES = frozenset({"draft", "candidate"})
_MAX_LINE = 128 * 1024


def _load_catalog(path: Path) -> tuple[list[dict], list[str]]:
    """Parse the legacy catalog log; verify record digests + hash chain."""
    entries, problems = [], []
    prior = None
    if not path.exists():
        return entries, [f"catalog_missing:{path}"]
    for position, raw in enumerate(path.read_bytes().splitlines()):
        if len(raw) > _MAX_LINE:
            problems.append(f"oversize_catalog_line:{position}")
            continue
        try:
            entry = loads_json(raw)
            if set(entry) != {"record", "record_digest", "prior_record_digest"}:
                raise ContractError("shape")
            record = ProcedureRecordV1.from_dict(entry["record"])
        except ContractError:
            problems.append(f"undecodable_catalog_entry:{position}")
            continue
        if record.digest != entry["record_digest"]:
            problems.append(f"catalog_digest_mismatch:{position}")
        if entry["prior_record_digest"] != prior:
            problems.append(f"catalog_chain_break:{position}")
        prior = hashlib.sha256(raw).hexdigest()
        entries.append({"position": position, "record": record,
                        "record_digest": entry["record_digest"], "line_sha256": prior})
    return entries, problems


def _load_decisions(path: Path) -> tuple[list[dict], list[str]]:
    """Parse the legacy decision journal; verify decision digests + chain."""
    entries, problems = [], []
    prior = None
    if not path.exists():
        return entries, problems  # an empty journal is a legal history
    for position, raw in enumerate(path.read_bytes().splitlines()):
        if len(raw) > _MAX_LINE:
            problems.append(f"oversize_decision_line:{position}")
            continue
        try:
            entry = loads_json(raw)
            if set(entry) != {"decision", "decision_digest", "prior_decision_digest"}:
                raise ContractError("shape")
            decision = (PromotionDecisionV2.from_dict(entry["decision"])
                        if "new_record_digest" in entry["decision"]
                        else PromotionDecisionV1.from_dict(entry["decision"]))
        except ContractError:
            problems.append(f"undecodable_decision_entry:{position}")
            continue
        if decision.digest != entry["decision_digest"]:
            problems.append(f"decision_digest_mismatch:{position}")
        if entry["prior_decision_digest"] != prior:
            problems.append(f"decision_chain_break:{position}")
        prior = hashlib.sha256(raw).hexdigest()
        entries.append({"position": position, "decision": decision,
                        "decision_digest": entry["decision_digest"], "line_sha256": prior})
    return entries, problems


def reconcile(catalog_entries, decision_entries):
    """Partition catalog rows into seeds, decision-backed and orphaned.

    Returns (seeds, imports, quarantined, decision_issues) where ``imports``
    is a list of (decision, record|None) in chain order.
    """
    seeds, quarantined = [], []
    by_digest = {}
    for entry in catalog_entries:
        rec = entry["record"]
        by_digest[rec.digest] = rec
        if rec.revision == 1 and rec.status in _SEED_STATUSES:
            seeds.append(rec)

    imports, decision_issues = [], []
    decided = set()
    # Simulate latest-revision state while replaying the chain in order.
    latest: dict[str, object] = {r.procedure_id: r for r in seeds}
    for entry in decision_entries:
        decision = entry["decision"]
        if isinstance(decision, PromotionDecisionV1):
            imports.append((decision, None))
            continue
        record = by_digest.get(decision.new_record_digest)
        if record is None:
            candidate = latest.get(
                # find the procedure whose current record digest is the
                # decision's candidate_digest
                _pid_of(latest, decision.candidate_digest) or "")
            if candidate is None or candidate.digest != decision.candidate_digest:
                decision_issues.append(
                    f"unmaterializable_decision:{decision.decision_id}")
                imports.append((decision, None))
                continue
            record = replace(candidate, revision=candidate.revision + 1,
                             status=decision.new_status)
            if record.digest != decision.new_record_digest:
                decision_issues.append(
                    f"reconstruction_digest_mismatch:{decision.decision_id}")
                imports.append((decision, None))
                continue
        decided.add(decision.new_record_digest)
        latest[record.procedure_id] = record
        imports.append((decision, record))

    for entry in catalog_entries:
        rec = entry["record"]
        if rec.revision == 1:
            if rec.status in _SEED_STATUSES:
                continue
            quarantined.append((rec, "seed_with_decision_managed_status"))
        elif rec.digest not in decided:
            quarantined.append((rec, "revision_without_verified_decision"))
    return seeds, imports, quarantined, decision_issues


def _pid_of(latest: dict, digest: str) -> str | None:
    for pid, record in latest.items():
        if record.digest == digest:
            return pid
    return None


def execute_import(db, catalog_entries, decision_entries,
                   seeds, imports, quarantined, *, controller_ref) -> dict:
    """Import reconciled state into the already-opened authority store."""
    stats = {"seeds": 0, "decisions": 0, "quarantined": 0}
    try:
        for rec in seeds:
            db.add_seed(rec)
            stats["seeds"] += 1
        for decision, record in imports:
            db._import_committed_decision(
                decision=decision, record=record,
                expected_prior_decision_digest=db.decision_head(),
                authority=controller_ref, source="jsonl-migration")
            stats["decisions"] += 1
        for rec, reason in quarantined:
            db.quarantine(source="catalog-jsonl", reason=reason, record=rec)
            stats["quarantined"] += 1
    except AuthorityError as exc:
        stats["import_error"] = str(exc)
        db.close()
        return stats
    verify_report = _verify_target(db, controller_ref)
    stats["post_import_verify"] = verify_report
    db.close()
    return stats


def _verify_target(db, controller) -> dict:
    structural = db.verify()
    authority = controller.verify()
    return {"ok": structural["ok"] and authority["ok"],
            "structural_problems": structural["problems"],
            "authority_problems": authority["problems"]}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cutover(catalog: Path, decisions: Path, backup_dir: Path) -> dict:
    """Rename legacy files to .migrated after byte-identical backup."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    moved = []
    for src in (catalog, decisions):
        if not src.exists():
            continue
        backup = backup_dir / src.name
        shutil.copy2(src, backup)
        assert _sha256_file(src) == _sha256_file(backup), "backup divergence"
        migrated = src.with_suffix(src.suffix + ".migrated")
        src.rename(migrated)
        moved.append({"source": src.name, "backup": str(backup),
                      "backup_sha256": _sha256_file(backup)})
    return {"moved": moved, "backup_dir": str(backup_dir),
            "rollback": "rename *.migrated back to original names and "
                        "delete the authority.db that replaced them"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--catalog", type=Path, required=True,
                        help="path to legacy procedures.jsonl")
    parser.add_argument("--decisions", type=Path, required=True,
                        help="path to legacy decisions.jsonl")
    parser.add_argument("--target", type=Path,
                        help="target authority.db path (required for --execute)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", default=True)
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--cutover", action="store_true",
                        help="rename legacy files to .migrated after verify")
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--signing-key", type=Path,
                        help="file containing a 64-hex Ed25519 seed")
    parser.add_argument("--key-id", default=None)
    parser.add_argument("--trusted-evaluator-keys", type=Path,
                        help="JSON object {key_id: public_key_hex}")
    parser.add_argument("--operator-token-digest", default=None)
    parser.add_argument("--trusted-operator-keys", type=Path,
                        help="JSON object {key_id: public_key_hex}")
    args = parser.parse_args(argv)

    catalog_entries, cat_problems = _load_catalog(args.catalog)
    decision_entries, dec_problems = _load_decisions(args.decisions)
    seeds, imports, quarantined, decision_issues = reconcile(
        catalog_entries, decision_entries)

    report = {
        "schema_version": 1,
        "mode": "execute" if args.execute else "dry-run",
        "inputs": {
            "catalog": {"path": str(args.catalog),
                        "sha256": _sha256_file(args.catalog) if args.catalog.exists() else None,
                        "entries": len(catalog_entries), "problems": cat_problems},
            "decisions": {"path": str(args.decisions),
                          "sha256": _sha256_file(args.decisions) if args.decisions.exists() else None,
                          "entries": len(decision_entries), "problems": dec_problems},
        },
        "reconciliation": {
            "seed_records": len(seeds),
            "decision_imports": len(imports),
            "quarantined": [
                {"procedure_id": r.procedure_id, "revision": r.revision,
                 "record_digest": r.digest, "reason": reason}
                for r, reason in quarantined
            ],
            "decision_issues": decision_issues,
        },
        "status": "pending",
    }

    if args.execute or args.cutover:
        if not args.target:
            report["status"] = "blocked"
            report["error"] = "--execute/--cutover requires --target"
            return _emit(report, args, 2)
        if not args.signing_key:
            report["status"] = "blocked"
            report["error"] = "--execute/--cutover requires --signing-key"
            return _emit(report, args, 2)
        trusted_eval = _load_keys(args.trusted_evaluator_keys)
        trusted_ops = _load_keys(args.trusted_operator_keys)
        # Bind a controller to the target store — the same object a
        # production deployment would use to verify authority.
        db = AuthorityDB(args.target)
        controller = PromotionController(
            db, operator_token_digest=args.operator_token_digest,
            trusted_evaluator_keys=trusted_eval,
            trusted_operator_keys=trusted_ops)
        stats = execute_import(
            db, catalog_entries, decision_entries,
            seeds, imports, quarantined, controller_ref=controller)
        report["import"] = stats
        ok = stats.get("post_import_verify", {}).get("ok", False)
        report["status"] = "complete" if ok else "failed_verification"
        if ok and args.cutover:
            backup = args.backup_dir or args.target.parent / "pre-migration-backup"
            report["cutover"] = cutover(args.catalog, args.decisions, backup)
            report["status"] = "cutover_complete"
    else:
        report["status"] = "blocked" if (cat_problems or dec_problems
                                       or quarantined or decision_issues) \
            else "clean"

    return _emit(report, args, 0 if report["status"] in
                 ("clean", "complete", "cutover_complete") else 1)


def _load_keys(path: Path | None) -> dict:
    if not path:
        return {}
    return dict(loads_json(path.read_bytes()))


def _emit(report: dict, args, code: int) -> int:
    if args.signing_key and args.signing_key.exists():
        seed = bytes.fromhex(args.signing_key.read_text().strip())
        key_id = args.key_id or "key-" + hashlib.sha256(
            signatures.public_key(seed)).hexdigest()[:24]
        body = canonical_json({k: v for k, v in report.items() if k != "signature"})
        report["signature"] = {
            "scheme": "ed25519",
            "key_id": key_id,
            "digest": signatures.sign(seed, b"sis-v3:migration_report:1\0" + body).hex(),
        }
        report["signed"] = True
    else:
        report["signed"] = False
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        args.report.write_text(text + "\n")
    print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
