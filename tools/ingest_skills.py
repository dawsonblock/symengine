#!/usr/bin/env python3
"""Ingest real agent skills into a candidate registry at PROPOSED.

A skill is a directory with ``SKILL.md`` (frontmatter + body) and optional
``references/``, ``scripts/`` and ``assets/`` files. Every discovered
skill is parsed into a bounded ``CandidateV1`` of type ``skill_bundle``
and submitted by the ``learner`` role. Ingestion is packaging only: a
skill that was qualified elsewhere, or that scans clean here, still enters
as PROPOSED and needs signed holdout evidence before it can serve.

Usage:
    python3 tools/ingest_skills.py --skills <dir> --registry <candidates.db> \
        --scope-kind family_id --scope-value fam-a [-o report.json]
    python3 tools/ingest_skills.py --skills <dir> --scope-kind global \
        --dry-run

Exit 0 when every discovered skill was accepted (submitted or already
present); exit 1 when any skill was rejected, with the reasons in the
report.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sis.v3.candidates import (CandidateError,  # noqa: E402
                               CandidateRegistry)
from sis.v3.contracts import CandidateV1, loads_json  # noqa: E402
from sis.v3.skill_ingest import (MAX_SCAN_SKILLS,  # noqa: E402
                                 SkillIngestError, SkillIngestReport,
                                 discover_skills_page, ingest_path,
                                 load_skill, scan_findings, skill_candidate)


def _discover_all(root: Path, *, max_skills: int | None):
    skills = []
    offset = 0
    pages = 0
    complete = True
    while True:
        page = discover_skills_page(root, offset=offset)
        pages += 1
        skills.extend(page)
        if page.complete:
            break
        offset = page.next_offset
        if max_skills is not None and len(skills) >= max_skills:
            complete = False
            break
    return skills[:max_skills] if max_skills is not None else skills, {
        "complete": complete,
        "scanned": len(skills),
        "pages": pages,
        "limit": MAX_SCAN_SKILLS,
        "next_offset": len(skills) if not complete else None,
    }


def _dry_run(root: Path, args) -> SkillIngestReport:
    report = SkillIngestReport([], discovery={
        "complete": True, "scanned": 0, "pages": 0})
    if (root / "manifest.json").is_file() and \
            (root / "payload.json").is_file():
        try:
            candidate = CandidateV1.from_dict(
                loads_json((root / "payload.json").read_bytes()))
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            report.append({"path": root.name, "status": "rejected",
                           "error": f"bundle_payload_unreadable:{exc}"})
            return report
        report.append({
            "path": root.name, "status": "dry_run",
            "candidate_id": candidate.candidate_id,
            "digest": candidate.digest, "state": None,
            "name": candidate.candidate_id,
            "steps": len(candidate.payload.get("steps", ())),
            "resources": 0,
            "scan_findings": scan_findings(candidate),
            "security": candidate.payload.get("security"),
            "auto_qualification_allowed": (
                candidate.payload.get("security", {}) or {}).get(
                    "auto_qualification_allowed", True)})
        report.discovery.update({"complete": True, "scanned": 1,
                                 "pages": 1})
        return report
    skills, discovery = _discover_all(root, max_skills=args.max_skills)
    report.discovery.update(discovery)
    for skill_dir in skills:
        relative = skill_dir.relative_to(root).as_posix() \
            if skill_dir != root else skill_dir.name
        try:
            source = load_skill(skill_dir)
            candidate = skill_candidate(
                source, scope_kind=args.scope_kind,
                scope_value=args.scope_value,
                target_agent=args.agent,
                target_task_family=args.task_family,
                created_at=args.created_at, source_name=relative)
        except SkillIngestError as exc:
            report.append({"path": relative, "status": "rejected",
                           "error": str(exc)})
            continue
        report.append({
            "path": relative, "status": "dry_run",
            "candidate_id": candidate.candidate_id,
            "digest": candidate.digest, "state": None,
            "name": source["name"], "steps": len(source["steps"]),
            "resources": len(source["resources"]),
            "scan_findings": scan_findings(candidate),
            "security": source["security"],
            "auto_qualification_allowed":
                source["security"]["auto_qualification_allowed"]})
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skills", type=Path, required=True)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--scope-kind", required=True,
                        choices=("registry_id", "family_id", "global"))
    parser.add_argument("--scope-value", default="")
    parser.add_argument("--agent", default="agent")
    parser.add_argument("--task-family", default="general")
    parser.add_argument("--created-at", default=None)
    parser.add_argument("--actor-role", default="learner")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--audit", type=Path, default=None,
                        help="append ingestion/security evidence JSONL")
    parser.add_argument("--max-skills", type=int, default=None,
                        help="explicit hard cap; report marks discovery incomplete")
    args = parser.parse_args()

    if args.scope_kind == "global" and args.scope_value:
        parser.error("global scope carries an empty --scope-value")
    if args.scope_kind != "global" and not args.scope_value:
        parser.error("--scope-value is required for registry/family scope")
    if not args.dry_run and args.registry is None:
        parser.error("--registry is required unless --dry-run")

    root = args.skills
    if args.dry_run:
        results = _dry_run(root, args)
    else:
        try:
            registry = CandidateRegistry(args.registry)
        except CandidateError as exc:
            print(json.dumps({"error": str(exc)}, indent=2))
            return 2
        try:
            results = ingest_path(
                root, registry, actor_role=args.actor_role,
                scope_kind=args.scope_kind, scope_value=args.scope_value,
                target_agent=args.agent,
                target_task_family=args.task_family,
                created_at=args.created_at, audit_path=args.audit,
                max_skills=args.max_skills)
        except (CandidateError, SkillIngestError) as exc:
            print(json.dumps({"error": str(exc)}, indent=2))
            return 2
        finally:
            registry.close()

    report = {
        "schema_version": 1,
        "kind": "skill_ingestion",
        "skills_root": str(root),
        "scope": {"kind": args.scope_kind, "value": args.scope_value},
        "dry_run": bool(args.dry_run),
        "discovery": results.discovery,
        "results": results,
        "summary": {
            "discovered": len(results),
            "submitted": sum(1 for r in results
                             if r["status"] == "submitted"),
            "already_present": sum(1 for r in results
                                   if r["status"] == "already_present"),
            "rejected": sum(1 for r in results if r["status"] == "rejected"),
            "flagged": sum(1 for r in results if r.get("scan_findings")),
            "auto_qualification_blocked": sum(
                1 for r in results
                if r.get("auto_qualification_allowed") is False),
        },
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
    print(text)
    return 1 if report["summary"]["rejected"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
