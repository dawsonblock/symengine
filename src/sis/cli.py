"""Command-line entry point: python -m sis / sis."""
import argparse
import json
import os
import sys
from pathlib import Path
from . import __version__
from .errors import SISError, InvalidInput
from .service import Service
from .server import serve
from .validation import canonical
from .anchoring import export_anchor, verify_anchor_file
from .sealed_eval import EvaluatorVault, _key_from_env


def load(path):
    with open(path, "r", encoding="utf8") as f:
        return json.load(f)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sis", description="Evidence-gated symbolic rule induction")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--db", default=os.getenv("SIS_DB", "sis.sqlite3"), help="SQLite rule registry")
    commands = parser.add_subparsers(dest="command", required=True)
    train = commands.add_parser("train", help="induce and optionally promote a rule from a study JSON file")
    train.add_argument("study", help="JSON with train/validation/namespace/promote")
    train.add_argument("--use-llm", action="store_true", help="explicitly allow an external LLM to see training data")
    query = commands.add_parser("query", help="suggest unlabeled distinguishing experiments")
    query.add_argument("request")
    paired = commands.add_parser("paired-eval", help="explicit opt-in live LLM-only vs same-LLM+SIS paired comparison")
    paired.add_argument("dataset", help="caller-controlled labeled cases, held locally")
    paired.add_argument("output", help="new result JSON file; refuses overwrite")
    paired.add_argument("--allow-network", action="store_true", help="explicitly send unlabeled case inputs to configured LLM")
    bench = commands.add_parser("benchmark", help="measure performance on caller-supplied disjoint test data")
    bench.add_argument("request")
    ret = commands.add_parser("retire", help="irreversibly retire a registered rule")
    ret.add_argument("request")
    commands.add_parser("tools", help="emit LLM agent tool JSON schemas")
    anchor_export = commands.add_parser("anchor-export", help="write an out-of-database audit checkpoint; never overwrite")
    anchor_export.add_argument("path")
    anchor_verify = commands.add_parser("anchor-verify", help="verify registry against trusted checkpoint file")
    anchor_verify.add_argument("path")
    batch = commands.add_parser("predict-batch", help="predict a bounded batch of input records")
    batch.add_argument("request")
    transfer = commands.add_parser('transfer', help='read-only, exact-schema cross-task prediction')
    transfer.add_argument('request')
    transfer_batch = commands.add_parser('transfer-batch', help='read-only 1-64 cross-task records')
    transfer_batch.add_argument('request')
    pred = commands.add_parser("predict", help="predict from an input JSON file")
    pred.add_argument("request", help="JSON with namespace and inputs")
    fb = commands.add_parser("feedback", help="record a user-reported outcome; mismatch suspends rule")
    fb.add_argument("request")
    rules = commands.add_parser("rules", help="show learned rules")
    rules.add_argument("--namespace", default="default")
    rules.add_argument("--all", action="store_true")
    commands.add_parser("audit", help="verify in-database hash-linked audit history")
    chat = commands.add_parser("chat", help="opt-in augment an OpenAI-compatible model")
    chat.add_argument("request")
    http = commands.add_parser("serve", help="run local HTTP JSON API")
    http.add_argument("--host", default="127.0.0.1")
    http.add_argument("--port", type=int, default=8765)
    seal = commands.add_parser('eval-seal', help='custodian: seal a secret holdout into a private one-use vault')
    seal.add_argument('dataset', help='private evaluation dataset (never give to candidate agents)')
    seal.add_argument('public', help='new public train/validation file; refuses overwrite')
    seal.add_argument('--vault', required=True, help='custodian-only SQLite vault file')
    seal.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY', help='name of evaluator-owned HMAC secret env variable')
    candidate = commands.add_parser('eval-candidate', help='candidate: derive a bounded rule using public data only')
    candidate.add_argument('public')
    candidate.add_argument('submission', help='new submission JSON path; refuses overwrite')
    candidate.add_argument('--max-candidates',type=int,default=12000)
    score = commands.add_parser('eval-score', help='custodian: score one admissible candidate exactly once')
    score.add_argument('public')
    score.add_argument('submission')
    score.add_argument('--vault', required=True)
    score.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY')
    score.add_argument('--receipt', required=True, help='new signed aggregate receipt file')
    recover = commands.add_parser('eval-recover', help='custodian: recover a receipt committed before output writing failed')
    recover.add_argument('public')
    recover.add_argument('--vault', required=True)
    recover.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY')
    recover.add_argument('--receipt', required=True, help='new recovered receipt JSON path; refuses overwrite')
    verify = commands.add_parser('eval-verify', help='custodian: replay signed receipt against sealed test')
    verify.add_argument('public')
    verify.add_argument('receipt')
    verify.add_argument('--vault', required=True)
    verify.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY')
    qualify = commands.add_parser('eval-qualify', help='custodian: attest sealed policy-relative thresholds')
    qualify.add_argument('public')
    qualify.add_argument('receipt')
    qualify.add_argument('--vault', required=True)
    qualify.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY')
    qualify.add_argument('--qualification', required=True, help='new signed qualification output')
    verify_qual = commands.add_parser('eval-verify-qualification', help='custodian: verify qualification and score replay')
    verify_qual.add_argument('public')
    verify_qual.add_argument('receipt')
    verify_qual.add_argument('qualification')
    verify_qual.add_argument('--vault', required=True)
    verify_qual.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY')
    ecapture=commands.add_parser('experience-capture', help='execute a bounded pure-tool plan and capture provenance')
    ecapture.add_argument('request')
    einduce=commands.add_parser('experience-induce', help='replay labeled captures and independently validate inferred skills')
    einduce.add_argument('request')
    for command, description in [
        ('skill-study','discover and optionally promote bounded procedural skills'),
        ('experience-study','convert labeled execution episodes into governed skill study'),
        ('trace-study','induce governed skills from typed and replay-checked training traces'),
        ('skill-predict','execute an active procedural skill'),
        ('skill-feedback','operator feedback; mismatch suspends skill'),
        ('skill-retire','retire a procedural skill'),
        ('skill-benchmark','score skills on operator-provided cases')]:
        cmd=commands.add_parser(command, help=description)
        cmd.add_argument('request')
    skills=commands.add_parser('skills',help='list procedural skills')
    skills.add_argument('--namespace',default='default')
    skills.add_argument('--all',action='store_true')
    commands.add_parser('skill-audit',help='verify procedural skill hash chain and projections')
    skill_freeze=commands.add_parser('skill-freeze',help='freeze active skill and dependencies to a hash-bound file')
    skill_freeze.add_argument('skill_id')
    skill_freeze.add_argument('output')
    skill_freeze.add_argument('--namespace',default='default')
    skill_seal=commands.add_parser('skill-eval-seal',help='custodian: precommit frozen skill and seal private procedural holdouts')
    skill_seal.add_argument('private_dataset')
    skill_seal.add_argument('bundle')
    skill_seal.add_argument('public')
    skill_seal.add_argument('--vault',required=True)
    skill_seal.add_argument('--key-env',default='SIS_EVAL_HMAC_KEY')
    skill_score=commands.add_parser('skill-eval-score',help='custodian: score precommitted frozen skill exactly once')
    skill_score.add_argument('public')
    skill_score.add_argument('bundle')
    skill_score.add_argument('receipt')
    skill_score.add_argument('--vault',required=True)
    skill_score.add_argument('--key-env',default='SIS_EVAL_HMAC_KEY')
    skill_recover=commands.add_parser('skill-eval-recover',help='custodian: recover committed evaluation receipt after interrupted file write')
    skill_recover.add_argument('public')
    skill_recover.add_argument('bundle')
    skill_recover.add_argument('receipt')
    skill_recover.add_argument('--vault',required=True)
    skill_recover.add_argument('--key-env',default='SIS_EVAL_HMAC_KEY')
    skill_verify=commands.add_parser('skill-eval-verify',help='custodian: verify signature and replay private holdout scoring')
    skill_verify.add_argument('public')
    skill_verify.add_argument('bundle')
    skill_verify.add_argument('receipt')
    skill_verify.add_argument('--vault',required=True)
    skill_verify.add_argument('--key-env',default='SIS_EVAL_HMAC_KEY')
    skill_export=commands.add_parser('skill-distill-export',help='custodian: export verified skill-generated pseudo-labels')
    skill_export.add_argument('public')
    skill_export.add_argument('bundle')
    skill_export.add_argument('receipt')
    skill_export.add_argument('inputs')
    skill_export.add_argument('output')
    skill_export.add_argument('--vault',required=True)
    skill_export.add_argument('--key-env',default='SIS_EVAL_HMAC_KEY')
    sft = commands.add_parser('neural-train', help='validate pseudo-label export and optionally execute local LoRA training')
    sft.add_argument('data', help='custodian-exported JSONL pseudo-label file')
    sft.add_argument('manifest', help='signed export JSON manifest')
    sft.add_argument('config', help='strict JSON training configuration')
    sft.add_argument('--execute', action='store_true', help='opt in to load model weights and train')
    sft.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY', help='custodian HMAC secret variable')
    sft.add_argument('--allow-unverified-export', action='store_true', help='unsafe: allow checksum-only demo export')
    three = commands.add_parser('neural-eval', help='evaluate baseline, baseline+skill, trained adapter (plus optional placebo)')
    three.add_argument('dataset', help='private locally labeled evaluation records')
    three.add_argument('bundle', help='frozen procedural skill closure')
    three.add_argument('output', help='new local aggregate report JSON; refuses overwrite')
    three.add_argument('--distilled-url', required=True, help='adapted model OpenAI-compatible chat/completions endpoint')
    three.add_argument('--distilled-model', required=True, help='adapted model ID')
    three.add_argument('--allow-network', action='store_true', help='opt in to sending unlabeled examples to endpoints')
    family_seal = commands.add_parser('family-eval-seal', help='custodian: HMAC precommit private task-family holdout and model identifiers')
    family_seal.add_argument('private_dataset')
    family_seal.add_argument('bundle')
    family_seal.add_argument('public_protocol')
    family_seal.add_argument('--baseline-id', required=True, help='pinned baseline model identifier')
    family_seal.add_argument('--adapted-id', required=True, help='pinned adapted model identifier')
    family_seal.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY')
    family_run = commands.add_parser('family-eval-run', help='custodian: one-use 3/4-arm task-family evaluation')
    family_run.add_argument('private_dataset')
    family_run.add_argument('bundle')
    family_run.add_argument('public_protocol')
    family_run.add_argument('report')
    family_run.add_argument('--vault', required=True, help='custodian-owned persistent SQLite one-use vault')
    family_run.add_argument('--adapted-url', required=True)
    family_run.add_argument('--adapted-model', required=True)
    family_run.add_argument('--allow-network', action='store_true')
    family_run.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY')
    family_verify = commands.add_parser('family-eval-verify', help='verify signed aggregate report and public protocol binding')
    family_verify.add_argument('public_protocol')
    family_verify.add_argument('report')
    family_verify.add_argument('--key-env', default='SIS_EVAL_HMAC_KEY')
    for cmd,description in [
        ('workflow-capture','execute read-only tabular operations and record observed results'),
        ('workflow-study','learn and optionally promote a normalized tabular workflow'),
        ('workflow-predict','run validated tabular workflow (read-only)'),
        ('workflow-retire','retire validated tabular workflow')]:
        commands.add_parser(cmd,help=description).add_argument('request')
    for cmd,description in [
        ('code-capture','instrument one bounded pure AST repair with test-vector observations'),
        ('code-study','replay captured code fixes and qualify a reusable operator-repair recipe'),
        ('code-preview','preview an active validated recipe against a supplied code snippet; no writes'),
        ('code-retire','operator-only retirement of a code recipe')]:
        sub=commands.add_parser(cmd,help=description)
        sub.add_argument('request')
    commands.add_parser('code-audit',help='verify local code recipe/audit hash consistency')
    code_list=commands.add_parser('code-list',help='list registered code recipes')
    code_list.add_argument('--namespace',default='default')
    commands.add_parser('workflow-audit',help='check local workflow snapshot and audit consistency')
    wlist=commands.add_parser('workflow-list',help='list known tabular workflows')
    wlist.add_argument('--namespace',default='default')
    args = parser.parse_args(argv)
    try:
        if args.command == 'family-eval-verify':
            from .family_eval import verify_report
            result=verify_report(load(args.report),load(args.public_protocol),key=_key_from_env(args.key_env))
            print(json.dumps(result,indent=2))
            return 0
        if args.command == 'family-eval-seal':
            from .family_eval import precommit
            if Path(args.public_protocol).exists():
                raise InvalidInput('public protocol exists; refusing overwrite')
            secret=_key_from_env(args.key_env)
            body=precommit(load(args.private_dataset),load(args.bundle), key=secret,
                           baseline_id=args.baseline_id, adapted_id=args.adapted_id)
            with open(args.public_protocol,'x',encoding='utf8') as fp:
                fp.write(canonical(body)+'\n')
            print(json.dumps({'status':'precommitted','experiment_id':body['experiment_id'],
                              'public_protocol':args.public_protocol,'test_family_counts':body['test_family_counts']},indent=2))
            return 0
        if args.command == 'family-eval-run':
            if not args.allow_network:
                raise InvalidInput('live family evaluation requires --allow-network')
            if Path(args.report).exists():
                raise InvalidInput('report exists; refusing overwrite')
            from .family_eval import FamilyExperimentVault,validate_protocol
            from .model import CompatibleLLM
            secret=_key_from_env(args.key_env)
            private=load(args.private_dataset);protocol=load(args.public_protocol);bundle=load(args.bundle)
            validate_protocol(protocol,private,bundle,key=secret)
            base=CompatibleLLM()
            adapted=CompatibleLLM(base_url=args.adapted_url,model=args.adapted_model)
            if base.url==adapted.url and base.model==adapted.model:
                raise InvalidInput('the baseline and adapted endpoints must differ')
            if base.model!=protocol['model_ids']['baseline'] or adapted.model!=protocol['model_ids']['adapted']:
                raise InvalidInput('configured model IDs must match precommitted IDs')
            with_vault=FamilyExperimentVault(args.vault)
            try:
                result=with_vault.run(private,protocol,bundle,base,adapted,key=secret)
            finally:
                with_vault.close()
            with open(args.report,'x',encoding='utf8') as fp:
                fp.write(canonical(result)+'\n')
            print(json.dumps({'status':result['status'],'qualification':result['qualification'],
                              'report_path':args.report},indent=2))
            return 0 if result['status']=='evaluated' else 2
        if args.command == 'neural-train':
            from .neural_training import train
            secret = os.getenv(args.key_env)
            if secret is None and not args.allow_unverified_export:
                raise InvalidInput('set the evaluator HMAC environment secret or explicitly allow unauthenticated demo export')
            value = train(args.data, args.manifest, load(args.config),
                          hmac_key=secret.encode('utf8') if secret is not None else None,
                          allow_unverified=args.allow_unverified_export, execute=args.execute)
            print(json.dumps(value,indent=2))
            return 0
        if args.command == 'neural-eval':
            if not args.allow_network:
                raise InvalidInput('neural-eval requires explicit --allow-network')
            if Path(args.output).exists():
                raise InvalidInput('output already exists; refusing overwrite')
            from .neural_eval import evaluate
            from .model import CompatibleLLM
            baseline = CompatibleLLM()
            distilled = CompatibleLLM(base_url=args.distilled_url,model=args.distilled_model)
            if baseline.url == distilled.url and baseline.model == distilled.model:
                raise InvalidInput('baseline and distilled model endpoint IDs must differ')
            value = evaluate(load(args.dataset),load(args.bundle),baseline,distilled,
                             baseline_label=baseline.model,distilled_label=distilled.model)
            with open(args.output,'x',encoding='utf8') as fp:
                fp.write(canonical(value)+'\n')
            print(json.dumps({'status':value['status'],'count':value['count'],
                              'arms':value['arms'],'vs_baseline':value['vs_baseline'],
                              'report_path':args.output},indent=2))
            return 0 if value['status']=='evaluated' else 2
        if args.command in ('skill-eval-seal','skill-eval-score','skill-eval-verify','skill-eval-recover','skill-distill-export'):
            from .skill_holdout import SkillHoldoutVault
            if args.command in ('skill-eval-seal','skill-eval-score','skill-eval-recover','skill-distill-export'):
                destination=Path(args.output if args.command=='skill-distill-export' else args.public if args.command=='skill-eval-seal' else args.receipt)
                if destination.exists():
                    raise InvalidInput('output already exists; refusing overwrite')
                if args.command=='skill-distill-export' and Path(str(destination)+'.manifest.json').exists():
                    raise InvalidInput('distillation manifest already exists; refusing overwrite')
            key=_key_from_env(args.key_env)
            with SkillHoldoutVault(args.vault,key=key) as vault:
                bundle=load(args.bundle)
                if args.command=='skill-eval-seal':
                    value=vault.seal(load(args.private_dataset),bundle)
                elif args.command=='skill-eval-score':
                    value=vault.score(load(args.public),bundle)
                elif args.command=='skill-eval-recover':
                    value=vault.recover_receipt(load(args.public),bundle)
                elif args.command=='skill-eval-verify':
                    value=vault.verify(load(args.public),bundle,load(args.receipt))
                else:
                    from .distillation import export
                    content,manifest=export(vault,load(args.public),bundle,load(args.receipt),load(args.inputs))
                    with open(args.output,'x',encoding='utf8') as fp: fp.write(content)
                    with open(str(args.output)+'.manifest.json','x',encoding='utf8') as fp: fp.write(canonical(manifest)+'\n')
                    value={'status':'exported','records':manifest['count'],'data_path':args.output,
                           'manifest_path':str(args.output)+'.manifest.json'}
            if args.command=='skill-eval-seal':
                with open(args.public,'x',encoding='utf8') as fp: fp.write(canonical(value)+'\n')
            elif args.command in ('skill-eval-score','skill-eval-recover'):
                with open(args.receipt,'x',encoding='utf8') as fp: fp.write(canonical(value)+'\n')
            print(json.dumps(value,indent=2))
            return 0
        if args.command=='skill-freeze':
            if Path(args.output).exists():
                raise InvalidInput('output already exists; refusing overwrite')
            service=Service(args.db,enable_llm=False)
            try:
                bundle=service.skill_freeze(args.namespace,args.skill_id)
            finally:
                service.registry.close()
            with open(args.output,'x',encoding='utf8') as fp:
                fp.write(canonical(bundle)+'\n')
            print(json.dumps({'status':'frozen','bundle_digest':bundle['bundle_digest'],'output':args.output},indent=2))
            return 0
        if args.command in ('eval-seal','eval-candidate','eval-score','eval-recover','eval-verify','eval-qualify','eval-verify-qualification'):
            if args.command == 'eval-candidate':
                if Path(args.submission).exists():
                    raise InvalidInput('submission output exists; will not overwrite')
                value = EvaluatorVault.make_submission(load(args.public), max_candidates=args.max_candidates)
                if value['status'] != 'candidate':
                    print(json.dumps(value, indent=2))
                    return 2
                with open(args.submission, 'x', encoding='utf8') as fp:
                    fp.write(canonical(value['submission']) + '\n')
                print(json.dumps({'status':'created','path':args.submission,'induction_status':value['induction']['status']},indent=2))
                return 0
            key = _key_from_env(args.key_env)
            if args.command == 'eval-seal' and Path(args.public).exists():
                raise InvalidInput('public output exists; will not overwrite')
            if args.command in ('eval-score','eval-recover') and Path(args.receipt).exists():
                raise InvalidInput('receipt output exists; will not overwrite')
            if args.command == 'eval-qualify' and Path(args.qualification).exists():
                raise InvalidInput('qualification output exists; will not overwrite')
            with EvaluatorVault(args.vault, key=key) as vault:
                if args.command == 'eval-seal':
                    value = vault.seal(load(args.dataset))
                    with open(args.public, 'x', encoding='utf8') as fp:
                        fp.write(canonical(value) + '\n')
                    print(json.dumps({'status':'sealed','evaluation_id':value['evaluation_id'],
                                      'public_path':args.public,'holdout_custody':'evaluator vault'},indent=2))
                elif args.command == 'eval-score':
                    value = vault.score(load(args.public),load(args.submission))
                    with open(args.receipt, 'x', encoding='utf8') as fp:
                        fp.write(canonical(value) + '\n')
                    print(json.dumps({'status':'scored','receipt_path':args.receipt,'metrics':value['metrics']},indent=2))
                elif args.command == 'eval-recover':
                    value = vault.recover_receipt(load(args.public))
                    with open(args.receipt, 'x', encoding='utf8') as fp:
                        fp.write(canonical(value) + '\n')
                    print(json.dumps({'status':'recovered','receipt_path':args.receipt,'metrics':value['metrics']},indent=2))
                elif args.command == 'eval-qualify':
                    value = vault.qualify(load(args.public),load(args.receipt))
                    with open(args.qualification, 'x', encoding='utf8') as fp:
                        fp.write(canonical(value) + '\n')
                    print(json.dumps({'status':value['assessment']['status'], 'qualification_path':args.qualification, 'reasons':value['assessment']['reasons']},indent=2))
                elif args.command == 'eval-verify-qualification':
                    value = vault.verify_qualification(load(args.public),load(args.receipt),load(args.qualification))
                    print(json.dumps(value,indent=2))
                else:
                    value = vault.verify(load(args.public),load(args.receipt))
                    print(json.dumps(value,indent=2))
            return 0
        if args.command == "serve":
            serve(args.host, args.port, db_path=args.db)
            return 0
        if args.command == 'paired-eval':
            if not args.allow_network or os.getenv('SIS_ENABLE_LLM') != '1':
                raise InvalidInput('paired-eval requires BOTH --allow-network and SIS_ENABLE_LLM=1')
            if Path(args.output).exists():
                raise InvalidInput('paired-eval output exists; will not overwrite')
            from .model import CompatibleLLM
            from .paired_eval import run_paired
            # Construct client before loading registry. Never write the labeled dataset to the model endpoint.
            client = CompatibleLLM()
            service = Service(args.db, enable_llm=False)
            try:
                result = run_paired(load(args.dataset), client, service, model_label=client.model)
            finally:
                service.registry.close()
            with open(args.output, 'x', encoding='utf8') as fp:
                fp.write(canonical(result) + '\n')
            print(json.dumps({'status': result['status'], 'result_file': args.output,
                              'cases': result['case_count'], 'paired': result['paired'],
                              'qualification': result['qualification']}, indent=2))
            return 0 if result['status'] == 'evaluated' else 2
        service = Service(args.db, enable_llm=os.getenv("SIS_ENABLE_LLM") == "1" or getattr(args, "use_llm", False))
        try:
            if args.command == "train":
                study = load(args.study)
                if args.use_llm:
                    study["use_llm"] = True
                value = service.study(study)
            elif args.command == 'query':
                value = service.query(load(args.request))
            elif args.command == 'benchmark':
                value = service.benchmark(load(args.request))
            elif args.command == 'retire':
                value = service.retire(load(args.request))
            elif args.command == 'tools':
                value = service.tools()
            elif args.command == "predict":
                value = service.predict(load(args.request))
            elif args.command == "transfer":
                value = service.transfer(load(args.request))
            elif args.command == "transfer-batch":
                value = service.transfer_batch(load(args.request))
            elif args.command == "predict-batch":
                value = service.predict_batch(load(args.request))
            elif args.command == "anchor-export":
                value = export_anchor(service.registry, args.path)
            elif args.command == "anchor-verify":
                value = verify_anchor_file(service.registry, args.path)
            elif args.command == "feedback":
                value = service.feedback(load(args.request))
            elif args.command == "rules":
                value = service.list_rules(args.namespace, args.all)
            elif args.command == "audit":
                value = service.registry.verify_audit()
            elif args.command == 'skill-study':
                value = service.skill_study(load(args.request))
            elif args.command == 'experience-study':
                value = service.experience_study(load(args.request))
            elif args.command == 'trace-study':
                value = service.trace_study(load(args.request))
            elif args.command == 'experience-capture':
                value = service.experience_capture(load(args.request))
            elif args.command == 'experience-induce':
                value = service.experience_induce(load(args.request))
            elif args.command == 'skill-predict':
                value = service.skill_predict(load(args.request))
            elif args.command == 'skill-feedback':
                value = service.skill_feedback(load(args.request))
            elif args.command == 'skill-retire':
                value = service.skill_retire(load(args.request))
            elif args.command == 'skill-benchmark':
                value = service.skill_benchmark(load(args.request))
            elif args.command == 'skills':
                value = {'skills':service.skill_list(args.namespace,args.all)}
            elif args.command == 'skill-audit':
                value = service.skill_audit()
            elif args.command == 'code-capture':
                value = service.code_capture(load(args.request))
            elif args.command == 'code-study':
                value = service.code_study(load(args.request))
            elif args.command == 'code-preview':
                value = service.code_preview(load(args.request))
            elif args.command == 'code-retire':
                value = service.code_retire(load(args.request))
            elif args.command == 'code-audit':
                value = service.code_audit()
            elif args.command == 'code-list':
                value = {'recipes':service.code_list(args.namespace)}
            elif args.command == 'workflow-capture':
                value = service.workflow_capture(load(args.request))
            elif args.command == 'workflow-study':
                value = service.workflow_study(load(args.request))
            elif args.command == 'workflow-predict':
                value = service.workflow_predict(load(args.request))
            elif args.command == 'workflow-retire':
                value = service.workflow_retire(load(args.request))
            elif args.command == 'workflow-audit':
                value = service.workflow_audit()
            elif args.command == 'workflow-list':
                value = {'workflows':service.workflow_list(args.namespace)}
            else:
                value = service.chat(load(args.request))
            print(json.dumps(value, indent=2, ensure_ascii=False))
            return 0
        finally:
            service.registry.close()
    except (SISError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
