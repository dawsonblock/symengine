"""Custodian-only synthetic skill-to-LLM data export after holdout qualification.

Labels here are OUTPUTS OF THE SKILL, not measured ground truth. This never
modifies any model's weights, and requires an external training pipeline.
"""
import hashlib
from .errors import InvalidInput, RuleRejected
from .validation import check_inputs, canonical, digest, input_schema
from .skill_bundle import validate_bundle, predict

FORMAT='sis.skill_distillation.v2'
INSTRUCTION='Perform the deterministic transformation described in task_description on inputs. Return only a JSON object containing the key output.'


def export(vault, public, bundle, receipt, candidate_inputs):
    confirmation=vault.verify(public,bundle,receipt)
    if confirmation['assessment']['status']!='policy_pass':
        raise RuleRejected('cannot export from skill that did not pass precommitted evaluation policy')
    records=validate_bundle(bundle)
    if not isinstance(candidate_inputs,list) or not 1<=len(candidate_inputs)<=256:
        raise InvalidInput('distillation candidate inputs must contain 1-256 records')
    clean=[check_inputs(x) for x in candidate_inputs]
    schema=records[bundle['root_skill_id']]['schema']
    if any(input_schema(x)!=schema for x in clean):
        raise InvalidInput('distillation input schema differs from evaluated skill')
    keys=[canonical(x) for x in clean]
    if len(set(keys))!=len(keys):
        raise InvalidInput('duplicate distillation records')
    # Custodian-side overlap verification. Never return the private holdout inputs.
    private,used,_=vault._get(public)
    sealed={canonical(row['inputs']) for name in ('holdout','shifted_holdout') for row in private[name]}
    sealed.update(canonical(x) for x in private['excluded_inputs'])
    if sealed.intersection(keys):
        raise RuleRejected('export input overlaps private evaluation or declared training/validation exclusions')
    rows=[]
    for inputs in clean:
        target=predict(bundle,inputs,validated_index=records)
        rows.append({'messages':[
            {'role':'system','content':INSTRUCTION},
            {'role':'user','content':canonical({'namespace':bundle['namespace'],'task_description':private['task_description'],'inputs':inputs})},
            {'role':'assistant','content':canonical({'output':target})}
        ]})
    jsonl=''.join(canonical(row)+'\n' for row in rows)
    info={'format':FORMAT,'evaluation_id':public['evaluation_id'],
          'bundle_digest':bundle['bundle_digest'],'count':len(rows),
          'data_sha256':hashlib.sha256(jsonl.encode('utf8')).hexdigest(),
          'generator':'frozen_symbolic_skill',
          'qualification':'policy_pass on custodian-scored private holdout',
          'limitations':'pseudo-labels from skill predictions, not independently verified truths; no neural training performed'}
    return jsonl,vault._signed(info)
