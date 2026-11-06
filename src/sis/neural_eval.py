"""Evaluator-side, read-only 3/4-arm neural-vs-symbolic comparison.

Ground-truth labels are never sent to the model clients. Caller-provided data
are not independently certified. Provider logging and benchmark contamination
remain out of scope. No results are promoted automatically.
"""
import json
import time
from .distillation import INSTRUCTION
from .errors import InvalidInput
from .paired_eval import _usage, exact_mcnemar_pvalue
from .skill_bundle import validate_bundle, predict
from .validation import canonical, check_examples, check_inputs, check_task_description, digest, input_schema, namespace_name
from .qualification import wilson_lower


def _strict_output(content, gold):
    if not isinstance(content, str) or len(content) > 8192:
        return 'invalid_output', None
    try:
        val = json.loads(content)
    except (ValueError, TypeError):
        return 'invalid_output', None
    if not isinstance(val, dict) or set(val) != {'output'} or type(val['output']) is not type(gold):
        return 'invalid_output', None
    answer = val['output']
    if type(answer) is int and abs(answer) > 1_000_000_000:
        return 'invalid_output', None
    if type(answer) is str and len(answer) > 128:
        return 'invalid_output', None
    return 'answered', answer


def _check_dataset(dataset, bundle):
    if not isinstance(dataset, dict) or set(dataset) != {'namespace', 'task_description', 'cases', 'excluded_inputs', 'max_tokens', 'include_placebo'}:
        raise InvalidInput('dataset requires namespace, task_description, cases, exclusions, max_tokens, include_placebo')
    namespace = namespace_name(dataset['namespace'])
    check_task_description(dataset['task_description'])
    if namespace != bundle['namespace']:
        raise InvalidInput('benchmark namespace does not match frozen skill')
    cases = check_examples(dataset['cases'], minimum=4)
    clean = dataset['excluded_inputs']
    if not isinstance(clean, list) or len(clean) > 256:
        raise InvalidInput('excluded_inputs must be list up to 256')
    excluded = [check_inputs(x) for x in clean]
    keys = [canonical(row['inputs']) for row in cases]
    blocked = [canonical(x) for x in excluded]
    if len(set(keys)) != len(keys) or len(set(blocked)) != len(blocked) or set(keys) & set(blocked):
        raise InvalidInput('duplicate or overlapping evaluation and declared training inputs')
    index = validate_bundle(bundle)
    root_schema = index[bundle['root_skill_id']]['schema']
    if any(input_schema(row['inputs']) != root_schema for row in cases):
        raise InvalidInput('benchmark input schema differs from frozen skill')
    limit = dataset['max_tokens']
    if type(limit) is not int or not 16 <= limit <= 512:
        raise InvalidInput('max_tokens must be 16-512')
    if type(dataset['include_placebo']) is not bool:
        raise InvalidInput('include_placebo must be boolean')
    return cases, excluded, limit, dataset['include_placebo'], index


def _call(client, user, gold, limit):
    messages = [{'role': 'system', 'content': INSTRUCTION},
                {'role': 'user', 'content': canonical(user)}]
    t = time.monotonic_ns()
    try:
        if hasattr(client, 'complete_with_metadata'):
            result, usage = client.complete_with_metadata(messages, max_tokens=limit)
        else:
            result = client.complete(messages, max_tokens=limit)
            usage = None
        status, answer = _strict_output(result, gold)
    except Exception:
        status, answer, usage = 'model_error', None, None
    return {'status': status, 'correct': status == 'answered' and answer == gold,
            'elapsed_ms': round((time.monotonic_ns()-t)/1e6, 3), 'usage': _usage(usage)}


def evaluate(dataset, frozen_bundle, baseline_client, distilled_client,
             *, baseline_label='base-model', distilled_label='adapted-model'):
    """Three arms: base, base+skill hint, trained adapter; optional placebo arm.

    Runs with counterbalanced order. Reject train/evaluation overlap when
    supplied, but provenance independence cannot be established by this method.
    """
    if baseline_client is distilled_client:
        raise InvalidInput('baseline and distilled clients must be separate objects')
    if not isinstance(baseline_label, str) or not isinstance(distilled_label, str) or not baseline_label or not distilled_label:
        raise InvalidInput('model labels required')
    cases, excluded, limit, placebo, index = _check_dataset(dataset, frozen_bundle)
    names = ['baseline', 'symbolic', 'distilled'] + (['placebo'] if placebo else [])
    outcomes=[]
    for idx, row in enumerate(cases):
        inputs, gold = row['inputs'], row['output']
        base_user = {'namespace': frozen_bundle['namespace'], 'task_description': dataset['task_description'], 'inputs': inputs}
        skill_status='unavailable'
        try:
            hint = predict(frozen_bundle, inputs, validated_index=index)
            if type(hint) is type(gold):
                skill_status='available'
            else:
                hint=None
        except (InvalidInput, ValueError, IndexError, KeyError, TypeError):
            hint=None
        # The optional placebo helps detect improvements due to extra context,
        # but it is not token-matched to the actual hint on all tokenizers.
        users={'baseline':base_user, 'distilled':base_user,
               'symbolic':{**base_user,'sis_prediction': {'status':skill_status, 'output':hint}}}
        if placebo:
            users['placebo']={**base_user,'sis_prediction': {'status':'unavailable','output':None}}
        order = names[idx % len(names):] + names[:idx % len(names)]
        arms={}
        for arm in order:
            client = distilled_client if arm=='distilled' else baseline_client
            arms[arm]=_call(client,users[arm],gold,limit)
        outcomes.append({'case_sha256':digest(inputs),'order':order,
                         'skill_available':skill_status=='available','arms':arms})
    summary={}
    for arm in names:
        correct=sum(int(r['arms'][arm]['correct']) for r in outcomes)
        answered=sum(r['arms'][arm]['status']=='answered' for r in outcomes)
        errors=sum(r['arms'][arm]['status']=='model_error' for r in outcomes)
        tokens=sum((r['arms'][arm]['usage'] or {}).get('total_tokens',0) for r in outcomes)
        reported=sum('total_tokens' in (r['arms'][arm]['usage'] or {}) for r in outcomes)
        summary[arm]={'correct':correct,'answered':answered,'model_errors':errors,
                      'accuracy':correct/len(cases),'coverage':answered/len(cases),
                      'wilson_95_lower':wilson_lower(correct,len(cases)),
                      'total_latency_ms':round(sum(r['arms'][arm]['elapsed_ms'] for r in outcomes),3),
                      'provider_total_tokens':tokens if reported==len(cases) else None}
    comparisons={}
    for arm in names:
        if arm=='baseline':continue
        baseline_only=sum(r['arms']['baseline']['correct'] and not r['arms'][arm]['correct'] for r in outcomes)
        other_only=sum(r['arms'][arm]['correct'] and not r['arms']['baseline']['correct'] for r in outcomes)
        comparisons[arm]={'accuracy_delta':summary[arm]['accuracy']-summary['baseline']['accuracy'],
                          'baseline_only_correct':baseline_only,'other_only_correct':other_only,
                          'mcnemar_exact_two_sided_p':exact_mcnemar_pvalue(baseline_only,other_only)}
    errors=sum(summary[a]['model_errors'] for a in names)
    return {'format':'sis.neural_comparison.v2', 'status':'invalid_model_errors' if errors else 'evaluated',
            'model_labels':{'baseline':baseline_label,'distilled':distilled_label},
            'bundle_digest':frozen_bundle['bundle_digest'],
            'test_commitment':digest({'namespace':dataset['namespace'],'task_description':dataset['task_description'],'cases':cases}),
            'exclusion_count':len(excluded),'count':len(cases), 'arms':summary,
            'vs_baseline':comparisons,'symbolic_hint_available':sum(r['skill_available'] for r in outcomes),
            'limitations': 'No certified unseen task families or independent dataset custody; placebo not token matched; no multiple-comparison correction; model endpoints may log prompts.'}
