"""Policy-relative post-score qualification, with honest uncertainty bounds.

A pass means a precommitted policy was met on *this vault's* test labels,
not that labels were independently sourced or that model intelligence improved.
No rule registry mutations are made here.
"""
import math
from .errors import InvalidInput, RuleRejected
from .validation import digest

DEFAULT_POLICY = {
    'min_test':30, 'min_shifted':30, 'min_coverage':0.95,
    'min_overall_accuracy':0.80, 'min_wilson_lower':0.65,
    'min_baseline_gain':0.05,
}


def check_policy(policy):
    if not isinstance(policy, dict) or set(policy) != set(DEFAULT_POLICY):
        raise InvalidInput('policy must provide the six documented threshold fields')
    clean = {}
    for k in ('min_test','min_shifted'):
        v = policy[k]
        if type(v) is not int or not 30 <= v <= 256:
            raise InvalidInput(f'{k} must be an integer between 30 and 256')
        clean[k] = v
    bounds = {'min_coverage':(0.5,1), 'min_overall_accuracy':(0.5,1),
              'min_wilson_lower':(0.5,1), 'min_baseline_gain':(0.0,1)}
    for k, (lo, hi) in bounds.items():
        v = policy[k]
        if type(v) not in (int,float) or not math.isfinite(v) or not lo <= v <= hi:
            raise InvalidInput(f'{k} must be a finite number in [{lo},{hi}]')
        clean[k] = float(v)
    return clean


def wilson_lower(successes, trials, z=1.959963984540054):
    """Two-sided 95% Wilson score interval lower endpoint for binomial rate."""
    if type(trials) is not int or type(successes) is not int or not 0 <= successes <= trials:
        raise InvalidInput('invalid binomial counts')
    if trials == 0:
        return 0.0
    n = trials
    p = successes/n
    denom = 1+z*z/n
    return max(0.0,(p+z*z/(2*n)-z*math.sqrt((p*(1-p)+z*z/(4*n))/n))/denom)


def assess(public, receipt):
    """Pure policy assessment. Call ONLY after trusted vault.verify(public, receipt)."""
    if not isinstance(public, dict) or not isinstance(receipt, dict):
        raise InvalidInput('public and receipt must be JSON objects')
    if 'qualification_policy' not in public:
        return {'status':'unqualified', 'reasons':['policy_not_precommitted'],
                'warning':'legacy v1.4 evaluation cannot retroactively gain precommitted qualification'}
    policy = check_policy(public['qualification_policy'])
    reasons = []
    metrics = receipt.get('metrics')
    if not isinstance(metrics, dict) or not {'test','shifted_test'}.issubset(metrics):
        reasons.append('required_test_domains_missing')
        metrics = metrics if isinstance(metrics,dict) else {}
    summaries = {}
    for group, count_min in (('test',policy['min_test']),('shifted_test',policy['min_shifted'])):
        m = metrics.get(group)
        if not isinstance(m, dict):
            continue
        total, answered, correct = m['count'],m['answered'],m['correct']
        if any(type(x) is not int for x in (total,answered,correct)) or not 0 <= correct <= answered <= total:
            raise RuleRejected('invalid receipt metric counts')
        if total < count_min:
            reasons.append(f'{group}_too_small')
        coverage = answered/total if total else 0.0
        accuracy = correct/total if total else 0.0
        lcb = wilson_lower(correct,total)
        baseline = m['train_majority_baseline_accuracy']
        if type(baseline) not in (float,int) or not 0 <= baseline <= 1:
            raise RuleRejected('invalid receipt baseline')
        gain = accuracy-baseline
        summaries[group] = {'count':total,'answered':answered,'correct':correct,
                            'coverage':coverage,'overall_accuracy':accuracy,
                            'accuracy_wilson_95_lower':lcb,
                            'majority_baseline_accuracy':baseline,'absolute_baseline_gain':gain}
        if coverage < policy['min_coverage']:
            reasons.append(f'{group}_coverage_below_threshold')
        if accuracy < policy['min_overall_accuracy']:
            reasons.append(f'{group}_accuracy_below_threshold')
        if lcb < policy['min_wilson_lower']:
            reasons.append(f'{group}_uncertainty_bound_below_threshold')
        if gain < policy['min_baseline_gain']:
            reasons.append(f'{group}_baseline_gain_below_threshold')
    return {'status':'policy_pass' if not reasons else 'unqualified',
            'reasons':reasons, 'policy':policy, 'policy_digest':digest(policy),
            'evaluation_id':public.get('evaluation_id'), 'rule_digest':receipt.get('rule_digest'),
            'domains':summaries,
            'qualification_scope':'precommitted, evaluator-verified, policy-relative local scoring; NOT independent dataset provenance or externally reproduced efficacy',
            'baseline_note':'baseline gain is descriptive only, not a paired significance test'}
