"""Bounded active learning. A question is not a label or evidence of truth."""
from collections import Counter
import json
from .errors import InvalidInput
from .expression import cost, evaluate, fingerprint
from .induction import _matches, candidates, generated_probes
from .validation import canonical, check_examples, digest


def suggest_queries(train, *, max_candidates=12000, max_hypotheses=48,
                    max_probes=256, limit=5):
    """Return disagreement-provoking inputs to send to a *real* external oracle.

    The oracle must be the user, a ground-truth program or the actual environment,
    not another prediction from the same candidate pool. No rule is promoted here.
    """
    train = check_examples(train, minimum=3)
    if type(max_candidates) is not int or not 100 <= max_candidates <= 50000:
        raise InvalidInput('max_candidates must be an integer between 100 and 50000')
    if type(max_hypotheses) is not int or not 2 <= max_hypotheses <= 128:
        raise InvalidInput('max_hypotheses must be between 2 and 128')
    if type(max_probes) is not int or not 1 <= max_probes <= 256:
        raise InvalidInput('max_probes must be between 1 and 256')
    if type(limit) is not int or not 1 <= limit <= 32:
        raise InvalidInput('limit must be between 1 and 32')
    seen = set()
    hypotheses = []
    exhausted = False
    for ast, _, _, exceeded in candidates(train, max_candidates):
        if exceeded or ast is None:
            exhausted = True
            break
        if _matches(ast, train):
            fp = fingerprint(ast)
            if fp not in seen:
                seen.add(fp)
                hypotheses.append(ast)
    hypotheses.sort(key=lambda a: (cost(a), fingerprint(a)))
    full_count = len(hypotheses)
    if len(hypotheses) > max_hypotheses:
        hypotheses = hypotheses[:max_hypotheses]
    input_keys = {canonical(x['inputs']) for x in train}
    if len(input_keys) != len(train):
        raise InvalidInput('training examples must have distinct input records')
    ranked = []
    for p in generated_probes(train[0]['inputs'], max_probes):
        if canonical(p) in input_keys:
            continue
        predictions = {}
        for ast in hypotheses:
            try:
                y = evaluate(ast, p)
            except (InvalidInput, KeyError, IndexError, TypeError, OverflowError):
                continue
            predictions[digest(ast)[:16]] = y
        groups = Counter(canonical(y) for y in predictions.values())
        if len(groups) < 2:
            continue
        # Gini disagreement, plus distinct outcome count, both purely heuristic.
        total = sum(groups.values())
        disagreement = 1 - sum((v / total) ** 2 for v in groups.values())
        ranked.append((len(groups), disagreement, canonical(p), {
            'inputs': p,
            'candidate_outputs': [json.loads(x) for x in sorted(groups, key=lambda k: (type(json.loads(k)).__name__, json.loads(k)))],
            'hypotheses_considered': total,
            'disagreement_score': round(disagreement, 6),
            'oracle_label_required': True,
        }))
    ranked.sort(key=lambda v: (-v[0], -v[1], v[2]))
    return {
        'status': 'oracle_queries' if ranked else 'no_distinguishing_query',
        'queries': [item[3] for item in ranked[:limit]],
        'hypotheses_matching_training': full_count,
        'hypotheses_sampled': len(hypotheses),
        'hypothesis_pool_limited': full_count > max_hypotheses,
        'candidate_search_truncated': exhausted,
        'train_digest': digest(train),
        'evidence': 'unlabeled hypothesis disagreements only; no answer is verified',
    }
