"""Strict split-local benchmark: evaluation is not independent third-party evidence."""
from collections import Counter
from .errors import InvalidInput
from .expression import evaluate
from .induction import induce
from .validation import check_examples, canonical, digest, input_schema


def benchmark(request):
    """Fit on train, gate on validation, inspect held-out test exactly once per call.

    This API cannot ensure a caller has *not* used the test set on prior calls.
    Tests remain caller-supplied; there is no claim of external independence.
    """
    if not isinstance(request, dict):
        raise InvalidInput('benchmark request must be a JSON object')
    train = check_examples(request.get('train'), minimum=3)
    validation = check_examples(request.get('validation'), minimum=2)
    test = check_examples(request.get('test'), minimum=2)
    schema = input_schema(train[0]['inputs'])
    typ = type(train[0]['output'])
    seen = set()
    for name, partition in [('train', train), ('validation', validation), ('test', test)]:
        for ex in partition:
            if input_schema(ex['inputs']) != schema or type(ex['output']) is not typ:
                raise InvalidInput('all splits must share input schema and output type')
            identifier = canonical(ex['inputs'])
            if identifier in seen:
                raise InvalidInput('train/validation/test inputs must be mutually disjoint')
            seen.add(identifier)
    induction = induce(train, validation, namespace=request.get('namespace', 'benchmark'),
                       max_candidates=request.get('max_candidates', 12000),
                       use_z3=request.get('use_z3', False))
    train_outputs = [canonical(e['output']) for e in train]
    counts = Counter(train_outputs)
    # Deterministic majority-value baseline; not optimized against test.
    majority = sorted(counts, key=lambda x: (-counts[x], x))[0]
    baseline_hits = sum(canonical(e['output']) == majority for e in test)
    predictions = []
    if induction['status'] == 'locally_validated':
        for ex in test:
            try:
                predictions.append(evaluate(induction['rule'], ex['inputs']))
            except (InvalidInput, KeyError, IndexError, OverflowError, TypeError):
                predictions.append(None)
    covered = sum(v is not None for v in predictions)
    correct = sum(type(v) is type(ex['output']) and v == ex['output']
                  for v, ex in zip(predictions, test) if v is not None)
    return {
        'status': 'evaluated' if induction['status'] == 'locally_validated' else 'abstained',
        'induction_status': induction['status'],
        'counts': {'train': len(train), 'validation': len(validation), 'test': len(test)},
        'split_digests': {'train': digest(train), 'validation': digest(validation), 'test': digest(test)},
        'rule_digest': digest(induction['rule']) if induction['rule'] is not None else None,
        'test_covered': covered, 'test_correct': correct,
        'coverage': covered / len(test),
        'selective_accuracy': correct / covered if covered else None,
        'overall_accuracy': correct / len(test),
        'train_majority_baseline_accuracy': baseline_hits / len(test),
        'source': 'caller-supplied holdout; independence, non-reuse, and label authenticity not verified',
        'promoted': False,
    }
