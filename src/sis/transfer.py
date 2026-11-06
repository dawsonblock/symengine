"""Explicit, read-only schema transfer of validated source rules.

The mapping is selected by the operator, not inferred from held-out labels.
Passing exact schema checks proves *structural compatibility*, not target accuracy.
"""
from .errors import InvalidInput
from .expression import validate_ast, evaluate
from .validation import NAME, check_inputs, input_schema, digest


def map_expression(expression, source_schema, target_inputs, field_map):
    """Return remapped AST, rejecting mismatched/partial/aliased field maps.

    All source fields must be mapped bijectively to target fields of the exact
    same scalar/list type. No target labels are consumed during mapping.
    """
    validate_ast(expression)
    inputs = check_inputs(target_inputs)
    target_schema = input_schema(inputs)
    if not isinstance(source_schema, dict) or not source_schema:
        raise InvalidInput('source schema must be a nonempty mapping')
    if not isinstance(field_map, dict) or set(field_map) != set(source_schema):
        raise InvalidInput('field_map must map every source field exactly once')
    targets = list(field_map.values())
    if any(type(name) is not str or not NAME.fullmatch(name) for name in targets):
        raise InvalidInput('field_map target identifiers are invalid')
    if len(set(targets)) != len(targets) or set(targets) != set(target_schema):
        raise InvalidInput('field_map must bijectively cover target fields')
    for source, target in field_map.items():
        if source_schema[source] != target_schema[target]:
            raise InvalidInput('mapped field types or list lengths differ')

    def rewrite(node):
        op = node['op']
        if op in ('field', 'item'):
            return {**node, 'name': field_map[node['name']]}
        if op == 'const':
            return dict(node)
        if op == 'if_eq':
            return {'op':op, **{k:rewrite(node[k]) for k in ('left','right','then','else')}}
        if 'arg' in node:
            return {'op':op, 'arg':rewrite(node['arg'])}
        return {'op':op, 'args':[rewrite(x) for x in node['args']]}

    mapped = rewrite(expression)
    validate_ast(mapped)
    return mapped


def transfer_result(source_rule, target_inputs, field_map):
    """Safely apply an operator-mapped source rule to one target record."""
    mapped = map_expression(source_rule['rule'], source_rule['schema'], target_inputs, field_map)
    from .errors import InvalidInput
    try:
        output = evaluate(mapped, target_inputs)
    except (InvalidInput, TypeError, KeyError, IndexError, OverflowError, ValueError):
        return {'status':'abstain','reason':'mapped expression cannot evaluate target record',
                'source_rule_id':source_rule['id'], 'transfer_digest':digest(mapped),
                'qualification':'unvalidated_target_hypothesis'}
    return {'status':'predicted', 'output':output, 'source_rule_id':source_rule['id'],
            'transfer_digest':digest(mapped), 'qualification':'unvalidated_target_hypothesis',
            'warning':'structural schema transfer only; no target-domain labels or accuracy verification'}
