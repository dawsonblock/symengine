"""Pure, bounded interpreter for v1.7 procedural skills.

No Python eval/exec, shell, filesystem, imports, network or ambient effects.
Programs accept only checked SIS input records and return bounded JSON scalars.
"""
import re
from .errors import InvalidInput
from .validation import check_inputs, check_scalar, input_schema, safe_result, NAME

FNS = {'add', 'sub', 'mul', 'min', 'max', 'eq', 'lt', 'gt', 'and', 'or', 'concat'}
UNARY = {'neg', 'abs', 'not', 'upper', 'lower'}
HEX_ID = re.compile(r'^[0-9a-f]{64}$')


def validate_program(node, *, schema=None):
    """Static shape/depth/name/budget validation; type correctness is also checked at runtime."""
    budget = [0]
    _validate(node, set(), budget, 0, 0, schema)
    return node


def _validate(node, variables, budget, depth, folds, schema):
    budget[0] += 1
    if budget[0] > 96 or depth > 12 or not isinstance(node, dict):
        raise InvalidInput('skill program exceeds 96 nodes/12 depth or has invalid AST')
    op = node.get('op')
    if op == 'input':
        if set(node) != {'op', 'name'} or not _name(node['name']):
            raise InvalidInput('invalid input reference')
        if schema is not None and node['name'] not in schema:
            raise InvalidInput('skill references absent input')
    elif op == 'var':
        if set(node) != {'op', 'name'} or not _name(node['name']) or node['name'] not in variables:
            raise InvalidInput('skill references undefined local variable')
    elif op == 'const':
        if set(node) != {'op', 'value'}:
            raise InvalidInput('invalid constant')
        check_scalar(node['value'])
    elif op == 'item':
        if (set(node) != {'op', 'field', 'index'} or not _name(node['field'])
                or type(node['index']) is not int or not 0 <= node['index'] < 16):
            raise InvalidInput('invalid fixed list index')
        if schema is not None and not isinstance(schema.get(node['field']), list):
            raise InvalidInput('item requires list field')
        if schema is not None and node['index'] >= len(schema[node['field']]):
            raise InvalidInput('list index exceeds schema length')
    elif op == 'unary':
        if set(node) != {'op', 'fn', 'arg'} or node['fn'] not in UNARY:
            raise InvalidInput('invalid unary function')
        _validate(node['arg'], variables, budget, depth+1, folds, schema)
    elif op == 'binary':
        if set(node) != {'op', 'fn', 'left', 'right'} or node['fn'] not in FNS:
            raise InvalidInput('invalid binary function')
        for key in ('left', 'right'):
            _validate(node[key], variables, budget, depth+1, folds, schema)
    elif op == 'if':
        if set(node) != {'op', 'condition', 'then', 'else'}:
            raise InvalidInput('invalid branch')
        for key in ('condition', 'then', 'else'):
            _validate(node[key], variables, budget, depth+1, folds, schema)
    elif op == 'let':
        if set(node) != {'op', 'name', 'value', 'body'} or not _name(node['name']):
            raise InvalidInput('invalid binding')
        if node['name'] in variables:
            raise InvalidInput('skill cannot shadow local variables')
        _validate(node['value'], variables, budget, depth+1, folds, schema)
        _validate(node['body'], variables | {node['name']}, budget, depth+1, folds, schema)
    elif op == 'fold':
        if (set(node) != {'op', 'field', 'item', 'acc', 'initial', 'body'}
                or not all(_name(node[x]) for x in ('field', 'item', 'acc'))
                or node['item'] == node['acc'] or node['item'] in variables or node['acc'] in variables
                or folds >= 2):
            raise InvalidInput('invalid or excessively nested bounded fold')
        if schema is not None and not isinstance(schema.get(node['field']), list):
            raise InvalidInput('fold requires list input')
        _validate(node['initial'], variables, budget, depth+1, folds, schema)
        _validate(node['body'], variables | {node['item'], node['acc']}, budget, depth+1, folds+1, schema)
    elif op == 'call':
        if (set(node) != {'op', 'skill_id', 'args'} or not isinstance(node['skill_id'], str)
                or not HEX_ID.fullmatch(node['skill_id']) or not isinstance(node['args'], dict)
                or not 1 <= len(node['args']) <= 16):
            raise InvalidInput('invalid skill call')
        for name, value in node['args'].items():
            if not _name(name):
                raise InvalidInput('invalid skill-call argument name')
            _validate(value, variables, budget, depth+1, folds, schema)
    else:
        raise InvalidInput('unsupported skill program operation')


def _name(x):
    return isinstance(x, str) and NAME.fullmatch(x) is not None


def execute(program, inputs, resolver=None, *, namespace='default', _ids=(), _fuel=None):
    """Execute bounded expression. Resolver must return an active, integrity-checked skill."""
    clean = check_inputs(inputs)
    validate_program(program, schema=input_schema(clean))
    fuel = [0] if _fuel is None else _fuel
    return safe_result(_run(program, clean, {}, resolver, namespace, _ids, fuel))


def _run(node, inputs, scope, resolver, namespace, ids, fuel):
    fuel[0] += 1
    if fuel[0] > 2048:
        raise InvalidInput('skill exceeded execution fuel')
    op = node['op']
    if op == 'input':
        value = inputs[node['name']]
        if isinstance(value, list):
            raise InvalidInput('whole list cannot be used as a scalar')
        return value
    if op == 'item':
        return inputs[node['field']][node['index']]
    if op == 'var':
        return scope[node['name']]
    if op == 'const':
        return node['value']
    if op == 'unary':
        value = _run(node['arg'], inputs, scope, resolver, namespace, ids, fuel)
        fn = node['fn']
        if fn in {'neg', 'abs'}:
            _type(value, int)
            return safe_result(-value if fn == 'neg' else abs(value))
        if fn == 'not':
            _type(value, bool)
            return not value
        _type(value, str)
        return safe_result(value.upper() if fn == 'upper' else value.lower())
    if op == 'binary':
        a = _run(node['left'], inputs, scope, resolver, namespace, ids, fuel)
        b = _run(node['right'], inputs, scope, resolver, namespace, ids, fuel)
        fn = node['fn']
        if fn == 'eq':
            return type(a) is type(b) and a == b
        if fn in {'and', 'or'}:
            _type(a, bool)
            _type(b, bool)
            return a and b if fn == 'and' else a or b
        if fn == 'concat':
            _type(a, str)
            _type(b, str)
            return safe_result(a + b)
        _type(a, int)
        _type(b, int)
        if fn == 'add': out = a + b
        elif fn == 'sub': out = a - b
        elif fn == 'mul': out = a * b
        elif fn == 'min': out = min(a, b)
        elif fn == 'max': out = max(a, b)
        elif fn == 'lt': return a < b
        else: return a > b
        return safe_result(out)
    if op == 'if':
        condition = _run(node['condition'], inputs, scope, resolver, namespace, ids, fuel)
        _type(condition, bool)
        return _run(node['then'] if condition else node['else'], inputs, scope, resolver, namespace, ids, fuel)
    if op == 'let':
        value = safe_result(_run(node['value'], inputs, scope, resolver, namespace, ids, fuel))
        return _run(node['body'], inputs, {**scope, node['name']: value}, resolver, namespace, ids, fuel)
    if op == 'fold':
        seq = inputs[node['field']]
        if not isinstance(seq, list):
            raise InvalidInput('fold field is not a list')
        acc = safe_result(_run(node['initial'], inputs, scope, resolver, namespace, ids, fuel))
        for element in seq:
            acc = safe_result(_run(node['body'], inputs, {**scope, node['item']: element, node['acc']: acc}, resolver, namespace, ids, fuel))
        return acc
    if op == 'call':
        sid = node['skill_id']
        if resolver is None or sid in ids or len(ids) >= 4:
            raise InvalidInput('skill-call dependency unavailable, cyclic or too deep')
        record = resolver(sid)
        if not record or record['namespace'] != namespace or record['status'] != 'active':
            raise InvalidInput('skill-call dependency is not active in this namespace')
        call_inputs = {name: safe_result(_run(value, inputs, scope, resolver, namespace, ids, fuel))
                       for name, value in node['args'].items()}
        call_inputs = check_inputs(call_inputs)
        if input_schema(call_inputs) != record['schema']:
            raise InvalidInput('skill-call dependency schema mismatch')
        validate_program(record['program'], schema=record['schema'])
        return _run(record['program'], call_inputs, {}, resolver, namespace, ids+(sid,), fuel)
    raise InvalidInput('unreachable invalid skill expression')


def _type(value, cls):
    if type(value) is not cls:
        raise InvalidInput('skill operation received wrong operand type')
