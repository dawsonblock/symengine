"""v2.4 bounded, non-executing Python code repair learning.

Only pure, AST-interpretable function bodies are permitted; NO eval, exec,
Python import, shell, tests-as-process, or arbitrary file write occurs here.
A coding agent supplies operator choices and evaluator-owned expected values.
Hash chains demonstrate local consistency, not external provenance.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import difflib
import hashlib
import re
from .errors import InvalidInput
from .validation import digest

MAX_SOURCE = 48_000
MAX_CASES = 32
MAX_ABS = 1_000_000
MAX_OUTPUT = 1_000_000_000
OPS = {'Add':ast.Add, 'Sub':ast.Sub, 'Mult':ast.Mult, 'FloorDiv':ast.FloorDiv}
NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z', re.ASCII)
FILE = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,90}\.py\Z', re.ASCII)


def _name(value, label):
    if type(value) is not str or not NAME.fullmatch(value):
        raise InvalidInput(f'invalid {label}')
    return value


def _source(value):
    if type(value) is not str or not 1 <= len(value.encode('utf8')) <= MAX_SOURCE or '\x00' in value:
        raise InvalidInput('Python source must be UTF-8 text of 1-48000 bytes')
    return value


def _file(value):
    if type(value) is not str or not FILE.fullmatch(value) or value.startswith('.'):
        raise InvalidInput('single flat .py filename required; paths are not accepted')
    return value


def _parse(source, function):
    _source(source)
    _name(function, 'function')
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise InvalidInput('invalid Python source') from exc
    if len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef):
        raise InvalidInput('only one top-level pure function is allowed')
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function]
    if len(functions) != 1:
        raise InvalidInput('expected exactly one top-level named function')
    fn=functions[0]
    args=fn.args
    if (fn.decorator_list or args.posonlyargs or args.kwonlyargs or args.kwarg or args.vararg or
            args.defaults or args.kw_defaults or len(args.args) not in (1,2,3,4) or
            len({x.arg for x in args.args}) != len(args.args) or
            len(fn.body)!=1 or not isinstance(fn.body[0],ast.Return)):
        raise InvalidInput('only undecorated, single-return pure functions with 1-4 positional args supported')
    if fn.returns is not None or any(x.annotation for x in args.args):
        raise InvalidInput('function annotations are out of scope')
    parameters=tuple(x.arg for x in args.args)
    _check_expr_syntax(fn.body[0].value, parameters)
    return tree, fn, parameters


def _check_expr_syntax(expr, parameters, depth=0):
    if depth>12:
        raise InvalidInput('expression depth exceeded')
    if isinstance(expr,ast.Constant) and type(expr.value) is int:
        if abs(expr.value)>MAX_OUTPUT:
            raise InvalidInput('literal magnitude exceeded')
    elif isinstance(expr,ast.Name) and expr.id in parameters:
        return
    elif isinstance(expr,ast.UnaryOp) and type(expr.op) is ast.USub:
        _check_expr_syntax(expr.operand,parameters,depth+1)
    elif isinstance(expr,ast.BinOp) and type(expr.op) in OPS.values():
        _check_expr_syntax(expr.left,parameters,depth+1)
        _check_expr_syntax(expr.right,parameters,depth+1)
    else:
        raise InvalidInput('unapproved Python syntax; no code executed')


def _eval_expr(expr, variables, depth=0):
    if depth>12:
        raise InvalidInput('expression depth exceeded')
    if isinstance(expr,ast.Constant) and type(expr.value) is int:
        n=expr.value
    elif isinstance(expr,ast.Name) and expr.id in variables:
        n=variables[expr.id]
    elif isinstance(expr,ast.UnaryOp) and isinstance(expr.op,ast.USub):
        n=-_eval_expr(expr.operand,variables,depth+1)
    elif isinstance(expr,ast.BinOp):
        lhs=_eval_expr(expr.left,variables,depth+1)
        rhs=_eval_expr(expr.right,variables,depth+1)
        if isinstance(expr.op,ast.Add): n=lhs+rhs
        elif isinstance(expr.op,ast.Sub): n=lhs-rhs
        elif isinstance(expr.op,ast.Mult): n=lhs*rhs
        elif isinstance(expr.op,ast.FloorDiv):
            if rhs==0: raise InvalidInput('division by zero')
            n=lhs//rhs
        else: raise InvalidInput('unsupported expression operation')
    else:
        raise InvalidInput('unsupported Python syntax; no code executed')
    if type(n) is not int or abs(n)>MAX_OUTPUT:
        raise InvalidInput('bounded integer result required')
    return n


def _testcases(cases, parameter_names):
    if type(cases) is not list or not 2<=len(cases)<=MAX_CASES:
        raise InvalidInput('2-32 labeled test vectors required')
    checked=[]; seen=set()
    for case in cases:
        if type(case) is not dict or set(case)!={'args','expected'} or type(case['args']) is not dict:
            raise InvalidInput('case must contain args and expected')
        args=case['args']
        if set(args)!=set(parameter_names) or any(type(v) is not int or abs(v)>MAX_ABS for v in args.values()):
            raise InvalidInput('case arguments do not match function signature or bounds')
        expected=case['expected']
        if type(expected) is not int or abs(expected)>MAX_OUTPUT:
            raise InvalidInput('expected result must be a bounded integer')
        signature=digest(args)
        if signature in seen: raise InvalidInput('duplicate test vector')
        seen.add(signature)
        checked.append({'args':{key:args[key] for key in parameter_names},'expected':expected})
    return checked


def check_cases(source, function, cases):
    """Interpret safe AST subset; never import or execute the submitted source."""
    _, fn, parameters = _parse(source,function)
    checked=_testcases(cases,parameters)
    result=[]
    for case in checked:
        try:
            actual=_eval_expr(fn.body[0].value,case['args'])
        except InvalidInput:
            actual=None
        result.append({'args':case['args'],'expected':case['expected'],'actual':actual,
                       'pass':type(actual) is int and actual==case['expected']})
    return {'cases':result,'passed':sum(item['pass'] for item in result), 'total':len(result)}


def _recipe(recipe):
    if type(recipe) is not dict or set(recipe)!={'kind','from_op','to_op'} or recipe['kind']!='binary_operator_swap':
        raise InvalidInput('only binary_operator_swap supported')
    source,target=recipe['from_op'],recipe['to_op']
    if source not in OPS or target not in OPS or source==target:
        raise InvalidInput('invalid or identical operator transition')
    return {'kind':'binary_operator_swap','from_op':source,'to_op':target}


def transform(source, function, recipe):
    recipe=_recipe(recipe)
    tree, fn, _ = _parse(source,function)
    matches=[x for x in ast.walk(fn.body[0].value) if isinstance(x,ast.BinOp) and type(x.op) is OPS[recipe['from_op']]]
    if len(matches)!=1:
        raise InvalidInput('target operator not unique within function expression')
    matches[0].op=OPS[recipe['to_op']]()
    result=ast.unparse(ast.fix_missing_locations(tree))+'\n'
    _source(result)
    # AST reparse and conservative interpreter check, but no source execution.
    _parse(result,function)
    return result


def _capture_body(source, filename, function, recipe, cases):
    _file(filename)
    _,_,params=_parse(source,function)
    checked=_testcases(cases,params)
    edited=transform(source,function,recipe)
    before=check_cases(source,function,checked)
    after=check_cases(edited,function,checked)
    if before['passed'] == before['total']:
        raise InvalidInput('recorded edit had no failing examples to repair')
    body={'version':1,'filename':filename,'function':function,'source':source,
          'recipe':_recipe(recipe),'cases':checked,
          'original_sha256':hashlib.sha256(source.encode('utf8')).hexdigest(),
          'patched_sha256':hashlib.sha256(edited.encode('utf8')).hexdigest(),
          'before':before,'after':after,
          'evidence_scope':'local AST interpreter; caller supplies test labels'}
    return body


def capture_repair(request):
    if type(request) is not dict or set(request)!={'source','filename','function','recipe','cases'}:
        raise InvalidInput('capture requires source, filename, function, recipe, cases')
    body=_capture_body(**request)
    return {**deepcopy(body),'capture_digest':digest(body)}


def replay_repair(capture):
    keys={'version','filename','function','source','recipe','cases',
          'original_sha256','patched_sha256','before','after','evidence_scope','capture_digest'}
    if type(capture) is not dict or set(capture)!=keys:
        raise InvalidInput('invalid code capture envelope')
    try:
        body=_capture_body(capture['source'],capture['filename'],capture['function'],capture['recipe'],capture['cases'])
    except (TypeError,KeyError) as exc:
        raise InvalidInput('malformed code capture') from exc
    if capture!={**body,'capture_digest':digest(body)}:
        raise InvalidInput('code capture differs from independent AST replay')
    return {'recipe':body['recipe'],'filename':body['filename'],'function':body['function'],
            'source_digest':body['original_sha256'],'patched_digest':body['patched_sha256'],
            'capture_digest':capture['capture_digest'],'before':body['before'],'after':body['after']}


def preview_patch(request, recipe):
    if type(request) is not dict or set(request)!={'source','filename','function'}:
        raise InvalidInput('preview requires source, filename and function')
    _file(request['filename'])
    patched=transform(request['source'],request['function'],recipe)
    diff=''.join(difflib.unified_diff(request['source'].splitlines(True),patched.splitlines(True),
                  fromfile='a/'+request['filename'],tofile='b/'+request['filename']))
    if len(diff)>100_000: raise InvalidInput('diff exceeds limit')
    return {'status':'preview','original_sha256':hashlib.sha256(request['source'].encode('utf8')).hexdigest(),
            'patched_sha256':hashlib.sha256(patched.encode('utf8')).hexdigest(),
            'diff':diff,'patched_source':patched,'authority':'read-only; no filesystem changes or Python execution'}
