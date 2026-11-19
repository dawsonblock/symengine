"""Intentionally tiny declarative AST. Absolutely no Python eval/exec.

Every operation is declared exactly once, as an :class:`OpSpec` in the
ordered :data:`OPS` registry: its shape, argument and result types, total
evaluation function, cost, commutativity, optional Z3 translation and
structural-form tag. Validation, evaluation, cost, the enumerator, the SMT
translation, schema transfer, the LLM prompt and the benchmark's
structural comparison all read this table, so an op cannot mean one thing
in one place and another elsewhere.

``GRAMMAR_VERSION`` names the op table. Induction results carry it so a
result produced under another grammar is rejected with a clear message
instead of an opaque mismatch; stored rule ids never depend on it.
"""
from dataclasses import dataclass
from typing import Callable

from .errors import InvalidInput
from .validation import canonical, check_scalar, check_inputs, safe_result, NAME

GRAMMAR_VERSION = "sis-grammar-1"

#: Integer results beyond this magnitude are an evaluation error.
INT_BOUND = 1_000_000_000
#: Maximum AST nodes and nesting levels (leaves are level 1, like depth()).
MAX_AST_NODES = 31
MAX_AST_DEPTH = 6


@dataclass(frozen=True)
class OpSpec:
    """One grammar operation.

    ``shape`` is ``leaf`` (field/item/const), ``unary`` (``arg``),
    ``binary`` (``args``) or ``cond`` (``left``/``right``/``then``/
    ``else``). ``arg_types`` lists the operand types (``int``, ``str``,
    ``bool`` or ``any``); for a ``cond`` it lists the two compared operand
    types, and the result is the type of the branches (``result_type``
    ``branch``). ``fn`` is the total evaluation function on Python values:
    it either returns a value or raises :class:`InvalidInput`; for a
    ``cond`` it returns whether the ``then`` branch is taken. ``cost`` is
    the node's own cost; an AST's cost adds its children's. ``z3`` maps the
    z3 module and translated operands to a z3 term, or is ``None`` when the
    op has no SMT translation. ``tag`` names the node in structural forms.
    """

    name: str
    shape: str
    arg_types: tuple
    result_type: str
    fn: Callable | None
    cost: int
    commutative: bool = False
    z3: Callable | None = None
    tag: str = ""

    @property
    def form_tag(self):
        return self.tag or self.name


def _require_int(value):
    if type(value) is not int:
        raise InvalidInput("numeric operation requires integer operands")


def _require_str(value):
    if type(value) is not str:
        raise InvalidInput("text operation requires string")


def _bounded(value):
    if abs(value) > INT_BOUND:
        raise InvalidInput("integer expression exceeded safe bounds")
    return value


def _int2(compute):
    def apply(a, b):
        _require_int(a)
        _require_int(b)
        return _bounded(compute(a, b))
    return apply


def _int1(compute):
    def apply(v):
        _require_int(v)
        return compute(v)
    return apply


def _str1(compute):
    def apply(v):
        _require_str(v)
        return compute(v)
    return apply


def _z3_if(z3, cond, then, other):
    return z3.If(cond, then, other)


_SPECS = (
    OpSpec("field", "leaf", (), "any", None, 1),
    OpSpec("item", "leaf", (), "any", None, 1),
    OpSpec("const", "leaf", (), "any", None, 2),
    OpSpec("add", "binary", ("int", "int"), "int", _int2(lambda a, b: a + b),
           2, True, lambda z3, x, y: x + y),
    OpSpec("sub", "binary", ("int", "int"), "int", _int2(lambda a, b: a - b),
           2, False, lambda z3, x, y: x - y),
    OpSpec("mul", "binary", ("int", "int"), "int", _int2(lambda a, b: a * b),
           2, True, lambda z3, x, y: x * y),
    OpSpec("min", "binary", ("int", "int"), "int", _int2(min), 2, True,
           lambda z3, x, y: z3.If(x <= y, x, y)),
    OpSpec("max", "binary", ("int", "int"), "int", _int2(max), 2, True,
           lambda z3, x, y: z3.If(x >= y, x, y)),
    OpSpec("absdiff", "binary", ("int", "int"), "int",
           _int2(lambda a, b: abs(a - b)), 2, True,
           lambda z3, x, y: z3.If(x - y >= 0, x - y, y - x)),
    OpSpec("eq", "binary", ("any", "any"), "bool", lambda a, b: a == b, 2,
           True, lambda z3, x, y: x == y),
    OpSpec("neg", "unary", ("int",), "int", _int1(lambda v: -v), 2, False,
           lambda z3, x: -x),
    OpSpec("abs", "unary", ("int",), "int", _int1(abs), 2, False,
           lambda z3, x: z3.If(x >= 0, x, -x)),
    OpSpec("upper", "unary", ("str",), "str", _str1(str.upper), 2),
    OpSpec("lower", "unary", ("str",), "str", _str1(str.lower), 2),
    OpSpec("reverse", "unary", ("str",), "str", _str1(lambda v: v[::-1]), 2),
    OpSpec("if_eq", "cond", ("any", "any"), "branch", lambda a, b: a == b, 4,
           False, lambda z3, x, y: x == y),
)

#: Ordered op registry: name -> OpSpec. Insertion order is significant
#: (prompt text and enumeration order derive from it).
OPS = {spec.name: spec for spec in _SPECS}
LEAVES = frozenset(name for name, s in OPS.items() if s.shape == "leaf")
BINARY = frozenset(name for name, s in OPS.items() if s.shape == "binary")
UNARY = frozenset(name for name, s in OPS.items() if s.shape == "unary")
CONDITIONAL = frozenset(name for name, s in OPS.items() if s.shape == "cond")
COMMUTATIVE = frozenset(name for name, s in OPS.items() if s.commutative)
COND_KEYS = ("left", "right", "then", "else")


def ops_of(shape, *, arg_types=None, result_type=None):
    """Registry entries of one shape, optionally filtered by types."""
    return [spec for spec in OPS.values()
            if spec.shape == shape
            and (arg_types is None or spec.arg_types == tuple(arg_types))
            and (result_type is None or spec.result_type == result_type)]


def children(ast):
    """The child ASTs of a node, in a fixed order."""
    shape = OPS[ast["op"]].shape
    if shape == "unary":
        return [ast["arg"]]
    if shape == "binary":
        return list(ast["args"])
    if shape == "cond":
        return [ast[key] for key in COND_KEYS]
    return []


def rebuild(ast, new_children):
    """A copy of ``ast`` with its children replaced (same order as children())."""
    shape = OPS[ast["op"]].shape
    if shape == "unary":
        return {"op": ast["op"], "arg": new_children[0]}
    if shape == "binary":
        return {"op": ast["op"], "args": list(new_children)}
    if shape == "cond":
        return {"op": ast["op"], **dict(zip(COND_KEYS, new_children))}
    return dict(ast)


def validate_ast(ast, *, depth=1, budget=None):
    """Validate shape, op names and limits; ``depth`` counts the root as 1."""
    budget = [0] if budget is None else budget
    budget[0] += 1
    if budget[0] > MAX_AST_NODES or depth > MAX_AST_DEPTH or not isinstance(ast, dict):
        raise InvalidInput(
            f"expression exceeds {MAX_AST_NODES} nodes / {MAX_AST_DEPTH} levels "
            "or is not an object")
    op = ast.get("op")
    if not isinstance(op, str) or op not in OPS:
        raise InvalidInput(f"unsupported expression op: {str(op)[:30]}")
    spec = OPS[op]
    if op == "field":
        if set(ast) != {"op", "name"} or not isinstance(ast["name"], str) or not NAME.fullmatch(ast["name"]):
            raise InvalidInput("invalid field expression")
    elif op == "item":
        if set(ast) != {"op", "name", "index"} or not isinstance(ast["name"], str) or not NAME.fullmatch(ast["name"]) or type(ast["index"]) is not int or not (0 <= ast["index"] < 16):
            raise InvalidInput("invalid item expression")
    elif op == "const":
        if set(ast) != {"op", "value"}:
            raise InvalidInput("invalid const expression")
        check_scalar(ast["value"])
    elif spec.shape == "binary":
        if set(ast) != {"op", "args"} or not isinstance(ast["args"], list) or len(ast["args"]) != 2:
            raise InvalidInput("binary ops require exactly two args")
        for child in ast["args"]:
            validate_ast(child, depth=depth+1, budget=budget)
    elif spec.shape == "unary":
        if set(ast) != {"op", "arg"}:
            raise InvalidInput("unary ops require one arg")
        validate_ast(ast["arg"], depth=depth+1, budget=budget)
    else:
        if set(ast) != {"op", *COND_KEYS}:
            raise InvalidInput(f"{op} requires left, right, then, else")
        for key in COND_KEYS:
            validate_ast(ast[key], depth=depth+1, budget=budget)
    return ast


def evaluate(ast, inputs):
    # Public use validates first; recursion below trusts only an already validated AST.
    validate_ast(ast)
    inputs = check_inputs(inputs)
    return safe_result(_eval(ast, inputs))


def _eval(ast, inputs):
    op = ast["op"]
    if op == "field":
        value = inputs[ast["name"]]
        if isinstance(value, list):
            raise InvalidInput("field cannot return a list")
        return value
    if op == "item":
        value = inputs[ast["name"]]
        if not isinstance(value, list):
            raise InvalidInput("item requires list input")
        return value[ast["index"]]
    if op == "const":
        return ast["value"]
    spec = OPS[op]
    if spec.shape == "cond":
        taken = spec.fn(_eval(ast["left"], inputs), _eval(ast["right"], inputs))
        return _eval(ast["then" if taken else "else"], inputs)
    if spec.shape == "unary":
        return spec.fn(_eval(ast["arg"], inputs))
    a, b = (_eval(x, inputs) for x in ast["args"])
    return spec.fn(a, b)


def apply_op(op, *values):
    """Apply a non-leaf, non-conditional op to already evaluated operands."""
    return OPS[op].fn(*values)


def cost(ast):
    spec = OPS[ast["op"]]
    return spec.cost + sum(cost(child) for child in children(ast))


def depth(ast):
    """Nesting depth of a validated AST; leaves are depth 1."""
    kids = children(ast)
    return 1 + (max(depth(child) for child in kids) if kids else 0)


def fingerprint(ast):
    return canonical(ast)


def structural_form(ast):
    """Commutative-normalised form for structural comparison of rules."""
    op = ast["op"]
    if op == "field":
        return ("field", ast["name"])
    if op == "item":
        return ("item", ast["name"], ast["index"])
    if op == "const":
        return ("const", type(ast["value"]).__name__, ast["value"])
    spec = OPS[op]
    forms = tuple(structural_form(child) for child in children(ast))
    if spec.commutative:
        forms = tuple(sorted(forms))
    return (spec.form_tag,) + forms


def z3_translate(ast, variables, z3):
    """Translate an AST to a z3 term over ``variables``.

    Raises ``ValueError`` for an op without a translation or a non-integer
    constant, so callers can report the expression as unsupported.
    """
    op = ast["op"]
    if op == "field":
        return variables[ast["name"]]
    if op == "item":
        return variables[ast["name"]][ast["index"]]
    if op == "const":
        if type(ast["value"]) is not int:
            raise ValueError("numeric only")
        return z3.IntVal(ast["value"])
    spec = OPS[op]
    if spec.z3 is None:
        raise ValueError("unsupported op for Z3")
    if spec.shape == "cond":
        left, right, then, other = (
            z3_translate(ast[key], variables, z3) for key in COND_KEYS)
        return _z3_if(z3, spec.z3(z3, left, right), then, other)
    return spec.z3(z3, *(z3_translate(child, variables, z3)
                         for child in children(ast)))


def prompt_grammar():
    """The allowed-AST sentence used in LLM proposal prompts."""
    binary = "/".join(s.name for s in OPS.values() if s.shape == "binary")
    unary = "/".join(s.name for s in OPS.values() if s.shape == "unary")
    cond = "/".join(s.name for s in OPS.values() if s.shape == "cond")
    return ("Allowed AST: field(name), item(name,index), const(value), "
            f"binary {binary}(args:[AST,AST]), "
            f"unary {unary}(arg:AST), "
            f"{cond}(left,right,then,else).")
