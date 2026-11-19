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
from .validation import canonical, check_scalar, check_inputs, safe_result, NAME, MAX_TEXT

GRAMMAR_VERSION = "sis-grammar-2"

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
    op has no SMT translation; ``z3_guard`` returns the condition under
    which the op is defined (a nonzero divisor). ``tag`` names the node in
    structural forms. ``const_arg`` is the index of an operand that must be
    a literal integer constant in ``[0, MAX_TEXT]`` (slice lengths).
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
    z3_guard: Callable | None = None
    const_arg: int | None = None

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


def _floordiv(a, b):
    _require_int(a)
    _require_int(b)
    if b == 0:
        # A zero divisor makes the expression undefined on this record; it
        # is an evaluation error, never a fitted value.
        raise InvalidInput("division by zero")
    return _bounded(a // b)


def _mod(a, b):
    _require_int(a)
    _require_int(b)
    if b == 0:
        raise InvalidInput("modulo by zero")
    return a % b


def _z3_floordiv(z3, x, y):
    # Python floors toward negative infinity; z3 integer division is
    # Euclidean, which agrees with flooring for a positive divisor.
    return z3.If(y > 0, x / y, (-x) / (-y))


def _z3_mod(z3, x, y):
    return x - y * _z3_floordiv(z3, x, y)


def _cmp(compute):
    def apply(a, b):
        _require_int(a)
        _require_int(b)
        return compute(a, b)
    return apply


def _concat(a, b):
    _require_str(a)
    _require_str(b)
    if len(a) + len(b) > MAX_TEXT:
        raise InvalidInput("string expression exceeded safe length")
    return a + b


def _slice_length(n):
    if type(n) is not int or not 0 <= n <= MAX_TEXT:
        raise InvalidInput("slice length must be an integer in [0, 128]")
    return n


def _slice_prefix(s, n):
    _require_str(s)
    return s[:_slice_length(n)]


def _slice_suffix(s, n):
    _require_str(s)
    n = _slice_length(n)
    return s[len(s) - n:] if n < len(s) else s


def _contains(a, b):
    _require_str(a)
    _require_str(b)
    return b in a


def _len(s):
    _require_str(s)
    return len(s)


def _str_of_int(v):
    _require_int(v)
    return str(v)


def _lt(a, b):
    _require_int(a)
    _require_int(b)
    return a < b


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
    # --- grammar 2 -------------------------------------------------------
    OpSpec("floordiv", "binary", ("int", "int"), "int", _floordiv, 2, False,
           _z3_floordiv, z3_guard=lambda z3, x, y: y != 0),
    OpSpec("mod", "binary", ("int", "int"), "int", _mod, 2, False, _z3_mod,
           z3_guard=lambda z3, x, y: y != 0),
    OpSpec("lt", "binary", ("int", "int"), "bool", _cmp(lambda a, b: a < b), 2,
           False, lambda z3, x, y: x < y),
    OpSpec("le", "binary", ("int", "int"), "bool", _cmp(lambda a, b: a <= b), 2,
           False, lambda z3, x, y: x <= y),
    OpSpec("gt", "binary", ("int", "int"), "bool", _cmp(lambda a, b: a > b), 2,
           False, lambda z3, x, y: x > y),
    OpSpec("concat", "binary", ("str", "str"), "str", _concat, 2),
    OpSpec("slice_prefix", "binary", ("str", "int"), "str", _slice_prefix, 2,
           const_arg=1),
    OpSpec("slice_suffix", "binary", ("str", "int"), "str", _slice_suffix, 2,
           const_arg=1),
    OpSpec("contains", "binary", ("str", "str"), "bool", _contains, 2),
    OpSpec("len", "unary", ("str",), "int", _len, 2),
    OpSpec("str_of_int", "unary", ("int",), "str", _str_of_int, 2),
    OpSpec("if_lt", "cond", ("int", "int"), "branch", _lt, 4, False,
           lambda z3, x, y: x < y),
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
        if spec.const_arg is not None:
            fixed = ast["args"][spec.const_arg]
            if (not isinstance(fixed, dict) or fixed.get("op") != "const"
                    or type(fixed.get("value")) is not int
                    or not 0 <= fixed["value"] <= MAX_TEXT):
                raise InvalidInput(f"{op} length must be a constant integer in [0, {MAX_TEXT}]")
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


def z3_translate(ast, variables, z3, guards=None):
    """Translate an AST to a z3 term over ``variables``.

    Raises ``ValueError`` for an op without a translation or a non-integer
    constant, so callers can report the expression as unsupported. When
    ``guards`` is a list, the definedness condition of every partial op
    (a nonzero divisor) is appended to it; requiring all of them is
    conservative inside untaken branches, never unsound, because every
    witness is re-checked by the runtime evaluator.
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
            z3_translate(ast[key], variables, z3, guards) for key in COND_KEYS)
        return _z3_if(z3, spec.z3(z3, left, right), then, other)
    operands = [z3_translate(child, variables, z3, guards)
                for child in children(ast)]
    if spec.z3_guard is not None and guards is not None:
        guards.append(spec.z3_guard(z3, *operands))
    return spec.z3(z3, *operands)


def prompt_grammar():
    """The allowed-AST sentence used in LLM proposal prompts."""
    binary = "/".join(s.name for s in OPS.values() if s.shape == "binary")
    unary = "/".join(s.name for s in OPS.values() if s.shape == "unary")
    cond = "/".join(s.name for s in OPS.values() if s.shape == "cond")
    fixed = "/".join(s.name for s in OPS.values() if s.const_arg is not None)
    note = (f" The second arg of {fixed} must be const(non-negative integer)."
            if fixed else "")
    return ("Allowed AST: field(name), item(name,index), const(value), "
            f"binary {binary}(args:[AST,AST]), "
            f"unary {unary}(arg:AST), "
            f"{cond}(left,right,then,else).{note}")
