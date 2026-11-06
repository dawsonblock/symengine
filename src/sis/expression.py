"""Intentionally tiny declarative AST. Absolutely no Python eval/exec."""
from .errors import InvalidInput
from .validation import canonical, check_scalar, check_inputs, safe_result, NAME

BINARY = {"add", "sub", "mul", "min", "max", "absdiff", "eq"}
UNARY = {"neg", "abs", "upper", "lower", "reverse"}
OPS = {"field", "item", "const", "if_eq"} | BINARY | UNARY


def validate_ast(ast, *, depth=0, budget=None):
    budget = [0] if budget is None else budget
    budget[0] += 1
    if budget[0] > 31 or depth > 5 or not isinstance(ast, dict):
        raise InvalidInput("expression exceeds 31 nodes / 5 levels or is not an object")
    op = ast.get("op")
    if op not in OPS:
        raise InvalidInput(f"unsupported expression op: {str(op)[:30]}")
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
    elif op in BINARY:
        if set(ast) != {"op", "args"} or not isinstance(ast["args"], list) or len(ast["args"]) != 2:
            raise InvalidInput("binary ops require exactly two args")
        for child in ast["args"]:
            validate_ast(child, depth=depth+1, budget=budget)
    elif op in UNARY:
        if set(ast) != {"op", "arg"}:
            raise InvalidInput("unary ops require one arg")
        validate_ast(ast["arg"], depth=depth+1, budget=budget)
    else:
        if set(ast) != {"op", "left", "right", "then", "else"}:
            raise InvalidInput("if_eq requires left, right, then, else")
        for key in ("left", "right", "then", "else"):
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
    if op == "if_eq":
        branch = "then" if _eval(ast["left"], inputs) == _eval(ast["right"], inputs) else "else"
        return _eval(ast[branch], inputs)
    if op in UNARY:
        v = _eval(ast["arg"], inputs)
        if op in {"neg", "abs"}:
            _require_int(v)
            return -v if op == "neg" else abs(v)
        if type(v) is not str:
            raise InvalidInput("text operation requires string")
        return {"upper": str.upper, "lower": str.lower, "reverse": lambda x: x[::-1]}[op](v)
    a, b = (_eval(x, inputs) for x in ast["args"])
    if op == "eq":
        return a == b
    _require_int(a)
    _require_int(b)
    if op == "add": value = a + b
    elif op == "sub": value = a - b
    elif op == "mul": value = a * b
    elif op == "min": value = min(a,b)
    elif op == "max": value = max(a,b)
    else: value = abs(a-b)
    if abs(value) > 1_000_000_000:
        raise InvalidInput("integer expression exceeded safe bounds")
    return value


def _require_int(value):
    if type(value) is not int:
        raise InvalidInput("numeric operation requires integer operands")


def cost(ast):
    op = ast["op"]
    if op in ("field", "item"):
        return 1
    if op == "const":
        return 2
    if op in UNARY:
        return 2 + cost(ast["arg"])
    if op in BINARY:
        return 2 + sum(map(cost, ast["args"]))
    return 4 + sum(cost(ast[x]) for x in ("left", "right", "then", "else"))


def fingerprint(ast):
    return canonical(ast)
