"""Single boundary for JSON/data-shape validation."""
import hashlib
import json
import math
import re
from .errors import InvalidInput

NAME = re.compile(r"^[A-Za-z_][A-Za-z_0-9]{0,63}$")
MAX_TEXT = 128
MAX_MAGNITUDE = 1_000_000_000
MAX_EXAMPLES = 256


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf8")).hexdigest()


def namespace_name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise InvalidInput("namespace must be a simple identifier (1-64 characters)")
    return value


def check_task_description(value):
    if (not isinstance(value, str) or not value.strip() or len(value) > 2000
            or any(ord(char) < 32 and char not in '\n\t' for char in value)):
        raise InvalidInput("task_description must be 1-2000 printable characters")
    return value


def check_scalar(value):
    if isinstance(value, bool):
        return value
    if type(value) is int and abs(value) <= MAX_MAGNITUDE:
        return value
    if isinstance(value, str) and len(value) <= MAX_TEXT:
        return value
    raise InvalidInput("values must be bool, bounded integer, or short string")


def check_inputs(inputs):
    if not isinstance(inputs, dict) or not inputs or len(inputs) > 16:
        raise InvalidInput("inputs must be a nonempty object with at most 16 fields")
    clean = {}
    for name, value in inputs.items():
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise InvalidInput("input field name is not a valid identifier")
        if isinstance(value, list):
            if not (1 <= len(value) <= 16):
                raise InvalidInput("list inputs must have 1-16 elements")
            clean[name] = [check_scalar(x) for x in value]
        else:
            clean[name] = check_scalar(value)
    return clean


def check_examples(data, *, minimum=0):
    if not isinstance(data, list) or not (minimum <= len(data) <= MAX_EXAMPLES):
        raise InvalidInput(f"examples must be a list of {minimum}-{MAX_EXAMPLES} items")
    clean = []
    for entry in data:
        if not isinstance(entry, dict) or set(entry) != {"inputs", "output"}:
            raise InvalidInput("each example must have exactly 'inputs' and 'output'")
        clean.append({"inputs": check_inputs(entry["inputs"]), "output": check_scalar(entry["output"])})
    if clean:
        schema = input_schema(clean[0]["inputs"])
        out_type = type(clean[0]["output"])
        for example in clean[1:]:
            if input_schema(example["inputs"]) != schema:
                raise InvalidInput("all examples must share field types and list lengths")
            if type(example["output"]) is not out_type:
                raise InvalidInput("all outputs must share a type")
    return clean


def input_schema(inputs):
    schema = {}
    for name, value in sorted(inputs.items()):
        if isinstance(value, list):
            schema[name] = [type(x).__name__ for x in value]
        else:
            schema[name] = type(value).__name__
    return schema


def require_schema(inputs, schema):
    if input_schema(inputs) != schema:
        raise InvalidInput("inputs do not match the stored rule's schema")


def safe_result(value):
    if isinstance(value, bool) or isinstance(value, str):
        return check_scalar(value)
    if type(value) is int and abs(value) <= MAX_MAGNITUDE:
        return value
    raise InvalidInput("expression produced an out-of-range or unsupported result")
