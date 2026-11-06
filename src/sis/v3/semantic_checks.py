"""Semantic gates for patch-transforming procedures (SIS3-141).

The audited failure: an operator-swap recipe learned from local examples
rewrote ``remaining_balance``'s ``a - b`` into ``a + b`` — lexically plausible,
semantically wrong. These checks are the first line of defense: a patch
proposal that changes an operator must preserve the metamorphic class the
source relied on, and every patch-transforming procedure requires an
independent semantic contract reference before it may be recommended.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum


class OpClass(Enum):
    COMMUTATIVE = "commutative"      # +, *, ==, !=, and, or
    NONCOMMUTATIVE = "noncommutative"  # -, /, //, %, **, <, >, <=, >=
    OTHER = "other"


_COMMUTATIVE = (ast.Add, ast.Mult, ast.Eq, ast.NotEq, ast.And, ast.Or)
_NONCOMMUTATIVE = (
    ast.Sub, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.Lt, ast.LtE, ast.Gt, ast.GtE,
)


def op_class(node: ast.AST) -> OpClass:
    """Classify an operator node by the metamorphic relations it satisfies."""
    if isinstance(node, _COMMUTATIVE):
        return OpClass.COMMUTATIVE
    if isinstance(node, _NONCOMMUTATIVE):
        return OpClass.NONCOMMUTATIVE
    return OpClass.OTHER


@dataclass(frozen=True)
class OperatorChange:
    lineno: int
    old_class: OpClass
    new_class: OpClass


def operator_changes(source: str, patched: str) -> list[OperatorChange]:
    """Diff two Python sources at operator granularity (AST, not text)."""
    try:
        old_tree = ast.parse(source)
        new_tree = ast.parse(patched)
    except SyntaxError as exc:
        raise ValueError("unparseable source") from exc
    old_ops = _collect(old_tree)
    new_ops = _collect(new_tree)
    changes: list[OperatorChange] = []
    if len(old_ops) != len(new_ops):
        # Structural change beyond a pure operator swap; report at top level.
        changes.append(OperatorChange(0, OpClass.OTHER, OpClass.OTHER))
        return changes
    for (old_node, old_lineno), (new_node, new_lineno) in zip(old_ops, new_ops):
        old_cls = op_class(old_node)
        new_cls = op_class(new_node)
        if type(old_node) is not type(new_node) or old_cls != new_cls:
            changes.append(OperatorChange(old_lineno, old_cls, new_cls))
    return changes


def metamorphic_violations(changes: list[OperatorChange]) -> list[str]:
    """Flag changes that break the source's metamorphic class.

    Only same-class swaps (commutative→commutative, noncommutative→
    noncommutative) are presumptively safe. Any class crossing — including
    an unclassifiable OTHER op or the structural-difference marker — cannot
    be proven semantics-preserving and is reported.
    """
    problems: list[str] = []
    for change in changes:
        if change.lineno == 0 and change.old_class == change.new_class == OpClass.OTHER:
            problems.append("structural change beyond an operator swap")
        elif change.old_class != change.new_class:
            problems.append(
                f"line {change.lineno}: {change.old_class.value} -> "
                f"{change.new_class.value} operator swap alters symmetry"
            )
    return problems


def _collect(tree: ast.AST) -> list[tuple[ast.AST, int]]:
    ops: list[tuple[ast.AST, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp):
            ops.append((node.op, node.lineno))
        elif isinstance(node, ast.BoolOp):
            ops.append((node.op, node.lineno))
        elif isinstance(node, ast.Compare):
            for op in node.ops:
                ops.append((op, node.lineno))
    return ops


def requires_semantic_contract(has_patch_effect: bool, semantic_contract_digest) -> bool:
    """Patch-transforming guidance requires verified task intent."""
    return not has_patch_effect or semantic_contract_digest is not None
