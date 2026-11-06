"""AST-only operator-change induction; *never* executes or applies source.

A structural mutation does not prove semantic correctness. It is intentionally
candidate-only and requires independently supplied semantic tests, repository-
disjoint holdouts, and evaluator promotion before agent-facing use.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..contracts import SourceChangeV1


@dataclass(frozen=True)
class StructuralChange:
    candidate_id: str
    node_type: str
    old_operator: str
    new_operator: str
    before_structure_digest: str
    after_structure_digest: str
    contract_digest: str
    receipt_digest: str
    status: str = "candidate"
    source_change_digest: str = ""


def _op_nodes(tree: ast.AST) -> list[ast.AST]:
    return [n for n in ast.walk(tree) if isinstance(n, (ast.operator, ast.unaryop, ast.cmpop, ast.boolop))]


def induce_structural_change(
    before: str, after: str, *, semantic_contract_digest: str,
    independently_verified_receipt_digest: str,
) -> StructuralChange | None:
    """Find exactly one operator substitution with all other AST fields equal.

    Does not claim generalizability or that tests passed. The referenced
    contract/receipt must be validated by an independent promotion authority.
    """
    for digest in (semantic_contract_digest, independently_verified_receipt_digest):
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("expected_sha256_digest")
    if max(len(before), len(after)) > 128_000:
        raise ValueError("source_too_large")
    left, right = ast.parse(before), ast.parse(after)
    left_ops, right_ops = _op_nodes(left), _op_nodes(right)
    if len(left_ops) != len(right_ops):
        return None
    changed = [(type(a).__name__, type(b).__name__) for a, b in zip(left_ops, right_ops)
               if type(a) is not type(b)]
    if len(changed) != 1:
        return None
    # Normalize every operation node to the same placeholder class to prove
    # structural identity across the two trees except operator identity.
    class NormalizeOperators(ast.NodeTransformer):
        def visit_BinOp(self, node):
            self.generic_visit(node)
            node.op = ast.Add()
            return node
        def visit_UnaryOp(self, node):
            self.generic_visit(node)
            node.op = ast.UAdd()
            return node
        def visit_Compare(self, node):
            self.generic_visit(node)
            node.ops = [ast.Eq() for _ in node.ops]
            return node
        def visit_BoolOp(self, node):
            self.generic_visit(node)
            node.op = ast.And()
            return node
        def visit_AugAssign(self, node):
            self.generic_visit(node)
            node.op = ast.Add()
            return node
    lnorm = NormalizeOperators().visit(ast.parse(before))
    rnorm = NormalizeOperators().visit(ast.parse(after))
    if ast.dump(lnorm, include_attributes=False) != ast.dump(rnorm, include_attributes=False):
        return None
    old, new = changed[0]
    before_digest = hashlib.sha256(ast.dump(left, include_attributes=False).encode()).hexdigest()
    after_digest = hashlib.sha256(ast.dump(right, include_attributes=False).encode()).hexdigest()
    identity = hashlib.sha256((before_digest+after_digest+semantic_contract_digest+independently_verified_receipt_digest).encode()).hexdigest()[:24]
    return StructuralChange("struct-" + identity, "operator", old, new, before_digest,
                            after_digest, semantic_contract_digest, independently_verified_receipt_digest)


def induce_from_source_change(
    record: "SourceChangeV1",
    file_contents: dict[str, tuple[bytes | None, bytes | None]],
    *, semantic_contract_digest: str,
    independently_verified_receipt_digest: str,
) -> StructuralChange | None:
    """Induce a structural change only from a *verified* capture artifact.

    ``file_contents`` maps each changed path to ``(before_bytes,
    after_bytes)`` — ``None`` for the absent side of added/removed files.
    Every supplied byte string is hashed and checked against the
    record's ``file_changes`` digests, so induction can only run on the
    bytes the capture path actually observed — never agent-claimed
    sources. Exactly one modified text file is required.
    """
    modified = [c for c in record.file_changes if c["kind"] == "modified"]
    if len(record.file_changes) != 1 or len(modified) != 1:
        raise ValueError("induction_requires_single_modified_file")
    entry = modified[0]
    pair = file_contents.get(entry["path"])
    if pair is None or pair[0] is None or pair[1] is None:
        raise ValueError("missing_file_bytes")
    if hashlib.sha256(pair[0]).hexdigest() != entry["before_digest"]:
        raise ValueError("before_bytes_mismatch")
    if hashlib.sha256(pair[1]).hexdigest() != entry["after_digest"]:
        raise ValueError("after_bytes_mismatch")
    change = induce_structural_change(
        pair[0].decode("utf-8"), pair[1].decode("utf-8"),
        semantic_contract_digest=semantic_contract_digest,
        independently_verified_receipt_digest=independently_verified_receipt_digest)
    if change is None:
        return None
    return StructuralChange(
        change.candidate_id, change.node_type, change.old_operator,
        change.new_operator, change.before_structure_digest,
        change.after_structure_digest, change.contract_digest,
        change.receipt_digest, "candidate", record.digest)
