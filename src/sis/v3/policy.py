"""Default-deny v3 role/action policy.

Callers must map authenticated process/transport credentials to a role before
calling this module. A role supplied inside an agent-controlled JSON request is
never an authenticated principal.
"""
from __future__ import annotations

from types import MappingProxyType


class AuthorizationDenied(PermissionError):
    """The trusted caller role is not allowed to perform an action."""


ROLES = frozenset({"agent", "runner", "learner", "evaluator", "operator"})
ACTIONS = frozenset({
    "guidance:read", "qualified_catalog:read", "observation:append",
    "candidate:write", "workspace:execute", "outcome:evaluate",
    "outcome:sign", "evaluator_private:read", "promotion:approve",
    "policy:write", "artifact:read",
})

_ALLOWED = {
    "agent": frozenset({"guidance:read", "qualified_catalog:read", "observation:append"}),
    "runner": frozenset({"workspace:execute", "observation:append", "artifact:read"}),
    "learner": frozenset({"candidate:write", "artifact:read"}),
    "evaluator": frozenset({"outcome:evaluate", "outcome:sign", "evaluator_private:read", "artifact:read"}),
    "operator": frozenset({"promotion:approve", "policy:write", "qualified_catalog:read", "artifact:read"}),
}
PERMISSIONS = MappingProxyType(_ALLOWED)


def is_allowed(role: str, action: str) -> bool:
    """Return False for every unknown role/action pair."""
    return (isinstance(role, str) and isinstance(action, str)
            and role in PERMISSIONS and action in ACTIONS and action in PERMISSIONS[role])


def require_permission(role: str, action: str) -> None:
    """Enforce a policy decision after trusted identity resolution."""
    if not is_allowed(role, action):
        raise AuthorizationDenied(f"role is not authorized for {action}")
