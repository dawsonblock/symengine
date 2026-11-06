"""Authenticated v3 serving boundary.

The legacy ``/v1`` API is a learning/registry surface. Production
guidance must not be reachable through it: every production decision has
to carry an authenticated execution identity, consume a shared nonce,
revalidate the witnessed authority snapshot and commit a durable receipt.

``V3ServingService`` is the only supported production guidance entry
point. It authenticates the caller (bearer token -> requester identity),
passes that requester to the gateway so it is checked against the signed
execution identity, and returns the committed authorization record with
the guidance.
"""
from __future__ import annotations

import hmac
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone

_HEX = re.compile(r"^[0-9a-f]{64}$")
_OUTCOMES = frozenset({"pass", "fail", "partial", "error"})
_MAX_TOKEN = 512
_GUIDANCE_FIELDS = frozenset({
    "request", "repository_id", "execution_identity", "task_family",
    "revoked_digests", "files_present", "symbols_extra",
})
_OUTCOME_FIELDS = frozenset({
    "task_id", "served_digest", "receipt_digest", "outcome",
    "authorization_id",
})


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _instant(value: str) -> datetime:
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class ServingServiceError(RuntimeError):
    """A v3 request was rejected before or during governed serving."""

    def __init__(self, reason: str, detail: str = "",
                 status: int = 400) -> None:
        self.reason = reason
        self.status = status
        super().__init__(f"{reason}: {detail}" if detail else reason)


class V3ServingService:
    """Authenticated, fail-closed HTTP-facing serving adapter."""

    def __init__(
        self,
        gateway,
        *,
        api_keys: Mapping[str, str],
        clock: Callable[[], str] | None = None,
    ) -> None:
        if not api_keys:
            raise ServingServiceError("v3_api_keys_required", status=500)
        keys: dict[str, tuple[str, str | None]] = {}
        for token, value in api_keys.items():
            if not (isinstance(token, str) and len(token.encode("utf8")) >= 24):
                raise ServingServiceError(
                    "v3_api_key_too_short", status=500)
            if len(token.encode("utf8")) > _MAX_TOKEN:
                raise ServingServiceError("v3_api_key_too_long", status=500)
            if isinstance(value, str):
                requester, expires_at = value, None
            elif isinstance(value, Mapping):
                requester = value.get("requester")
                expires_at = value.get("expires_at")
            else:
                raise ServingServiceError(
                    "v3_api_key_entry_invalid", status=500)
            if not (isinstance(requester, str) and requester):
                raise ServingServiceError(
                    "v3_requester_identity_required", status=500)
            if expires_at is not None:
                if not isinstance(expires_at, str):
                    raise ServingServiceError(
                        "v3_api_key_expiry_invalid", status=500)
                try:
                    _instant(expires_at)
                except (TypeError, ValueError) as exc:
                    raise ServingServiceError(
                        "v3_api_key_expiry_invalid", status=500) from exc
            keys[token] = (requester, expires_at)
        self._keys = keys
        self._gateway = gateway
        self._clock = clock or _utcnow

    @property
    def gateway(self):
        return self._gateway

    def health(self) -> dict:
        return self._gateway.health()

    def handle(self, path: str, payload: Mapping, headers) -> tuple[int, dict]:
        """Dispatch one authenticated v3 request."""
        try:
            requester = self._authenticate(headers)
            if path == "/v3/guidance":
                return self._guidance(payload, requester)
            if path == "/v3/outcome":
                return self._outcome(payload, requester)
            raise ServingServiceError("not_found", status=404)
        except ServingServiceError as exc:
            return exc.status, {"error": exc.reason}
        except (TypeError, ValueError) as exc:
            return 400, {"error": "invalid_request", "detail": str(exc)[:200]}

    # ------------------------------------------------------------------ #
    def _authenticate(self, headers) -> str:
        raw = ""
        if headers is not None:
            raw = headers.get("Authorization") or \
                headers.get("authorization") or ""
        if not isinstance(raw, str) or not raw.startswith("Bearer "):
            raise ServingServiceError("unauthorized", status=401)
        token = raw[len("Bearer "):]
        now = _instant(self._clock())
        for known, (requester, expires_at) in self._keys.items():
            if hmac.compare_digest(token.encode("utf8"),
                                   known.encode("utf8")):
                if expires_at is not None and _instant(expires_at) <= now:
                    raise ServingServiceError("unauthorized", status=401)
                return requester
        raise ServingServiceError("unauthorized", status=401)

    def _guidance(self, payload: Mapping, requester: str) -> tuple[int, dict]:
        if not isinstance(payload, Mapping):
            raise ServingServiceError("invalid_request")
        unknown = sorted(set(payload) - _GUIDANCE_FIELDS)
        if unknown:
            raise ServingServiceError(
                "unknown_field", ",".join(unknown[:4]))
        request = payload.get("request")
        if not isinstance(request, Mapping):
            raise ServingServiceError("request_required")
        repository_id = payload.get("repository_id")
        if not (isinstance(repository_id, str) and repository_id):
            raise ServingServiceError("repository_id_required")
        identity = payload.get("execution_identity")
        if not isinstance(identity, Mapping):
            raise ServingServiceError("execution_identity_required")
        task_family = payload.get("task_family")
        if task_family is not None and not isinstance(task_family, str):
            raise ServingServiceError("task_family_invalid")
        revoked = payload.get("revoked_digests", ())
        if not isinstance(revoked, (list, tuple)) or any(
                not (isinstance(item, str) and _HEX.fullmatch(item))
                for item in revoked):
            raise ServingServiceError("revoked_digests_invalid")
        files_present = payload.get("files_present", ())
        symbols_extra = payload.get("symbols_extra", ())
        for name, value in (("files_present", files_present),
                            ("symbols_extra", symbols_extra)):
            if not isinstance(value, (list, tuple)) or any(
                    not isinstance(item, str) for item in value):
                raise ServingServiceError(f"{name}_invalid")

        guidance = self._gateway.serve(
            request, repository_id=repository_id,
            revoked_digests=frozenset(revoked),
            files_present=tuple(files_present),
            symbols_extra=tuple(symbols_extra),
            task_family=task_family,
            execution_identity=identity,
            requester_identity=requester,
        )
        authorization = self._authorization_for(identity, guidance)
        body = {
            "guidance": guidance.to_dict(),
            "guidance_digest": guidance.digest,
            "decision": guidance.decision,
            "qualified_advice": guidance.decision == "advisory",
            "abstained": guidance.decision == "abstain",
            "authorization": authorization,
        }
        if guidance.decision == "abstain":
            body["reason_code"] = guidance.reason_code
        return 200, body

    def _authorization_for(self, identity: Mapping, guidance) -> dict | None:
        control_plane = getattr(self._gateway, "control_plane", None)
        if control_plane is None:
            return None
        nonce = identity.get("session_nonce") \
            if isinstance(identity, Mapping) else None
        if not isinstance(nonce, str) or not nonce:
            return None
        try:
            receipt = control_plane.authorization_for_nonce(nonce)
        except Exception:  # noqa: BLE001 - receipt lookup is advisory only
            return None
        if receipt is None or \
                receipt.get("guidance_digest") != guidance.digest:
            # A replay loser must not be handed the winner's receipt.
            return None
        return receipt

    def _outcome(self, payload: Mapping, requester: str) -> tuple[int, dict]:
        if not isinstance(payload, Mapping):
            raise ServingServiceError("invalid_request")
        unknown = sorted(set(payload) - _OUTCOME_FIELDS)
        if unknown:
            raise ServingServiceError(
                "unknown_field", ",".join(unknown[:4]))
        task_id = payload.get("task_id")
        served_digest = payload.get("served_digest")
        receipt_digest = payload.get("receipt_digest")
        outcome = payload.get("outcome")
        authorization_id = payload.get("authorization_id")
        if not (isinstance(task_id, str) and task_id):
            raise ServingServiceError("task_id_required")
        for name, value in (("served_digest", served_digest),
                            ("receipt_digest", receipt_digest)):
            if not (isinstance(value, str) and _HEX.fullmatch(value)):
                raise ServingServiceError(f"{name}_invalid")
        if outcome not in _OUTCOMES:
            raise ServingServiceError("outcome_invalid")
        if authorization_id is not None and not (
                isinstance(authorization_id, str) and authorization_id):
            raise ServingServiceError("authorization_id_invalid")
        try:
            self._gateway.record_outcome(
                task_id=task_id, served_digest=served_digest,
                receipt_digest=receipt_digest, outcome=outcome,
                authorization_id=authorization_id)
        except ValueError as exc:
            raise ServingServiceError(str(exc)) from exc
        return 200, {
            "recorded": True,
            "task_id": task_id,
            "outcome": outcome,
        }


__all__ = ["ServingServiceError", "V3ServingService"]
