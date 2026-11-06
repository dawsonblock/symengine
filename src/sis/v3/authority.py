"""Strict, decision-backed projection for security-sensitive guidance serving.

Store records are *not* authority. This façade requires a fully verified
authority store — committed signed decisions and materialized revisions from
one transactional ``AuthorityDB`` — plus exact projection agreement. Fail
closed on drift, dangling writes, invalid signatures or missing controllers.
"""
from __future__ import annotations

from .procedures import ProcedureStore
from .promotion import PromotionController


class AuthorityError(RuntimeError):
    pass


class AuthorizedCatalogView:
    def __init__(self, store: ProcedureStore, controller: PromotionController):
        if controller.store is not store:
            raise AuthorityError("controller_store_mismatch")
        self._store = store
        self._controller = controller

    def _validated(self):
        store_status = self._store.verify()
        decision_status = self._controller.verify()
        if not store_status["ok"] or not decision_status["ok"]:
            raise AuthorityError("authority_verification_failed")
        return self._controller.projected_statuses()

    def by_status(self, status: str):
        projected = self._validated()
        records = self._store.by_status(status)
        if status != "qualified":
            return records
        # Fail closed if even one qualified catalog entry lacks a decision.
        if any(projected.get(record.digest) != "qualified" for record in records):
            raise AuthorityError("qualified_record_without_decision")
        return records

    def all_latest(self):
        self._validated()
        return self._store.all_latest()

    def qualified_head_digest(self):
        self.by_status("qualified")
        return self._store.qualified_head_digest()

    def get(self, *args, **kwargs):
        self._validated()
        return self._store.get(*args, **kwargs)
