"""Compatibility/testing namespace — never wired to production credentials.

Modules under ``sis.v3.compat`` are retained for fixture compatibility and
historical behavior tests only. They do not enforce the authority-backed
serving contract and must not be exposed to agent credentials, HTTP handlers,
or CLI production paths.
"""
