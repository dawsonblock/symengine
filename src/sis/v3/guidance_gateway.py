"""Deprecated import location for the legacy phase-gated guidance gateway.

The implementation moved to :mod:`sis.v3.compat.guidance_gateway`. This shim
exists only to keep old imports resolvable during the deprecation window; it
must not be wired to agent-facing serving paths. Removal target: the first
release after the v3.1-alpha train closes gate G1.
"""
from __future__ import annotations

import warnings as _warnings

_warnings.warn(
    "sis.v3.guidance_gateway is deprecated; use sis.v3.compat.guidance_gateway "
    "for tests/fixtures or sis.v3.secure_guidance.StrictGuidanceGateway for serving",
    DeprecationWarning,
    stacklevel=2,
)

from .compat.guidance_gateway import (  # noqa: E402
    PHASES,
    GuidanceGateway,
    retrieve_shadow,
)

__all__ = ["GuidanceGateway", "PHASES", "retrieve_shadow"]
