# Evaluator sandbox image for SIS v3 Docker execution.
#
# The image carries the pinned test runner only. It has no network tools,
# no shell history, no package manager cache, and runs as an unprivileged
# user. Build with:
#
#   docker build --platform linux/arm64 -t sis-evaluator:3.3.8 docker/sandbox
#
# The base image is pinned by its multi-architecture index digest, resolved
# with `docker buildx imagetools inspect python:3.12-slim` on 2026-11-12.
# A tag alone would let a rebuilt image resolve to different bytes.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN pip install --no-cache-dir pytest==8.4.2 \
    && rm -rf /root/.cache /tmp/*

# The base image already has nobody at 65534; reuse it and keep HOME in
# the tmpfs at runtime.
USER 65534:65534
ENV HOME=/tmp
WORKDIR /workspace
