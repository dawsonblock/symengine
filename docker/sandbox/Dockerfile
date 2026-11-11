# Evaluator sandbox image for SIS v3 Docker execution.
#
# The image carries the pinned test runner only. It has no network tools,
# no shell history, no package manager cache, and runs as an unprivileged
# user. Build with:
#
#   docker build --platform linux/arm64 -t sis-evaluator:3.3.8 docker/sandbox
#
# Production deployments must pin the base image by digest and record the
# resolved image digest in the isolation policy.
FROM python:3.12-slim

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
