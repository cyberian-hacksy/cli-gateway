# Gateway container: the remote bridge (public) in front of CLIProxyAPI (container loopback).
# Build from the repository root:  docker build -f deploy/Dockerfile .
# Every external input is pinned: both base images by digest, Python packages by hash.

# CLIProxyAPI v8.0.27, multi-arch index digest.
FROM eceasy/cli-proxy-api@sha256:b7cf456bf6ef7f6489f18144e7cc166dbb8b2e5f46d6ee8881a321aaea563730 AS cliproxy

# python:3.13-slim-bookworm. Bookworm matches the glibc the CLIProxyAPI binary links against.
FROM python@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TZ=UTC PYTHONPATH=/opt/cgw-src/src

COPY --from=cliproxy /CLIProxyAPI/CLIProxyAPI /opt/cliproxy/CLIProxyAPI

# Regenerate with: uv export --frozen --no-dev --no-emit-project --format requirements-txt -o deploy/requirements.lock
COPY deploy/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --root-user-action=ignore --require-hashes -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

# The bridge is pure Python and runs from source, so no build backend is fetched at build time.
COPY src /opt/cgw-src/src
COPY deploy/cliproxy.yaml deploy/entrypoint.py deploy/egress_check.py /opt/cgw/

CMD ["python", "/opt/cgw/entrypoint.py"]
