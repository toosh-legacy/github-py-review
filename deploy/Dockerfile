# Build context is the repo root (see docker-compose.yml / fly.toml).

# --------------------------------------------------------------------------- #
# Stage 1: install eslint-plugin-security.
#
# Without this the deployed scanner reports the JS/TS detector as degraded on
# every single scan and falls back to regex checks. Building it here rather than
# copying the host's node_modules keeps the image reproducible and platform-
# correct (native deps compiled for the image, not for whoever ran docker build).
# --------------------------------------------------------------------------- #
FROM node:22-bookworm-slim AS eslint
WORKDIR /eslint
COPY src/security/eslint/package.json ./
RUN npm install --omit=dev --no-audit --no-fund


# --------------------------------------------------------------------------- #
# Stage 2: the API image.
# --------------------------------------------------------------------------- #
FROM python:3.13-slim

WORKDIR /app

# git is needed only by the history-scanning CLI, not by the API — but it is a
# few megabytes and having it means `docker run ... -m security.cli /repo
# --history` works against a mounted clone.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Node runtime for eslint. Both images are Debian bookworm, so the binary and
# its shared libraries match; code_scan.py invokes `node <eslint>/bin/eslint.js`
# directly and never needs npm or npx at runtime.
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node

# All Python packages live under src/, which is the import root.
COPY src ./src
COPY --from=eslint /eslint/node_modules ./src/security/eslint/node_modules

ENV PYTHONPATH=/app/src

# Fail the build rather than ship an image whose JS detector silently degrades.
RUN node --version \
    && python -c "import sys; sys.path.insert(0, 'src'); \
from security.code_scan import _eslint_binary; \
assert _eslint_binary() is not None, 'eslint missing from image'; \
import bandit; print('detectors ok')"

EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=2)"

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8001"]
