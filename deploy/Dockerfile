# Build context is the repo root.
#
# The image runs the scanner, not a server:
#
#     docker run --rm -v "$PWD:/repo:ro" ghcr.io/<owner>/reposec scan /repo
#
# Bind-mount read-only: the scanner never writes to the repository, and saying
# so in the command is cheaper than asking anyone to trust that.

# --------------------------------------------------------------------------- #
# Stage 1: install eslint-plugin-security.
#
# Without this the image reports the JS/TS detector as degraded on every scan
# and falls back to regex checks. Building it here rather than copying the
# host's node_modules keeps the image reproducible and platform-correct.
# --------------------------------------------------------------------------- #
FROM node:22-bookworm-slim AS eslint
WORKDIR /eslint
COPY src/reposec/detectors/eslint/package.json ./
RUN npm install --omit=dev --no-audit --no-fund


# --------------------------------------------------------------------------- #
# Stage 2: the scanner.
# --------------------------------------------------------------------------- #
FROM python:3.13-slim

WORKDIR /app

# git is required by `scan --history`, which is the reason to run this in CI at
# all — a working-tree scan cannot see a credential that was deleted later.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Node runtime for eslint. Both images are Debian bookworm, so the binary and
# its shared libraries match; code.py invokes `node <eslint>/bin/eslint.js`
# directly and never needs npm or npx at runtime.
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY --from=eslint /eslint/node_modules ./src/reposec/detectors/eslint/node_modules

# Installed rather than PYTHONPATH'd, so the container runs the same `reposec`
# entry point users get from pip — one code path, not two.
RUN pip install --no-cache-dir --no-deps -e .

# The bind-mounted repo is owned by the host uid, not by `scanner`, so git's
# dubious-ownership check would refuse to read it and --history would silently
# find nothing. The container only ever reads the mount.
RUN git config --system --add safe.directory '*'

# Fail the build rather than ship an image whose detectors silently degrade.
#
# `reposec doctor` cannot be that gate: it reports what is available and always
# exits 0, by design, so a missing analyzer would print a line nobody reads and
# the build would go green. verify_image.py scans a fixture and names whichever
# analyzer failed to run. See its docstring for why the check is offline.
COPY deploy/verify_image.py /tmp/verify_image.py
RUN python /tmp/verify_image.py && rm /tmp/verify_image.py

# A scan writes nothing outside /tmp, so the container does not need root.
RUN useradd --create-home --uid 10001 scanner
USER scanner

# `docker run <image> scan /repo` — the subcommand is the argument.
ENTRYPOINT ["reposec"]
CMD ["--help"]
