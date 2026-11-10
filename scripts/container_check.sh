#!/usr/bin/env bash
# Build the image and check it the way AWS Lambda will run it (issue #26, step 2).
# CI (.github/workflows/tests.yml, job "container") and a local run use exactly these commands:
#
#     bash scripts/container_check.sh [image-tag]
#
# Needs Docker and about 12 GB of free disk. The first build takes a while (PyTorch + model).
# Creates no cloud resources and pushes nothing. Never reads the real secrets file.
set -euo pipefail

# Git Bash on Windows rewrites "/tmp/zt"-style arguments into Windows paths; this turns that off.
export MSYS_NO_PATHCONV=1

IMAGE="${1:-zt-firewall:container-check}"
NAME="zt-container-check"
PROBE="zt-context-probe"
# Lambda's limit is 10 GB uncompressed. Decimal 10e9 is slightly stricter than 10 GiB on purpose.
MAX_BYTES=10000000000
CANARY=".env.canary"          # matches the ".env*" rule; lets the probe prove the rule works

cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "--- container logs (check failed) ---"
    docker logs "$NAME" 2>&1 | tail -n 80 || true
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rmi -f "$PROBE" >/dev/null 2>&1 || true
  rm -f "$CANARY"
  exit "$status"
}
trap cleanup EXIT

echo "== 1. Build (--provenance=false: Lambda rejects images with attestation manifests)"
docker build --provenance=false -t "$IMAGE" .

echo "== 2. Image size must stay under Lambda's limit"
# Lambda counts the uncompressed size of all layers. Docker reports that differently by image store:
#  - classic store (CI): `inspect .Size` is the unpacked size
#  - containerd store (Docker Desktop): `inspect .Size` is the COMPRESSED size (4.5 GB for an 8 GB
#    image), and `docker images` shows compressed + unpacked added together (12.5 GB)
# The sum of the layer sizes in `docker history` is the unpacked size on both, so gate on the
# larger of the two numbers.
reported=$(docker image inspect "$IMAGE" --format '{{.Size}}')
unpacked=$(docker history --human=false --no-trunc --format '{{.Size}}' "$IMAGE" | awk '{s+=$1} END {printf "%d", s}')
case "$unpacked" in ''|0|*[!0-9]*) echo "FAIL: could not measure the layer sizes"; exit 1 ;; esac
size=$(( reported > unpacked ? reported : unpacked ))
echo "image size: $size bytes (inspect: $reported, layer sum: $unpacked, limit $MAX_BYTES)"
if [ "$size" -ge "$MAX_BYTES" ]; then
  echo "FAIL: image is too big for Lambda"
  exit 1
fi

echo "== 3. .dockerignore keeps secrets and dev files out of the build context"
# The Dockerfile only copies named files, so .dockerignore is a second line of defence: it matters
# if someone later adds "COPY . .". This builds a probe image from the repo's own .dockerignore and
# lists what is left of the build context. The canary file is created and removed here; the real
# secrets file is never opened.
: > "$CANARY"
docker build -q -t "$PROBE" -f - . <<'EOF' >/dev/null
FROM busybox
COPY . /ctx
EOF
leaked=$(docker run --rm "$PROBE" ls -A /ctx | grep -E '^(\.env.*|venv|\.git|private|tests|evals|\.claude|infra)$' || true)
if [ -n "$leaked" ]; then
  echo "FAIL: these are not excluded by .dockerignore: $leaked"
  exit 1
fi
echo "ok: build context is clean"

echo "== 4. Run read-only, non-root, no network (how Lambda runs it)"
# AUDIT_LOG_DIR and HOME point at the tmpfs because the root filesystem is read-only; on Lambda,
# Terraform sets the same two values (/tmp is the only writable path there too).
docker run -d --name "$NAME" \
  --read-only --tmpfs /tmp --user 1000:1000 --network none \
  -e AUDIT_LOG_DIR=/tmp/zt -e HOME=/tmp \
  "$IMAGE" >/dev/null

echo "== 5. Smoke test inside the container (waits for the model to load, up to 5 minutes)"
docker exec -i "$NAME" python - < scripts/container_smoke_test.py

echo "== Container checks passed"
