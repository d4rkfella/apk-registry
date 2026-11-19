#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
MELANGE="${MELANGE:-melange}"
APKO="${APKO:-apko}"
E2E_REPOSITORY="${APK_REGISTRY_E2E_REPOSITORY:-e2e-os}"
INDEX_TIMEOUT="${APK_REGISTRY_E2E_INDEX_TIMEOUT:-60}"
TMP_DIR=$(mktemp -d)
SERVER_PID=
LOG_TAIL_PID=

stop_registry() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=
  fi
}

cleanup() {
  stop_registry
  if [ -n "$LOG_TAIL_PID" ]; then
    kill "$LOG_TAIL_PID" 2>/dev/null || true
    wait "$LOG_TAIL_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

start_registry() {
  (
    APK_REGISTRY_LISTEN_ADDR="127.0.0.1:$PORT" \
    APK_REGISTRY_STORAGE_ROOT="$TMP_DIR/registry-data" \
    APK_REGISTRY_REPOSITORY="$E2E_REPOSITORY" \
    APK_REGISTRY_ADMIN_USERNAME="$ADMIN_USER" \
    APK_REGISTRY_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    APK_REGISTRY_PUBLIC_URL="$BASE" \
    APK_REGISTRY_INDEX_SIGNING_KEY="$SIGNING_KEY" \
    "$TMP_DIR/apk-registry" >>"$TMP_DIR/registry.log" 2>&1
  ) &
  SERVER_PID=$!
  if [ -z "$LOG_TAIL_PID" ]; then
    tail -n +1 -f "$TMP_DIR/registry.log" &
    LOG_TAIL_PID=$!
  fi

  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "Registry exited before becoming healthy." >&2
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "Registry did not become healthy." >&2
  return 1
}

has_hello_world_package() {
  python3 - "$1" 2>/dev/null <<'PY'
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as archive:
    for member in archive.getmembers():
        if member.isfile():
            contents = archive.extractfile(member).read()
            if b"P:hello-world\n" in contents:
                raise SystemExit(0)
raise SystemExit(1)
PY
}

for tool in "$MELANGE" "$APKO" docker curl go python3 tail; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Required tool not found: %s\n' "$tool" >&2
    exit 1
  fi
done

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
BASE="http://127.0.0.1:$PORT"
SIGNING_KEY="$TMP_DIR/e2e.rsa"
ADMIN_USER=integration-admin
ADMIN_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

printf '%s\n' '== generate package signing key =='
"$MELANGE" keygen "$SIGNING_KEY"
chmod 600 "$SIGNING_KEY"

printf '\n%s\n' '== build registry server =='
go build -o "$TMP_DIR/apk-registry" "$ROOT_DIR/cmd/server"

printf '\n%s\n' '== build signed hello-world package =='
"$MELANGE" build \
  --arch x86_64 \
  --runner docker \
  --signing-key "$SIGNING_KEY" \
  --license MIT \
  --generate-index=false \
  --out-dir "$TMP_DIR/packages" \
  "$ROOT_DIR/scripts/e2e/hello-world.melange.yaml"
APK=$(find "$TMP_DIR/packages" -type f -name 'hello-world-*.apk' -print -quit)
if [ -z "$APK" ]; then
  echo "Melange did not produce the hello-world APK." >&2
  exit 1
fi

printf '\n%s\n' '== start registry with signed indexes =='
: >"$TMP_DIR/registry.log"
start_registry

cat >"$TMP_DIR/empty-apko.yaml" <<EOF
contents:
  keyring:
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
  repositories:
    - $BASE/$E2E_REPOSITORY
    - https://packages.wolfi.dev/os
  packages:
    - busybox
archs:
  - x86_64
EOF

printf '\n%s\n' '== verify apko accepts a fresh empty repository =='
"$APKO" build \
  --arch x86_64 \
  --sbom-path "$TMP_DIR" \
  "$TMP_DIR/empty-apko.yaml" \
  apk-registry-empty-e2e:latest \
  "$TMP_DIR/empty-image.tar"
if [ -n "$(find "$TMP_DIR/registry-data/$E2E_REPOSITORY" -type f -name '*.apk' -print -quit)" ]; then
  echo "The fresh repository unexpectedly contains an APK." >&2
  exit 1
fi
curl --fail-with-body --silent --show-error -o /dev/null "$BASE/$E2E_REPOSITORY/e2e.rsa.pub"

printf '\n%s\n' '== create deploy token =='
API_TOKEN=$(
  curl --fail-with-body --silent --show-error \
    --user "$ADMIN_USER:$ADMIN_PASSWORD" \
    -H 'Content-Type: application/json' \
    -d '{"name":"e2e-deploy","permissions":["deploy"]}' \
    "$BASE/api/v1/admin/tokens" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])'
)

printf '\n%s\n' '== upload signed package =='
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $API_TOKEN" \
  --upload-file "$APK" \
  "$BASE/$E2E_REPOSITORY/x86_64/$(basename "$APK")"

printf '\n%s\n' '== wait for signed repository index =='
attempt=0
while [ "$attempt" -lt "$INDEX_TIMEOUT" ]; do
  if curl -fsS -o "$TMP_DIR/APKINDEX.tar.gz" "$BASE/$E2E_REPOSITORY/x86_64/APKINDEX.tar.gz" 2>/dev/null &&
    has_hello_world_package "$TMP_DIR/APKINDEX.tar.gz"; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$attempt" -eq "$INDEX_TIMEOUT" ]; then
  echo "Repository index did not become available." >&2
  exit 1
fi

printf '\n%s\n' '== restart registry and verify package persistence =='
stop_registry
rm "$TMP_DIR/registry-data/$E2E_REPOSITORY/x86_64/APKINDEX.tar.gz"
start_registry

attempt=0
while [ "$attempt" -lt "$INDEX_TIMEOUT" ]; do
  if curl -fsS -o "$TMP_DIR/recovered-APKINDEX.tar.gz" "$BASE/$E2E_REPOSITORY/x86_64/APKINDEX.tar.gz" 2>/dev/null &&
    has_hello_world_package "$TMP_DIR/recovered-APKINDEX.tar.gz"; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$attempt" -eq "$INDEX_TIMEOUT" ]; then
  echo "Registry did not recover the package index after restart." >&2
  exit 1
fi

cat >"$TMP_DIR/apko.yaml" <<EOF
contents:
  repositories:
    - $BASE/$E2E_REPOSITORY
  packages:
    - hello-world
archs:
  - x86_64
EOF

printf '\n%s\n' '== discover signing key and install recovered package with apko =='
"$APKO" build \
  --arch x86_64 \
  --sbom-path "$TMP_DIR" \
  "$TMP_DIR/apko.yaml" \
  apk-registry-e2e:latest \
  "$TMP_DIR/image.tar"

python3 - "$TMP_DIR/image.tar" <<'PY'
import json
import sys
import tarfile

target = "usr/share/hello-world/message"
with tarfile.open(sys.argv[1], "r") as image:
    manifest = json.load(image.extractfile("manifest.json"))
    found = False
    for layer_name in manifest[0]["Layers"]:
        with image.extractfile(layer_name) as layer_file:
            with tarfile.open(fileobj=layer_file, mode="r:*") as layer:
                if target in layer.getnames():
                    found = True
                    break

if not found:
    raise SystemExit(f"apko image does not contain {target}")
print(f"Verified package file in apko image: {target}")
PY

printf '\n%s\n' 'End-to-end package build, signed upload, restart recovery, and apko installation succeeded.'
