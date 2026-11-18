#!/bin/sh
set -eu
BASE="${BASE:-http://localhost:8080}"
TOKEN="${TOKEN:-}"
REPO="${REPO:-${REGISTRY_REPOSITORY:-os}}"
ARCH="${ARCH:-x86_64}"
INDEX_FORMAT="${APK_INDEX_FORMAT:-v2}"
INDEX_TIMEOUT="${INDEX_TIMEOUT:-60}"
APK="${APK:-}"

case "$INDEX_FORMAT" in
  v2) INDEX_NAME=APKINDEX.tar.gz ;;
  v3) INDEX_NAME=Packages.adb ;;
  *)
    echo "APK_INDEX_FORMAT must be v2 or v3." >&2
    exit 2
    ;;
esac

if [ -z "$TOKEN" ]; then
  echo "Set TOKEN to an API key with deploy permission." >&2
  exit 2
fi
if [ -z "$APK" ] || [ ! -f "$APK" ]; then
  echo "Set APK to the path of a valid .apk package." >&2
  exit 2
fi
case "$INDEX_TIMEOUT" in
  ''|*[!0-9]*)
    echo "INDEX_TIMEOUT must be a positive number of seconds." >&2
    exit 2
    ;;
esac
if [ "$INDEX_TIMEOUT" -lt 1 ]; then
  echo "INDEX_TIMEOUT must be a positive number of seconds." >&2
  exit 2
fi

FILE=$(basename "$APK")
PACKAGE_URL="$BASE/$REPO/$ARCH/$FILE"
INDEX_URL="$BASE/$REPO/$ARCH/$INDEX_NAME"

printf '%s\n' '== health =='
curl -fsS "$BASE/healthz"

printf '\n%s\n' '== package upload =='
curl -fsS \
  -H "Authorization: Bearer $TOKEN" \
  --upload-file "$APK" \
  "$PACKAGE_URL"

printf '\n%s\n' '== wait for repository index =='
attempt=0
while [ "$attempt" -lt "$INDEX_TIMEOUT" ]; do
  if curl -fsS -o /dev/null \
    -H "Authorization: Bearer $TOKEN" \
    "$INDEX_URL" 2>/dev/null; then
    printf 'Index is available: %s\n' "$INDEX_URL"
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done

printf 'Index did not become available within %s seconds: %s\n' \
  "$INDEX_TIMEOUT" "$INDEX_URL" >&2
exit 1
