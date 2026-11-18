#!/bin/sh
set -eu

storage_root="${STORAGE_ROOT:-/var/lib/apk-registry}"
mkdir -p "$storage_root"
if [ "$(stat -c '%u' "$storage_root")" != "10001" ]; then
  chown -R registry:registry "$storage_root"
fi

exec su-exec registry /usr/local/bin/apk-registry "$@"
