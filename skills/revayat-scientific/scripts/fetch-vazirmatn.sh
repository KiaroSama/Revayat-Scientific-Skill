#!/usr/bin/env bash
# Portable font/license/provenance transaction; keeps the original positional CLI.
set -euo pipefail
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if command -v python3 >/dev/null 2>&1; then
  exec python3 -B "$here/font-fetch.py" "$@"
elif command -v python >/dev/null 2>&1; then
  exec python -B "$here/font-fetch.py" "$@"
else
  echo 'fetch-vazirmatn: Python 3.10+ is required' >&2
  exit 2
fi
