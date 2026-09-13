#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if command -v python3 >/dev/null 2>&1; then
  exec python3 "$here/install.py" "$@"
elif command -v python >/dev/null 2>&1; then
  exec python "$here/install.py" "$@"
fi
echo 'install: Python 3.10+ is required' >&2
exit 1
