#!/usr/bin/env bash
# Metadata-only, read-only wallet artifact inventory. No candidate values emitted.
set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if command -v python3 >/dev/null 2>&1; then
  exec python3 "$SCRIPT_DIR/scan_wallet_artifacts.py" "$@"
fi
exec python "$SCRIPT_DIR/scan_wallet_artifacts.py" "$@"
