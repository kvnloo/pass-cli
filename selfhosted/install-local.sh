#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${PASS_CLI_LOCAL_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$DEST"
cp "$HERE/pass_cli_local.py" "$DEST/pass-cli-local"
chmod 0755 "$DEST/pass-cli-local"
echo "Installed $DEST/pass-cli-local"
