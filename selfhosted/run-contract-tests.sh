#!/usr/bin/env bash
set -euo pipefail
: "${PASSD_BACKEND_ROOT:?Set PASSD_BACKEND_ROOT=/path/to/passd-backend}"
python -m unittest discover -s "$(dirname "$0")/tests" -v
