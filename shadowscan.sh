#!/bin/bash
# ShadowScan Command Wrapper

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_PATH="python3"

# Run shadowscan with Python module
cd "$SCRIPT_DIR"
exec "$PYTHON_PATH" -m shadowscan.cli.main "$@"