#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Prefer rsvg-convert, fall back to cairosvg via Python helper
if command -v rsvg-convert &>/dev/null; then
    echo "Using rsvg-convert"
    exec python3 "$SCRIPT_DIR/build-icons.py" --renderer=rsvg "$@"
else
    echo "rsvg-convert not found, using cairosvg"
    python3 -c "import cairosvg" 2>/dev/null || {
        echo "Installing cairosvg..."
        pip3 install --quiet cairosvg
    }
    exec python3 "$SCRIPT_DIR/build-icons.py" --renderer=cairosvg "$@"
fi
