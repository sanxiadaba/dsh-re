#!/usr/bin/env sh
set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHONPATH="$DIR/src" PYTHONUTF8=1 exec "$DIR/.venv/bin/python" -m pwre "$@"
