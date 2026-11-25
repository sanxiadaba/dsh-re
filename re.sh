#!/usr/bin/env sh
set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -x "$DIR/.venv/bin/python" ]; then
  echo "re: 还没建虚拟环境。在本目录执行：" >&2
  echo "    python3 -m venv .venv" >&2
  echo "    .venv/bin/pip install -e ." >&2
  exit 2
fi
if ! "$DIR/.venv/bin/python" -c "import capstone, pefile, elftools" 2>/dev/null; then
  echo "re: 依赖没装好。在本目录执行：" >&2
  echo "    .venv/bin/pip install -e ." >&2
  exit 2
fi
PYTHONPATH="$DIR/src" PYTHONUTF8=1 exec "$DIR/.venv/bin/python" -m pwre "$@"
