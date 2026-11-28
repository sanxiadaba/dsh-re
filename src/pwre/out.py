"""输出：默认紧凑文本，--json 给全量。上下文是硬预算，默认行数越少越好。"""

import json
import sys

SCHEMA = 1


def emit(args, lines, payload=None):
    """按 --json 决定输出形态。payload 为 None 时不输出 JSON。

    dict 载荷统一带 schema 版本，下游可以按版本解析；不改调用方传进来的 dict。
    """
    if getattr(args, "json", False) and payload is not None:
        if isinstance(payload, dict):
            payload = {"schema": SCHEMA, **payload}
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        return
    for line in lines:
        print(line)


def human_size(n: int) -> str:
    """1024 进制，保留一位小数。"""
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{n} B"


def warn(message: str) -> None:
    print(f"re: {message}", file=sys.stderr)
