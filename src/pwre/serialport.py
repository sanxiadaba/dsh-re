"""串口：列端口、监听、环回自检、收发。

嵌入式现场的"再确认一遍"：芯片到底有没有在说话、线有没有接反、波特率对不对。
依赖 pyserial；缺了就明确告诉你怎么装，不自己糊一套 Win32 API。
"""

import time

from .errors import ReError
from .out import human_size


def _serial():
    try:
        import serial
        from serial.tools import list_ports
    except ImportError:
        raise ReError(
            "缺少 pyserial",
            hint="在仓库目录执行 .venv\\Scripts\\pip install pyserial",
        )
    return serial, list_ports


def ports() -> list[dict]:
    _, list_ports = _serial()
    return [
        {"device": item.device, "description": item.description or "", "hwid": item.hwid or ""}
        for item in list_ports.comports()
    ]


def _open(port: str, baud: int, read_timeout: float = 0.2):
    serial, _ = _serial()
    try:
        handle = serial.Serial(port, baud, timeout=read_timeout)
    except serial.SerialException as exc:
        raise ReError(f"打不开串口 {port}（{baud}）：{exc}", hint="re serial --list 看端口名；被别的程序占用时先关掉它")
    handle.reset_input_buffer()
    return handle


def _decode(text: str) -> bytes:
    if text.startswith("hex:"):
        raw = text[4:].replace(",", " ").split()
        try:
            return bytes(int(item, 16) for item in raw)
        except ValueError:
            raise ReError(f"hex 数据不合法：{text}")
    if text.startswith("text:"):
        return text[5:].encode("utf-8")
    return text.encode("utf-8")


def listen(port: str, baud: int, seconds: float = 2.0, limit: int = 4096) -> bytes:
    handle = _open(port, baud)
    try:
        deadline = time.time() + seconds
        buffer = bytearray()
        while time.time() < deadline and len(buffer) < limit:
            chunk = handle.read(max(1, limit - len(buffer)))
            if chunk:
                buffer += chunk
        return bytes(buffer)
    finally:
        handle.close()


def loopback(port: str, baud: int, probe: bytes | None = None, wait: float = 0.6) -> dict:
    """发一串可识别字节再读回：线接没接、短接对不对，一次说清。"""
    payload = probe or b"re-probe-0123456789\r\n"
    handle = _open(port, baud)
    try:
        handle.write(payload)
        handle.flush()
        time.sleep(wait)
        back = handle.read(max(len(payload), 64))
        return {
            "port": port,
            "baud": baud,
            "sent": payload,
            "received": back,
            "echo": back[: len(payload)] == payload,
        }
    finally:
        handle.close()


def exchange(port: str, baud: int, send: str, seconds: float = 1.0) -> dict:
    payload = _decode(send)
    if not payload:
        raise ReError("要发的内容是空的", hint="给 text:内容 或 hex:01 02；空串发不出去")
    handle = _open(port, baud)
    try:
        handle.write(payload)
        handle.flush()
        deadline = time.time() + seconds
        buffer = bytearray()
        while time.time() < deadline:
            chunk = handle.read(256)
            if chunk:
                buffer += chunk
        return {"sent": payload, "received": bytes(buffer), "size": len(buffer)}
    finally:
        handle.close()


def hexdump(data: bytes, limit: int = 32) -> list[str]:
    lines = []
    for offset in range(0, min(len(data), limit * 16), 16):
        chunk = data[offset: offset + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset:04x}  {chunk.hex(' '):<47}  {text}")
    if len(data) > limit * 16:
        lines.append(f"  … 共 {human_size(len(data))}")
    return lines
