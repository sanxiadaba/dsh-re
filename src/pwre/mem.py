"""运行时内存：列进程、列模块、按地址 dump。Windows 用 ReadProcessMemory。

别的平台直接报不支持——不假装能跑。ctypes.wintypes 只在 Windows 上可用，
所以放在函数里延迟导入，不然 Linux 上连 `import pwre` 都会失败。
"""

import sys
from pathlib import Path

from .errors import ReError

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03
MAX_PATH = 260
ERROR_PARTIAL_COPY = 299
ERROR_INSUFFICIENT_BUFFER = 122
MAX_READ = 64 << 20


def _require_windows():
    if sys.platform != "win32":
        raise ReError(
            "re mem 目前只支持 Windows（ReadProcessMemory）",
            hint="Linux 用 /proc/<pid>/maps + process_vm_readv，macOS 用 task_for_pid；还没有实现",
        )


def _wintypes():
    from ctypes import wintypes

    return wintypes


def _kernel32():
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = _wintypes().HANDLE
    k32.OpenProcess.argtypes = [ctypes.c_ulong, _wintypes().BOOL, ctypes.c_ulong]
    k32.CloseHandle.argtypes = [_wintypes().HANDLE]
    k32.ReadProcessMemory.argtypes = [
        _wintypes().HANDLE, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    return k32


def _psapi():
    import ctypes

    wt = _wintypes()
    ps = ctypes.WinDLL("psapi", use_last_error=True)
    ps.EnumProcessModulesEx.argtypes = [
        wt.HANDLE, ctypes.c_void_p, wt.DWORD,
        ctypes.POINTER(wt.DWORD), wt.DWORD,
    ]
    ps.EnumProcessModulesEx.restype = wt.BOOL
    ps.GetModuleInformation.argtypes = [
        wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
    ]
    ps.GetModuleInformation.restype = wt.BOOL
    ps.GetModuleBaseNameW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
    ps.GetModuleBaseNameW.restype = wt.DWORD
    return ps


def list_processes(filt: str = "") -> tuple[list[dict], int]:
    """返回 (进程表, 打不开的个数)。

    只用 PROCESS_QUERY_LIMITED_INFORMATION + QueryFullProcessImageNameW：
    受保护进程（Registry/csrss/…）也能拿到名字，不再静默漏掉。
    """
    _require_windows()
    import ctypes

    wt = _wintypes()
    k32, ps = _kernel32(), _psapi()
    capacity = 4096
    while True:
        pids = (wt.DWORD * capacity)()
        needed = wt.DWORD()
        if not ps.EnumProcesses(ctypes.byref(pids), ctypes.sizeof(pids), ctypes.byref(needed)):
            raise ReError(f"EnumProcesses 失败：{ctypes.get_last_error()}")
        count = needed.value // ctypes.sizeof(wt.DWORD)
        if count < capacity:
            break
        capacity *= 2
    rows, skipped = [], 0
    for index in range(count):
        pid = pids[index]
        if not pid:
            continue
        handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            skipped += 1
            continue
        try:
            size = wt.DWORD(MAX_PATH)
            buffer = ctypes.create_unicode_buffer(MAX_PATH)
            if k32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                name = buffer.value.rsplit("\\", 1)[-1]
                if name and (not filt or filt.lower() in name.lower()):
                    rows.append({"pid": pid, "name": name})
            else:
                skipped += 1
        finally:
            k32.CloseHandle(handle)
    rows.sort(key=lambda row: row["name"].lower())
    return rows, skipped


def modules(pid: int) -> list[dict]:
    _require_windows()
    import ctypes

    wt = _wintypes()
    k32, ps = _kernel32(), _psapi()
    handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ReError(
            f"打不开进程 {pid}（错误 {ctypes.get_last_error()}）",
            hint="权限不够时用管理员权限运行；64 位目标别用 32 位解释器",
        )

    class MODULEINFO(ctypes.Structure):
        _fields_ = [
            ("lpBaseOfDll", ctypes.c_void_p),
            ("SizeOfImage", wt.DWORD),
            ("EntryPoint", ctypes.c_void_p),
        ]

    try:
        needed = wt.DWORD()
        if not ps.EnumProcessModulesEx(handle, None, 0, ctypes.byref(needed), LIST_MODULES_ALL):
            raise ReError(
                f"EnumProcessModulesEx 失败：{ctypes.get_last_error()}",
                hint="进程可能刚退出；或 32/64 位解释器与目标不匹配",
            )
        handles = (ctypes.c_void_p * max(1, needed.value // ctypes.sizeof(ctypes.c_void_p)))()
        if not ps.EnumProcessModulesEx(handle, handles, needed.value, ctypes.byref(needed), LIST_MODULES_ALL):
            error = ctypes.get_last_error()
            hint = "进程可能刚退出；或 32/64 位解释器与目标不匹配"
            if error == ERROR_PARTIAL_COPY:
                hint = "ERROR_PARTIAL_COPY(299)：多半是 32/64 位不匹配，或目标是被保护的进程"
            raise ReError(f"EnumProcessModulesEx 失败：{error}", hint=hint)
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        rows = []
        for index in range(count):
            info = MODULEINFO()
            if not ps.GetModuleInformation(handle, handles[index], ctypes.byref(info), ctypes.sizeof(info)):
                continue
            name = ctypes.create_unicode_buffer(MAX_PATH)
            ps.GetModuleBaseNameW(handle, handles[index], name, MAX_PATH)
            rows.append({"base": info.lpBaseOfDll or 0, "size": info.SizeOfImage, "name": name.value})
        rows.sort(key=lambda row: row["base"])
        return rows
    finally:
        k32.CloseHandle(handle)


def read(pid: int, addr: int, size: int, max_size: int = MAX_READ) -> bytes:
    _require_windows()
    import ctypes

    if not 0 < size <= max_size:
        raise ReError(f"一次最多读 {max_size:,} 字节，收到 {size:,}")
    wt = _wintypes()
    k32 = _kernel32()
    handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ReError(f"打不开进程 {pid}（错误 {ctypes.get_last_error()}）", hint="试试管理员权限")
    try:
        buffer = ctypes.create_string_buffer(size)
        read_bytes = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buffer, size, ctypes.byref(read_bytes))
        if not ok:
            raise ReError(
                f"读 0x{addr:x} 失败（错误 {ctypes.get_last_error()}）",
                hint="地址可能没映射；先用 re mem --modules 找模块范围",
            )
        if read_bytes.value < size:
            from .out import warn

            warn(f"只读到 {read_bytes.value:,}/{size:,} 字节")
        return buffer.raw[: read_bytes.value]
    finally:
        k32.CloseHandle(handle)


def dump(pid: int, addr: int, size: int, out: Path) -> int:
    data = read(pid, addr, size)
    out.write_bytes(data)
    return len(data)
