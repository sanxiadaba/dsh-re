"""运行时内存：列进程、列模块、按地址 dump。Windows 用 ReadProcessMemory。

别的平台直接报不支持——不假装能跑。
"""

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path

from .errors import ReError

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03
MAX_PATH = 260


def _require_windows():
    if sys.platform != "win32":
        raise ReError(
            "re mem 目前只支持 Windows（ReadProcessMemory）",
            hint="Linux 用 /proc/<pid>/maps + process_vm_readv，macOS 用 task_for_pid；还没有实现",
        )


def _kernel32():
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _psapi():
    ps = ctypes.WinDLL("psapi", use_last_error=True)
    ps.EnumProcessModulesEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
    ]
    ps.EnumProcessModulesEx.restype = wintypes.BOOL
    ps.GetModuleInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
    ]
    ps.GetModuleInformation.restype = wintypes.BOOL
    ps.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    ps.GetModuleBaseNameW.restype = wintypes.DWORD
    return ps


def list_processes(filt: str = "") -> list[dict]:
    _require_windows()
    k32, ps = _kernel32(), _psapi()
    capacity = 4096
    while True:
        pids = (wintypes.DWORD * capacity)()
        needed = wintypes.DWORD()
        if not ps.EnumProcesses(ctypes.byref(pids), ctypes.sizeof(pids), ctypes.byref(needed)):
            raise ReError(f"EnumProcesses 失败：{ctypes.get_last_error()}")
        count = needed.value // ctypes.sizeof(wintypes.DWORD)
        if count < capacity:
            break
        capacity *= 2
    rows = []
    for index in range(count):
        pid = pids[index]
        if not pid:
            continue
        handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            continue
        try:
            buffer = ctypes.create_unicode_buffer(MAX_PATH)
            if ps.GetModuleBaseNameW(handle, None, buffer, MAX_PATH):
                name = buffer.value
                if not filt or filt.lower() in name.lower():
                    rows.append({"pid": pid, "name": name})
        finally:
            k32.CloseHandle(handle)
    rows.sort(key=lambda row: row["name"].lower())
    return rows


def modules(pid: int) -> list[dict]:
    _require_windows()
    k32, ps = _kernel32(), _psapi()
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ReError(
            f"打不开进程 {pid}（错误 {ctypes.get_last_error()}）",
            hint="权限不够时用管理员权限运行；64 位目标别用 32 位解释器",
        )

    class MODULEINFO(ctypes.Structure):
        _fields_ = [
            ("lpBaseOfDll", ctypes.c_void_p),
            ("SizeOfImage", wintypes.DWORD),
            ("EntryPoint", ctypes.c_void_p),
        ]

    try:
        needed = wintypes.DWORD()
        if not ps.EnumProcessModulesEx(handle, None, 0, ctypes.byref(needed), LIST_MODULES_ALL):
            raise ReError(f"EnumProcessModulesEx 失败：{ctypes.get_last_error()}")
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        handles = (ctypes.c_void_p * count)()
        if not ps.EnumProcessModulesEx(handle, handles, needed.value, ctypes.byref(needed), LIST_MODULES_ALL):
            raise ReError(f"EnumProcessModulesEx 失败：{ctypes.get_last_error()}")
        rows = []
        for index in range(count):
            info = MODULEINFO()
            if not ps.GetModuleInformation(handle, handles[index], ctypes.byref(info), ctypes.sizeof(info)):
                continue
            name = ctypes.create_unicode_buffer(MAX_PATH)
            ps.GetModuleBaseNameW(handle, handles[index], name, MAX_PATH)
            rows.append(
                {
                    "base": info.lpBaseOfDll or 0,
                    "size": info.SizeOfImage,
                    "name": name.value,
                }
            )
        rows.sort(key=lambda row: row["base"])
        return rows
    finally:
        k32.CloseHandle(handle)


def read(pid: int, addr: int, size: int) -> bytes:
    _require_windows()
    k32 = _kernel32()
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ReError(f"打不开进程 {pid}（错误 {ctypes.get_last_error()}）", hint="试试管理员权限")
    try:
        buffer = ctypes.create_string_buffer(size)
        read_bytes = ctypes.c_size_t()
        ok = k32.ReadProcessMemory(
            handle, ctypes.c_void_p(addr), buffer, size, ctypes.byref(read_bytes)
        )
        if not ok:
            raise ReError(
                f"读 0x{addr:x} 失败（错误 {ctypes.get_last_error()}，已读 {read_bytes.value} 字节）",
                hint="地址可能没映射；先用 re mem --modules 找模块范围",
            )
        return buffer.raw[: read_bytes.value]
    finally:
        k32.CloseHandle(handle)


def dump(pid: int, addr: int, size: int, out: Path) -> int:
    data = read(pid, addr, size)
    out.write_bytes(data)
    return len(data)
