"""Executor for the first read-only, local AgentSentinel milestone."""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Mapping

from .policy import TaskPolicy


_HAS_FD_RELATIVE_OPENS = (
    os.name == "posix" and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd
)


def _windows_opened_path(file_descriptor: int) -> Path:
    """Resolve a Windows file handle after open, including traversed reparse points."""
    import ctypes
    import msvcrt

    handle = msvcrt.get_osfhandle(file_descriptor)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_name = kernel32.GetFinalPathNameByHandleW
    get_name.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32)
    get_name.restype = ctypes.c_uint32
    needed = get_name(handle, None, 0, 0)
    if needed == 0 or needed > 32_768:
        raise OSError("opened file path could not be verified")
    buffer = ctypes.create_unicode_buffer(needed + 1)
    written = get_name(handle, buffer, len(buffer), 0)
    if written == 0 or written >= len(buffer):
        raise OSError("opened file path could not be verified")
    path = buffer.value
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    else:
        raise OSError("opened file path has an unsupported form")
    return Path(path)


class LocalReadOnlyExecutor:
    """Read allowlisted files; never run commands or make network requests.

    On POSIX, each path component is opened relative to an already-open directory
    with O_NOFOLLOW. Windows verifies the opened handle's final path, but remains
    limited to the app-created demo workspace; it does not provide the same
    hostile-workspace race guarantee.
    """

    def execute(self, tool_name: str, arguments: Mapping[str, object], policy: TaskPolicy) -> str:
        if tool_name != "read_file":
            raise ValueError("executor supports read_file only")
        if not policy.decide(tool_name, arguments).allowed:
            raise PermissionError("file is not in task policy")
        relative = str(arguments["path"])
        if _HAS_FD_RELATIVE_OPENS:
            return self._read_posix(relative, policy)
        return self._read_portable_demo(relative, policy)

    @staticmethod
    def _read_posix(relative: str, policy: TaskPolicy) -> str:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        opened: list[int] = []
        try:
            parent = os.open(policy.workspace, directory_flags)
            opened.append(parent)
            parts = relative.split("/")
            for part in parts[:-1]:
                parent = os.open(part, directory_flags, dir_fd=parent)
                opened.append(parent)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                         dir_fd=parent)
            opened.append(fd)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise PermissionError("only regular files can be read")
            if os.fstat(fd).st_nlink != 1:
                raise PermissionError("hardlinked files are not allowed")
            with os.fdopen(os.dup(fd), "rb") as stream:
                data = stream.read(policy.max_read_bytes + 1)
            if len(data) > policy.max_read_bytes:
                raise ValueError("file exceeds task read limit")
            return data.decode("utf-8", errors="replace")
        finally:
            for fd in reversed(opened):
                os.close(fd)

    @staticmethod
    def _read_portable_demo(relative: str, policy: TaskPolicy) -> str:
        candidate = policy.workspace
        for component in relative.split("/"):
            candidate = candidate / component
            if candidate.is_symlink():
                raise PermissionError("symlink path components are not allowed")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(policy.workspace):
            raise PermissionError("path escaped task workspace")
        with open(resolved, "rb") as stream:
            opened_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                raise PermissionError("only regular files can be read")
            if opened_stat.st_nlink != 1:
                raise PermissionError("hardlinked files are not allowed")
            if os.name == "nt":
                opened_path = _windows_opened_path(stream.fileno())
                if os.path.normcase(str(opened_path)) != os.path.normcase(str(resolved)):
                    raise PermissionError("opened file differs from approved path")
            data = stream.read(policy.max_read_bytes + 1)
        if len(data) > policy.max_read_bytes:
            raise ValueError("file exceeds task read limit")
        return data.decode("utf-8", errors="replace")


class ReadAndCommandExecutor:
    """Dispatch validated reads locally and commands to an injected executor."""

    def __init__(self, command_executor):
        self.reader = LocalReadOnlyExecutor()
        self.command_executor = command_executor

    def execute(self, tool_name: str, arguments: Mapping[str, object], policy: TaskPolicy) -> str:
        if tool_name == "read_file":
            return self.reader.execute(tool_name, arguments, policy)
        if tool_name == "execute_command":
            return self.command_executor.execute(tool_name, arguments, policy)
        raise ValueError("unsupported tool")
