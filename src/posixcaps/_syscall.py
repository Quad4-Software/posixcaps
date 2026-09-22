# SPDX-License-Identifier: 0BSD
"""Raw ctypes bindings for capget(2), capset(2) and prctl(2).

glibc has no capget/capset wrappers, so both are invoked through libc's
syscall(2). Their numbers differ per architecture. prctl goes through
the libc wrapper directly, so no number is needed for it.
"""

import ctypes
import ctypes.util
import errno
import os
import platform
import sys
from typing import NoReturn

from .errors import CapError, UnsupportedError

_LINUX_CAPABILITY_VERSION_3 = 0x20080522
_LINUX_CAPABILITY_U32S_3 = 2

PR_CAPBSET_READ = 23
PR_CAPBSET_DROP = 24

PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_IS_SET = 1
PR_CAP_AMBIENT_RAISE = 2
PR_CAP_AMBIENT_LOWER = 3
PR_CAP_AMBIENT_CLEAR_ALL = 4

PR_GET_SECUREBITS = 27
PR_SET_SECUREBITS = 28


class CapUserHeader(ctypes.Structure):
    """cap_user_header_t: ABI version selector and target thread id."""

    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int32),
    ]


class CapUserData(ctypes.Structure):
    """cap_user_data_t: one u32 slot per capability set.

    Version 3 uses an array of two: slot 0 holds capabilities 0-31 and
    slot 1 holds capabilities 32-63.
    """

    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


_libc: ctypes.CDLL | None = None
_numbers: tuple[int, int] | None = None


def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        if sys.platform != "linux":
            raise UnsupportedError("capabilities are only available on Linux")
        name = ctypes.util.find_library("c")
        _libc = ctypes.CDLL(name or None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
        _libc.prctl.restype = ctypes.c_int
    return _libc


def _syscall_numbers() -> tuple[int, int]:
    """Return the (capget, capset) syscall numbers for this architecture."""
    global _numbers
    if _numbers is not None:
        return _numbers
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        _numbers = (125, 126)
    elif machine in ("aarch64", "arm64", "riscv64", "loongarch64"):
        _numbers = (90, 91)
    elif machine.startswith("ppc"):
        _numbers = (183, 184)
    elif machine.startswith(("arm", "s390")) or machine in (
        "i386",
        "i486",
        "i586",
        "i686",
        "x86",
    ):
        _numbers = (184, 185)
    else:
        raise UnsupportedError(
            f"no capget/capset syscall numbers for architecture {machine}"
        )
    return _numbers


def _raise_errno(err: int) -> NoReturn:
    if err == errno.ENOSYS:
        raise UnsupportedError(err, os.strerror(err))
    raise CapError(err, os.strerror(err))


def _call(nr: int, *args: object) -> int:
    ret = int(_get_libc().syscall(nr, *args))
    if ret == -1:
        _raise_errno(ctypes.get_errno())
    return ret


def capget(pid: int = 0) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Read a thread's effective, permitted and inheritable sets.

    Each set is returned as a (low, high) pair of u32 masks: the low word
    covers capabilities 0-31, the high word capabilities 32-63.
    """
    header = CapUserHeader(version=_LINUX_CAPABILITY_VERSION_3, pid=pid)
    data = (CapUserData * _LINUX_CAPABILITY_U32S_3)()
    try:
        _call(_syscall_numbers()[0], ctypes.byref(header), ctypes.byref(data))
    except CapError as exc:
        if exc.errno == errno.EINVAL:
            raise UnsupportedError(
                errno.EINVAL,
                "kernel lacks _LINUX_CAPABILITY_VERSION_3 support",
            ) from exc
        raise
    return (
        (data[0].effective, data[1].effective),
        (data[0].permitted, data[1].permitted),
        (data[0].inheritable, data[1].inheritable),
    )


def capset(
    pid: int,
    effective: tuple[int, int],
    permitted: tuple[int, int],
    inheritable: tuple[int, int],
) -> None:
    """Write a thread's capability sets. Each set is a (low, high) mask pair."""
    header = CapUserHeader(version=_LINUX_CAPABILITY_VERSION_3, pid=pid)
    data = (CapUserData * _LINUX_CAPABILITY_U32S_3)(
        CapUserData(effective[0], permitted[0], inheritable[0]),
        CapUserData(effective[1], permitted[1], inheritable[1]),
    )
    _call(_syscall_numbers()[1], ctypes.byref(header), ctypes.byref(data))


def prctl(
    option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0, arg5: int = 0
) -> int:
    """Call prctl(2) and return its result, raising CapError on failure."""
    ret = int(_get_libc().prctl(option, arg2, arg3, arg4, arg5))
    if ret == -1:
        _raise_errno(ctypes.get_errno())
    return ret
