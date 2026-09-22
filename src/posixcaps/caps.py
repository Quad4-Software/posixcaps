# SPDX-License-Identifier: 0BSD
"""Capability sets of Linux threads, plus bounding and ambient operations.

Cap mirrors the CAP_* indexes from linux/capability.h. Capabilities is a
snapshot of a thread's effective, permitted and inheritable sets as
reported by capget(2); set() writes new sets back with capset(2). The
bounding set is managed through prctl(PR_CAPBSET_*) and the ambient set
through prctl(PR_CAP_AMBIENT_*).

Kernel references: capabilities(7), capget(2), prctl(2).
"""

from __future__ import annotations

import errno
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

from . import _syscall
from .errors import CapError, UnsupportedError

__all__ = [
    "Cap",
    "Capabilities",
    "ambient",
    "ambient_clear",
    "ambient_raise",
    "ambient_reset",
    "bounding",
    "cap_last_cap",
    "drop_bounding",
    "get",
]


class Cap(IntEnum):
    """A capability index, mirroring CAP_* from linux/capability.h.

    The numeric value is the bit index inside the kernel's capability
    masks: values 0-31 live in slot 0 of cap_user_data_t, values 32-40
    in slot 1. CAP_LAST_CAP is an alias for the highest defined index.
    """

    CAP_CHOWN = 0
    CAP_DAC_OVERRIDE = 1
    CAP_DAC_READ_SEARCH = 2
    CAP_FOWNER = 3
    CAP_FSETID = 4
    CAP_KILL = 5
    CAP_SETGID = 6
    CAP_SETUID = 7
    CAP_SETPCAP = 8
    CAP_LINUX_IMMUTABLE = 9
    CAP_NET_BIND_SERVICE = 10
    CAP_NET_BROADCAST = 11
    CAP_NET_ADMIN = 12
    CAP_NET_RAW = 13
    CAP_IPC_LOCK = 14
    CAP_IPC_OWNER = 15
    CAP_SYS_MODULE = 16
    CAP_SYS_RAWIO = 17
    CAP_SYS_CHROOT = 18
    CAP_SYS_PTRACE = 19
    CAP_SYS_PACCT = 20
    CAP_SYS_ADMIN = 21
    CAP_SYS_BOOT = 22
    CAP_SYS_NICE = 23
    CAP_SYS_RESOURCE = 24
    CAP_SYS_TIME = 25
    CAP_SYS_TTY_CONFIG = 26
    CAP_MKNOD = 27
    CAP_LEASE = 28
    CAP_AUDIT_WRITE = 29
    CAP_AUDIT_CONTROL = 30
    CAP_SETFCAP = 31
    CAP_MAC_OVERRIDE = 32
    CAP_MAC_ADMIN = 33
    CAP_SYSLOG = 34
    CAP_WAKE_ALARM = 35
    CAP_BLOCK_SUSPEND = 36
    CAP_AUDIT_READ = 37
    CAP_PERFMON = 38
    CAP_BPF = 39
    CAP_CHECKPOINT_RESTORE = 40
    CAP_LAST_CAP = 40


_CAP_LAST_CAP_PATH = Path("/proc/sys/kernel/cap_last_cap")


def cap_last_cap() -> int:
    """Return the highest capability index the running kernel supports.

    Reads /proc/sys/kernel/cap_last_cap and falls back to the highest
    capability known to this library when the file is unavailable.
    """
    try:
        return int(_CAP_LAST_CAP_PATH.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return int(Cap.CAP_CHECKPOINT_RESTORE)


def _set_to_masks(caps: Iterable[int]) -> tuple[int, int]:
    """Pack capability indexes into the (low, high) u32 pair of capset."""
    lo = hi = 0
    for cap in caps:
        index = int(cap)
        if not 0 <= index < 64:
            raise ValueError(f"capability index out of range: {index}")
        if index < 32:
            lo |= 1 << index
        else:
            hi |= 1 << (index - 32)
    return lo, hi


def _masks_to_set(lo: int, hi: int) -> frozenset[Cap]:
    """Unpack a (low, high) mask pair, dropping indexes unknown to Cap."""
    mask = (hi << 32) | lo
    return frozenset(cap for cap in Cap if mask & (1 << cap.value))


def _check_index(cap: Cap | int) -> int:
    index = int(cap)
    if not 0 <= index <= cap_last_cap():
        raise ValueError(f"capability index out of range: {index}")
    return index


@dataclass(frozen=True)
class Capabilities:
    """Snapshot of a thread's effective, permitted and inheritable sets.

    Read with for_self() or for_pid(); write back with set(). The object
    is immutable: set() pushes new values to the kernel but does not
    refresh the snapshot.
    """

    effective: frozenset[Cap]
    permitted: frozenset[Cap]
    inheritable: frozenset[Cap]
    pid: int = 0
    _masks: tuple[tuple[int, int], tuple[int, int], tuple[int, int]] | None = field(
        default=None, repr=False, compare=False
    )

    @classmethod
    def for_self(cls) -> Capabilities:
        """Read the capability sets of the calling thread."""
        return cls.for_pid(0)

    @classmethod
    def for_pid(cls, pid: int) -> Capabilities:
        """Read the capability sets of the given thread id."""
        if pid < 0:
            raise ValueError(f"pid must not be negative: {pid}")
        effective, permitted, inheritable = _syscall.capget(pid)
        return cls(
            effective=_masks_to_set(*effective),
            permitted=_masks_to_set(*permitted),
            inheritable=_masks_to_set(*inheritable),
            pid=pid,
            _masks=(effective, permitted, inheritable),
        )

    def set(
        self,
        *,
        effective: Iterable[Cap] | None = None,
        permitted: Iterable[Cap] | None = None,
        inheritable: Iterable[Cap] | None = None,
    ) -> None:
        """Write capability sets back to the kernel via capset(2).

        Arguments left as None keep this snapshot's values; capset always
        writes all three sets at once. Only the calling thread's sets can
        be changed: other pids are rejected with EPERM, and requests that
        break the rules of capabilities(7), such as adding a capability
        to the permitted set, surface as CapError with the kernel errno
        (EINVAL or EPERM).
        """
        # Sets not overridden keep the raw kernel masks so capability bits
        # unknown to the Cap enum survive a read-modify-write roundtrip.
        raw = self._masks

        def masks_of(
            index: int, arg: Iterable[Cap] | None, current: frozenset[Cap]
        ) -> tuple[int, int]:
            if arg is None:
                if raw is not None:
                    return raw[index]
                arg = current
            return _set_to_masks(arg)

        _syscall.capset(
            self.pid,
            masks_of(0, effective, self.effective),
            masks_of(1, permitted, self.permitted),
            masks_of(2, inheritable, self.inheritable),
        )


def get(pid: int = 0) -> Capabilities:
    """Return the capability sets of a thread (default: the caller)."""
    return Capabilities.for_pid(pid)


def bounding() -> frozenset[Cap]:
    """Return the calling thread's capability bounding set.

    The bounding set limits which capabilities can be gained during
    execve(2) and added to the inheritable set. See capabilities(7).
    """
    last = cap_last_cap()
    result: set[Cap] = set()
    for cap in Cap:
        if cap.value > last:
            continue
        try:
            if _syscall.prctl(_syscall.PR_CAPBSET_READ, cap.value, 0, 0, 0):
                result.add(cap)
        except CapError as exc:
            if exc.errno == errno.EINVAL:
                raise UnsupportedError(
                    errno.EINVAL, "kernel lacks capability bounding set support"
                ) from exc
            raise
    return frozenset(result)


def drop_bounding(cap: Cap | int) -> None:
    """Remove a capability from the calling thread's bounding set.

    Dropping is irreversible for the thread and its descendants and
    requires CAP_SETPCAP in the effective set; without it the kernel
    answers EPERM.
    """
    index = _check_index(cap)
    try:
        _syscall.prctl(_syscall.PR_CAPBSET_DROP, index, 0, 0, 0)
    except CapError as exc:
        if exc.errno == errno.EINVAL:
            raise UnsupportedError(
                errno.EINVAL, "kernel lacks capability bounding set support"
            ) from exc
        raise


def ambient() -> frozenset[Cap]:
    """Return the calling thread's ambient capability set (Linux 4.3+)."""
    last = cap_last_cap()
    result: set[Cap] = set()
    for cap in Cap:
        if cap.value > last:
            continue
        try:
            if _syscall.prctl(
                _syscall.PR_CAP_AMBIENT, _syscall.PR_CAP_AMBIENT_IS_SET, cap.value, 0, 0
            ):
                result.add(cap)
        except CapError as exc:
            if exc.errno == errno.EINVAL:
                raise UnsupportedError(
                    errno.EINVAL, "kernel lacks ambient capability support"
                ) from exc
            raise
    return frozenset(result)


def _ambient_op(subop: int, cap: Cap | int) -> None:
    index = _check_index(cap)
    try:
        _syscall.prctl(_syscall.PR_CAP_AMBIENT, subop, index, 0, 0)
    except CapError as exc:
        if exc.errno == errno.EINVAL:
            raise UnsupportedError(
                errno.EINVAL, "kernel lacks ambient capability support"
            ) from exc
        raise


def ambient_raise(cap: Cap | int) -> None:
    """Add a capability to the calling thread's ambient set.

    The capability must already be in both the permitted and the
    inheritable set, otherwise the kernel answers EPERM.
    """
    _ambient_op(_syscall.PR_CAP_AMBIENT_RAISE, cap)


def ambient_clear(cap: Cap | int) -> None:
    """Remove a capability from the calling thread's ambient set."""
    _ambient_op(_syscall.PR_CAP_AMBIENT_LOWER, cap)


def ambient_reset() -> None:
    """Clear the calling thread's whole ambient set."""
    try:
        _syscall.prctl(
            _syscall.PR_CAP_AMBIENT, _syscall.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0
        )
    except CapError as exc:
        if exc.errno == errno.EINVAL:
            raise UnsupportedError(
                errno.EINVAL, "kernel lacks ambient capability support"
            ) from exc
        raise
