# SPDX-License-Identifier: 0BSD
"""Thread securebits via prctl(PR_GET_SECUREBITS/PR_SET_SECUREBITS).

SecureBits mirrors the SECBIT_* masks from linux/securebits.h: each
member's value is the bit stored in the kernel's securebits word, so a
combined mask can be passed straight to PR_SET_SECUREBITS. Every
setting pairs a flag bit with a *_LOCKED bit that makes the flag
immutable once set.

Kernel references: capabilities(7), prctl(2), linux/securebits.h.
"""

from __future__ import annotations

from enum import IntFlag

from . import _syscall

__all__ = ["SecureBits", "issecure", "securebits", "set_securebits"]


class SecureBits(IntFlag):
    """A SECBIT_* flag or lock bit, mirroring linux/securebits.h.

    Each member's value is the kernel mask, 1 << SECURE_*, exactly as
    PR_GET_SECUREBITS returns it: NOROOT is bit 0, NOROOT_LOCKED bit 1,
    and so on up to EXEC_DENY_INTERACTIVE_LOCKED at bit 11.

    NOROOT makes uid 0 carry no implicit privilege. NO_SETUID_FIXUP
    stops set*uid transitions from fixing up the capability sets.
    KEEP_CAPS keeps capabilities across a setuid away from uid 0 (and is
    always cleared by execve(2)). NO_CAP_AMBIENT_RAISE forbids adding
    capabilities to the ambient set. EXEC_RESTRICT_FILE and
    EXEC_DENY_INTERACTIVE (Linux 6.17+) ask user space interpreters to
    vet what they execute. See Documentation/userspace-api/check_exec.rst.
    """

    NOROOT = 1 << 0
    NOROOT_LOCKED = 1 << 1
    NO_SETUID_FIXUP = 1 << 2
    NO_SETUID_FIXUP_LOCKED = 1 << 3
    KEEP_CAPS = 1 << 4
    KEEP_CAPS_LOCKED = 1 << 5
    NO_CAP_AMBIENT_RAISE = 1 << 6
    NO_CAP_AMBIENT_RAISE_LOCKED = 1 << 7
    EXEC_RESTRICT_FILE = 1 << 8
    EXEC_RESTRICT_FILE_LOCKED = 1 << 9
    EXEC_DENY_INTERACTIVE = 1 << 10
    EXEC_DENY_INTERACTIVE_LOCKED = 1 << 11


def securebits() -> SecureBits:
    """Return the calling thread's securebits mask (PR_GET_SECUREBITS).

    Reading needs no privilege. Bits the kernel sets but this library
    does not know survive in the returned mask, because IntFlag keeps
    unnamed bits.
    """
    return SecureBits(_syscall.prctl(_syscall.PR_GET_SECUREBITS, 0, 0, 0, 0))


def set_securebits(bits: SecureBits | int) -> None:
    """Replace the calling thread's securebits mask (PR_SET_SECUREBITS).

    Changing the classic bits, everything except EXEC_RESTRICT_FILE and
    EXEC_DENY_INTERACTIVE and their locks, requires CAP_SETPCAP in the
    effective set. Without it the kernel answers EPERM. The two exec
    bits may be raised without privilege on kernels that define them
    (Linux 6.17+). On kernels where the caller lacks CAP_SETPCAP, even a
    no-op write answers EPERM.

    Locked bits are irreversible: once a *_LOCKED bit is set, neither
    the lock nor its flag can change again, and attempts to do so
    answer EPERM. Securebits are inherited across fork(2) and execve(2)
    except KEEP_CAPS, which exec clears.
    """
    _syscall.prctl(_syscall.PR_SET_SECUREBITS, int(bits), 0, 0, 0)


def issecure(bit: SecureBits) -> bool:
    """Return whether the given securebit is set on the calling thread.

    Mirrors the kernel's issecure() helper, which tests one SECBIT_ bit
    of the caller's securebits: issecure(SECURE_NOROOT) in C is
    issecure(SecureBits.NOROOT) here.
    """
    return bool(securebits() & bit)
