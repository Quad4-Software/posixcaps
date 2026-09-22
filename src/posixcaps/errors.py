# SPDX-License-Identifier: 0BSD
"""Exception types raised by posixcaps."""


class CapError(OSError):
    """A capability syscall failed."""


class UnsupportedError(CapError):
    """The running kernel does not support the requested capability feature."""
