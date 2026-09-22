# SPDX-License-Identifier: 0BSD
"""Python bindings for Linux capabilities.

Read and modify the effective, permitted, inheritable, bounding and
ambient capability sets of threads, and the file capabilities stored in
the security.capability extended attribute. Everything goes through
capget(2)/capset(2), prctl(2) and getxattr(2)/setxattr(2) via ctypes.
There are no runtime dependencies.

Kernel references: capabilities(7), capget(2), prctl(2).
"""

from .caps import (
    Cap,
    Capabilities,
    ambient,
    ambient_clear,
    ambient_raise,
    ambient_reset,
    bounding,
    cap_last_cap,
    drop_bounding,
    get,
)
from .errors import CapError, UnsupportedError
from .filecaps import FileCaps, get_file_caps, set_file_caps
from .securebits import SecureBits, issecure, securebits, set_securebits

__version__ = "0.2.0"

__all__ = [
    "Cap",
    "CapError",
    "Capabilities",
    "FileCaps",
    "SecureBits",
    "UnsupportedError",
    "__version__",
    "ambient",
    "ambient_clear",
    "ambient_raise",
    "ambient_reset",
    "bounding",
    "cap_last_cap",
    "drop_bounding",
    "get",
    "get_file_caps",
    "issecure",
    "securebits",
    "set_file_caps",
    "set_securebits",
]
