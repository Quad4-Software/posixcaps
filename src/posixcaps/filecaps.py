# SPDX-License-Identifier: 0BSD
"""File capabilities in the security.capability extended attribute.

The xattr stores struct vfs_cap_data (v1/v2) or struct vfs_ns_cap_data
(v3) in little-endian u32 words: a magic_etc word carrying the revision
in its top byte and the effective flag in bit 0, then a permitted and
inheritable mask pair per u32 slot, and for v3 a trailing rootid word.
Reads of all three revisions are normalized to FileCaps. Writes always
use the v3 layout.

Kernel references: capabilities(7), linux/capability.h, setxattr(2).
"""

from __future__ import annotations

import errno
import os
import struct
from collections.abc import Iterable
from dataclasses import dataclass

from .caps import Cap, _masks_to_set, _set_to_masks

__all__ = ["FileCaps", "get_file_caps", "set_file_caps"]

_XATTR_NAME = "security.capability"

_VFS_CAP_REVISION_1 = 0x01000000
_VFS_CAP_REVISION_2 = 0x02000000
_VFS_CAP_REVISION_3 = 0x03000000
_VFS_CAP_REVISION_MASK = 0xFF000000
_VFS_CAP_FLAGS_EFFECTIVE = 0x000001

_XATTR_SIZE_V1 = 12
_XATTR_SIZE_V2 = 20
_XATTR_SIZE_V3 = 24


@dataclass(frozen=True)
class FileCaps:
    """Normalized view of a file's security.capability xattr.

    effective is the xattr's effective bit: when set, permitted
    capabilities also land in the process's effective set on execve(2).
    rootid is only stored by v3 xattrs. v1/v2 reads report 0, matching
    how the kernel interprets them.
    """

    effective: bool
    permitted: frozenset[Cap]
    inheritable: frozenset[Cap]
    rootid: int = 0


def _pack(caps: FileCaps) -> bytes:
    """Pack FileCaps into a v3 vfs_ns_cap_data blob (24 bytes)."""
    if not 0 <= caps.rootid <= 0xFFFFFFFF:
        raise ValueError(f"rootid out of range: {caps.rootid}")
    magic = _VFS_CAP_REVISION_3
    if caps.effective:
        magic |= _VFS_CAP_FLAGS_EFFECTIVE
    perm_lo, perm_hi = _set_to_masks(caps.permitted)
    inh_lo, inh_hi = _set_to_masks(caps.inheritable)
    return struct.pack("<6I", magic, perm_lo, inh_lo, perm_hi, inh_hi, caps.rootid)


def _unpack(blob: bytes) -> FileCaps:
    """Unpack a v1, v2 or v3 security.capability blob into FileCaps."""
    formats = {_XATTR_SIZE_V1: "<3I", _XATTR_SIZE_V2: "<5I", _XATTR_SIZE_V3: "<6I"}
    fmt = formats.get(len(blob))
    if fmt is None:
        raise ValueError(f"bad security.capability xattr size: {len(blob)}")
    expected = {
        _XATTR_SIZE_V1: _VFS_CAP_REVISION_1,
        _XATTR_SIZE_V2: _VFS_CAP_REVISION_2,
        _XATTR_SIZE_V3: _VFS_CAP_REVISION_3,
    }
    words = struct.unpack(fmt, blob)
    magic = words[0]
    revision = magic & _VFS_CAP_REVISION_MASK
    if revision != expected[len(blob)]:
        raise ValueError(
            f"capability xattr revision {revision:#x} does not match "
            f"its {len(blob)}-byte size"
        )
    effective = bool(magic & _VFS_CAP_FLAGS_EFFECTIVE)
    if len(blob) == _XATTR_SIZE_V1:
        perm_lo, inh_lo = words[1], words[2]
        perm_hi = inh_hi = 0
        rootid = 0
    elif len(blob) == _XATTR_SIZE_V2:
        perm_lo, inh_lo, perm_hi, inh_hi = words[1], words[2], words[3], words[4]
        rootid = 0
    else:
        perm_lo, inh_lo, perm_hi, inh_hi, rootid = (
            words[1],
            words[2],
            words[3],
            words[4],
            words[5],
        )
    return FileCaps(
        effective=effective,
        permitted=_masks_to_set(perm_lo, perm_hi),
        inheritable=_masks_to_set(inh_lo, inh_hi),
        rootid=rootid,
    )


def get_file_caps(path: str | os.PathLike[str]) -> FileCaps | None:
    """Return the file capabilities of path, or None when it has none.

    None is returned when the xattr is absent (ENODATA) or the
    filesystem does not support extended attributes at all (ENOTSUP).
    A malformed blob raises ValueError.
    """
    try:
        blob = os.getxattr(path, _XATTR_NAME)
    except OSError as exc:
        if exc.errno in (errno.ENODATA, errno.ENOTSUP):
            return None
        raise
    return _unpack(blob)


def set_file_caps(
    path: str | os.PathLike[str],
    *,
    effective: bool = False,
    permitted: Iterable[Cap] = (),
    inheritable: Iterable[Cap] = (),
    rootid: int = 0,
) -> None:
    """Write file capabilities to path's security.capability xattr.

    The blob is always written in the v3 vfs_ns_cap_data layout.
    Requires CAP_SETFCAP in the effective set. A missing privilege or a
    filesystem without xattr support surfaces as OSError.
    """
    caps = FileCaps(
        effective=bool(effective),
        permitted=frozenset(permitted),
        inheritable=frozenset(inheritable),
        rootid=rootid,
    )
    os.setxattr(path, _XATTR_NAME, _pack(caps))
