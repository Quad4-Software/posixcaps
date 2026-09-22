# SPDX-License-Identifier: 0BSD
"""The ctypes layouts and constants must match the kernel ABI exactly."""

import ctypes
import struct

import pytest

from posixcaps import _syscall
from posixcaps.caps import Cap
from posixcaps.filecaps import FileCaps, _pack, _unpack


def test_cap_user_header_layout() -> None:
    assert ctypes.sizeof(_syscall.CapUserHeader) == 8
    assert _syscall.CapUserHeader.version.offset == 0
    assert _syscall.CapUserHeader.pid.offset == 4


def test_cap_user_data_layout() -> None:
    assert ctypes.sizeof(_syscall.CapUserData) == 12
    assert _syscall.CapUserData.effective.offset == 0
    assert _syscall.CapUserData.permitted.offset == 4
    assert _syscall.CapUserData.inheritable.offset == 8
    assert ctypes.sizeof(_syscall.CapUserData * 2) == 24


def test_abi_version_constants() -> None:
    assert _syscall._LINUX_CAPABILITY_VERSION_3 == 0x20080522
    assert _syscall._LINUX_CAPABILITY_U32S_3 == 2


def test_prctl_constants() -> None:
    assert _syscall.PR_CAPBSET_READ == 23
    assert _syscall.PR_CAPBSET_DROP == 24
    assert _syscall.PR_CAP_AMBIENT == 47
    assert _syscall.PR_CAP_AMBIENT_IS_SET == 1
    assert _syscall.PR_CAP_AMBIENT_RAISE == 2
    assert _syscall.PR_CAP_AMBIENT_LOWER == 3
    assert _syscall.PR_CAP_AMBIENT_CLEAR_ALL == 4


def test_syscall_numbers_x86_64() -> None:
    assert _syscall._syscall_numbers() == (125, 126)


def test_vfs_pack_is_v3_layout() -> None:
    caps = FileCaps(
        effective=True,
        permitted=frozenset(
            {Cap.CAP_CHOWN, Cap.CAP_SYS_ADMIN, Cap.CAP_SETFCAP, Cap.CAP_BPF}
        ),
        inheritable=frozenset({Cap.CAP_NET_RAW}),
        rootid=1000,
    )
    blob = _pack(caps)
    assert len(blob) == 24
    magic, p_lo, i_lo, p_hi, i_hi, rootid = struct.unpack("<6I", blob)
    assert magic == 0x03000001
    assert p_lo == (1 << 0) | (1 << 21) | (1 << 31)
    assert i_lo == 1 << 13
    assert p_hi == 1 << (39 - 32)
    assert i_hi == 0
    assert rootid == 1000


def test_vfs_pack_no_effective_bit() -> None:
    caps = FileCaps(effective=False, permitted=frozenset(), inheritable=frozenset())
    blob = _pack(caps)
    magic = struct.unpack("<I", blob[:4])[0]
    assert magic == 0x03000000


def test_vfs_unpack_v1() -> None:
    blob = struct.pack("<3I", 0x01000001, (1 << 5) | (1 << 12), 1 << 7)
    caps = _unpack(blob)
    assert caps.effective
    assert caps.permitted == frozenset({Cap.CAP_KILL, Cap.CAP_NET_ADMIN})
    assert caps.inheritable == frozenset({Cap.CAP_SETUID})
    assert caps.rootid == 0


def test_vfs_unpack_v2() -> None:
    blob = struct.pack("<5I", 0x02000000, 1 << 31, 0, 1 << (34 - 32), 1 << (40 - 32))
    caps = _unpack(blob)
    assert not caps.effective
    assert caps.permitted == frozenset({Cap.CAP_SETFCAP, Cap.CAP_SYSLOG})
    assert caps.inheritable == frozenset({Cap.CAP_CHECKPOINT_RESTORE})
    assert caps.rootid == 0


def test_vfs_unpack_v3_roundtrip() -> None:
    original = FileCaps(
        effective=True,
        permitted=frozenset({Cap.CAP_CHOWN, Cap.CAP_AUDIT_READ, Cap.CAP_PERFMON}),
        inheritable=frozenset({Cap.CAP_MKNOD, Cap.CAP_MAC_ADMIN}),
        rootid=4242,
    )
    assert _unpack(_pack(original)) == original


def test_vfs_unpack_rejects_bad_size() -> None:
    with pytest.raises(ValueError, match="size"):
        _unpack(b"\x00" * 8)


def test_vfs_unpack_rejects_revision_size_mismatch() -> None:
    blob = struct.pack("<3I", 0x02000000, 0, 0)
    with pytest.raises(ValueError, match="revision"):
        _unpack(blob)


def test_vfs_pack_rejects_bad_rootid() -> None:
    caps = FileCaps(
        effective=False, permitted=frozenset(), inheritable=frozenset(), rootid=-1
    )
    with pytest.raises(ValueError, match="rootid"):
        _pack(caps)
