# SPDX-License-Identifier: 0BSD

from enum import IntEnum

import pytest
from hypothesis import given
from hypothesis import strategies as st

from posixcaps import Cap
from posixcaps.caps import _masks_to_set, _set_to_masks

EXPECTED = {
    "CAP_CHOWN": 0,
    "CAP_DAC_OVERRIDE": 1,
    "CAP_DAC_READ_SEARCH": 2,
    "CAP_FOWNER": 3,
    "CAP_FSETID": 4,
    "CAP_KILL": 5,
    "CAP_SETGID": 6,
    "CAP_SETUID": 7,
    "CAP_SETPCAP": 8,
    "CAP_LINUX_IMMUTABLE": 9,
    "CAP_NET_BIND_SERVICE": 10,
    "CAP_NET_BROADCAST": 11,
    "CAP_NET_ADMIN": 12,
    "CAP_NET_RAW": 13,
    "CAP_IPC_LOCK": 14,
    "CAP_IPC_OWNER": 15,
    "CAP_SYS_MODULE": 16,
    "CAP_SYS_RAWIO": 17,
    "CAP_SYS_CHROOT": 18,
    "CAP_SYS_PTRACE": 19,
    "CAP_SYS_PACCT": 20,
    "CAP_SYS_ADMIN": 21,
    "CAP_SYS_BOOT": 22,
    "CAP_SYS_NICE": 23,
    "CAP_SYS_RESOURCE": 24,
    "CAP_SYS_TIME": 25,
    "CAP_SYS_TTY_CONFIG": 26,
    "CAP_MKNOD": 27,
    "CAP_LEASE": 28,
    "CAP_AUDIT_WRITE": 29,
    "CAP_AUDIT_CONTROL": 30,
    "CAP_SETFCAP": 31,
    "CAP_MAC_OVERRIDE": 32,
    "CAP_MAC_ADMIN": 33,
    "CAP_SYSLOG": 34,
    "CAP_WAKE_ALARM": 35,
    "CAP_BLOCK_SUSPEND": 36,
    "CAP_AUDIT_READ": 37,
    "CAP_PERFMON": 38,
    "CAP_BPF": 39,
    "CAP_CHECKPOINT_RESTORE": 40,
}


def test_enum_values_match_kernel_header() -> None:
    assert issubclass(Cap, IntEnum)
    for name, value in EXPECTED.items():
        assert Cap[name] == value, name
    assert len(list(Cap)) == 41


def test_last_cap_alias() -> None:
    assert int(Cap.CAP_LAST_CAP) == 40
    assert max(int(cap) for cap in Cap) == 40


def test_masks_split_at_slot_boundary() -> None:
    lo, hi = _set_to_masks({Cap.CAP_SETFCAP, Cap.CAP_MAC_OVERRIDE, Cap.CAP_CHOWN})
    assert lo == (1 << 0) | (1 << 31)
    assert hi == 1 << 0
    lo, hi = _set_to_masks({Cap.CAP_CHECKPOINT_RESTORE})
    assert lo == 0
    assert hi == 1 << 8


def test_masks_decode_both_slots() -> None:
    caps = _masks_to_set((1 << 0) | (1 << 31), (1 << 0) | (1 << 8))
    assert caps == frozenset(
        {
            Cap.CAP_CHOWN,
            Cap.CAP_SETFCAP,
            Cap.CAP_MAC_OVERRIDE,
            Cap.CAP_CHECKPOINT_RESTORE,
        }
    )


def test_masks_decode_drops_unknown_indexes() -> None:
    assert _masks_to_set(0, 1 << 31) == frozenset()  # index 63 is not a Cap
    assert _masks_to_set(0xFFFFFFFF, 0xFFFFFFFF) == frozenset(Cap)


def test_set_to_masks_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="range"):
        _set_to_masks({64})
    with pytest.raises(ValueError, match="range"):
        _set_to_masks({-1})


@given(caps=st.frozensets(st.sampled_from(list(Cap))))
def test_mask_roundtrip(caps: frozenset[Cap]) -> None:
    lo, hi = _set_to_masks(caps)
    assert _masks_to_set(lo, hi) == caps


@given(lo=st.integers(0, 0xFFFFFFFF), hi=st.integers(0, 0xFFFFFFFF))
def test_decode_only_returns_known_caps(lo: int, hi: int) -> None:
    caps = _masks_to_set(lo, hi)
    assert caps <= frozenset(Cap)
    lo2, hi2 = _set_to_masks(caps)
    assert _masks_to_set(lo2, hi2) == caps
