# SPDX-License-Identifier: 0BSD
"""Mocked-syscall tests: encoding, decoding and errno passthrough."""

import ctypes
import errno
import platform
import sys
from types import SimpleNamespace

import pytest

from posixcaps import (
    Cap,
    Capabilities,
    CapError,
    UnsupportedError,
    _syscall,
    ambient,
    ambient_clear,
    ambient_raise,
    ambient_reset,
    bounding,
    cap_last_cap,
    drop_bounding,
    get,
)

Masks = tuple[tuple[int, int], tuple[int, int], tuple[int, int]]

FULL: Masks = ((0xFFFFFFFF, 0x1FF), (0xFFFFFFFF, 0x1FF), (0xFFFFFFFF, 0x1FF))
EMPTY: Masks = ((0, 0), (0, 0), (0, 0))


def stub_capget(monkeypatch: pytest.MonkeyPatch, masks: Masks = EMPTY) -> list[int]:
    seen: list[int] = []

    def fake(pid: int = 0) -> Masks:
        seen.append(pid)
        return masks

    monkeypatch.setattr(_syscall, "capget", fake)
    return seen


def test_for_self_decodes_all_sets(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_capget(
        monkeypatch,
        ((1 << 0, 0), ((1 << 10) | (1 << 31), 1 << 8), (0, 1 << 2)),
    )
    caps = Capabilities.for_self()
    assert caps.effective == frozenset({Cap.CAP_CHOWN})
    assert caps.permitted == frozenset(
        {Cap.CAP_NET_BIND_SERVICE, Cap.CAP_SETFCAP, Cap.CAP_CHECKPOINT_RESTORE}
    )
    assert caps.inheritable == frozenset({Cap.CAP_SYSLOG})
    assert caps.pid == 0


def test_for_pid_passes_thread_id(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = stub_capget(monkeypatch)
    get(4242)
    assert seen == [4242]


def test_for_pid_rejects_negative() -> None:
    with pytest.raises(ValueError, match="negative"):
        Capabilities.for_pid(-1)


def test_capget_einval_means_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval(nr: int, *args: object) -> int:
        raise CapError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "_call", raise_einval)
    with pytest.raises(UnsupportedError):
        _syscall.capget(0)


def test_capget_other_errnos_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_esrch(nr: int, *args: object) -> int:
        raise CapError(errno.ESRCH, "No such process")

    monkeypatch.setattr(_syscall, "_call", raise_esrch)
    with pytest.raises(CapError) as excinfo:
        _syscall.capget(0)
    assert excinfo.value.errno == errno.ESRCH


def test_capset_marshals_header_and_data(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake_call(nr: int, *args: object) -> int:
        calls.args = (nr, *args)
        return 0

    monkeypatch.setattr(_syscall, "_call", fake_call)
    _syscall.capset(0, (1, 2), (3, 4), (5, 6))
    nr, header_ref, data_ref = calls.args
    assert nr == _syscall._syscall_numbers()[1]
    header = header_ref._obj
    data = data_ref._obj
    assert header.version == _syscall._LINUX_CAPABILITY_VERSION_3
    assert header.pid == 0
    assert (data[0].effective, data[0].permitted, data[0].inheritable) == (1, 3, 5)
    assert (data[1].effective, data[1].permitted, data[1].inheritable) == (2, 4, 6)


def test_get_libc_rejects_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_libc", None)
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(UnsupportedError):
        _syscall._get_libc()


def test_prctl_surfaces_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    libc = SimpleNamespace(prctl=lambda *args: -1)
    monkeypatch.setattr(_syscall, "_get_libc", lambda: libc)
    ctypes.set_errno(errno.EPERM)
    with pytest.raises(CapError) as excinfo:
        _syscall.prctl(_syscall.PR_CAPBSET_READ, 0)
    assert excinfo.value.errno == errno.EPERM


def test_raise_errno_maps_enosys() -> None:
    with pytest.raises(UnsupportedError):
        _syscall._raise_errno(errno.ENOSYS)
    with pytest.raises(CapError) as excinfo:
        _syscall._raise_errno(errno.EPERM)
    assert excinfo.value.errno == errno.EPERM


def test_syscall_numbers_other_arches(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = {
        "aarch64": (90, 91),
        "riscv64": (90, 91),
        "i686": (184, 185),
        "armv7l": (184, 185),
        "s390x": (184, 185),
        "ppc64le": (183, 184),
    }
    for machine, numbers in expected.items():
        monkeypatch.setattr(_syscall, "_numbers", None)
        monkeypatch.setattr(platform, "machine", lambda m=machine: m)
        assert _syscall._syscall_numbers() == numbers, machine
    monkeypatch.setattr(_syscall, "_numbers", None)
    monkeypatch.setattr(platform, "machine", lambda: "mips64")
    with pytest.raises(UnsupportedError):
        _syscall._syscall_numbers()


def test_set_writes_all_three_sets(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake_capset(
        pid: int,
        effective: tuple[int, int],
        permitted: tuple[int, int],
        inheritable: tuple[int, int],
    ) -> None:
        calls.args = (pid, effective, permitted, inheritable)

    monkeypatch.setattr(_syscall, "capset", fake_capset)
    caps = Capabilities(
        effective=frozenset(),
        permitted=frozenset({Cap.CAP_NET_BIND_SERVICE, Cap.CAP_BPF}),
        inheritable=frozenset({Cap.CAP_WAKE_ALARM}),
    )
    caps.set(effective={Cap.CAP_NET_BIND_SERVICE})
    assert calls.args == (
        0,
        (1 << 10, 0),
        (1 << 10, 1 << (39 - 32)),
        (0, 1 << (35 - 32)),
    )


def test_set_surfaces_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval(*args: object) -> None:
        raise CapError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "capset", raise_einval)
    caps = Capabilities(frozenset(), frozenset(), frozenset())
    with pytest.raises(CapError) as excinfo:
        caps.set(permitted={Cap.CAP_SYS_ADMIN})
    assert excinfo.value.errno == errno.EINVAL


def test_bounding_collects_prctl_results(monkeypatch: pytest.MonkeyPatch) -> None:
    in_set = {Cap.CAP_CHOWN, Cap.CAP_SYS_ADMIN, Cap.CAP_CHECKPOINT_RESTORE}

    def fake_prctl(option: int, arg2: int, *rest: int) -> int:
        assert option == _syscall.PR_CAPBSET_READ
        return int(Cap(arg2) in in_set)

    monkeypatch.setattr(_syscall, "prctl", fake_prctl)
    assert bounding() == frozenset(in_set)


def test_bounding_einval_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval(*args: int) -> int:
        raise CapError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "prctl", raise_einval)
    with pytest.raises(UnsupportedError):
        bounding()


def test_bounding_other_errnos_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_efault(*args: int) -> int:
        raise CapError(errno.EFAULT, "Bad address")

    monkeypatch.setattr(_syscall, "prctl", raise_efault)
    with pytest.raises(CapError) as excinfo:
        bounding()
    assert excinfo.value.errno == errno.EFAULT


def test_bounding_skips_indexes_above_last_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []

    def fake_prctl(option: int, index: int, *rest: int) -> int:
        seen.append(index)
        return 0

    monkeypatch.setattr("posixcaps.caps.cap_last_cap", lambda: 31)
    monkeypatch.setattr(_syscall, "prctl", fake_prctl)
    assert bounding() == frozenset()
    assert max(seen) == 31


def test_drop_bounding_passes_index(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake_prctl(*args: int) -> int:
        calls.args = args
        return 0

    monkeypatch.setattr(_syscall, "prctl", fake_prctl)
    drop_bounding(Cap.CAP_SYS_RAWIO)
    assert calls.args == (_syscall.PR_CAPBSET_DROP, 17, 0, 0, 0)


def test_drop_bounding_eperm_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_eperm(*args: int) -> int:
        raise CapError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(_syscall, "prctl", raise_eperm)
    with pytest.raises(CapError) as excinfo:
        drop_bounding(Cap.CAP_SYS_ADMIN)
    assert excinfo.value.errno == errno.EPERM


def test_drop_bounding_einval_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval(*args: int) -> int:
        raise CapError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "prctl", raise_einval)
    with pytest.raises(UnsupportedError):
        drop_bounding(Cap.CAP_SYS_ADMIN)


def test_ambient_reads_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_prctl(option: int, subop: int, index: int, *rest: int) -> int:
        assert option == _syscall.PR_CAP_AMBIENT
        assert subop == _syscall.PR_CAP_AMBIENT_IS_SET
        return int(index == int(Cap.CAP_NET_BIND_SERVICE))

    monkeypatch.setattr(_syscall, "prctl", fake_prctl)
    assert ambient() == frozenset({Cap.CAP_NET_BIND_SERVICE})


def test_ambient_read_einval_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval(*args: int) -> int:
        raise CapError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "prctl", raise_einval)
    with pytest.raises(UnsupportedError):
        ambient()


def test_ambient_read_other_errnos_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_efault(*args: int) -> int:
        raise CapError(errno.EFAULT, "Bad address")

    monkeypatch.setattr(_syscall, "prctl", raise_efault)
    with pytest.raises(CapError) as excinfo:
        ambient()
    assert excinfo.value.errno == errno.EFAULT


def test_ambient_read_skips_indexes_above_last_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[int] = []

    def fake_prctl(option: int, subop: int, index: int, *rest: int) -> int:
        seen.append(index)
        return 0

    monkeypatch.setattr("posixcaps.caps.cap_last_cap", lambda: 31)
    monkeypatch.setattr(_syscall, "prctl", fake_prctl)
    assert ambient() == frozenset()
    assert max(seen) == 31


def test_ambient_reset_einval_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval(*args: int) -> int:
        raise CapError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "prctl", raise_einval)
    with pytest.raises(UnsupportedError):
        ambient_reset()


def test_ambient_reset_other_errnos_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_efault(*args: int) -> int:
        raise CapError(errno.EFAULT, "Bad address")

    monkeypatch.setattr(_syscall, "prctl", raise_efault)
    with pytest.raises(CapError) as excinfo:
        ambient_reset()
    assert excinfo.value.errno == errno.EFAULT


def test_ambient_raise_eperm_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_eperm(*args: int) -> int:
        raise CapError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(_syscall, "prctl", raise_eperm)
    with pytest.raises(CapError) as excinfo:
        ambient_raise(Cap.CAP_CHOWN)
    assert excinfo.value.errno == errno.EPERM


def test_ambient_raise_einval_is_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval(*args: int) -> int:
        raise CapError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "prctl", raise_einval)
    with pytest.raises(UnsupportedError):
        ambient_raise(Cap.CAP_CHOWN)


def test_ambient_ops_marshal_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[int, ...]] = []

    def fake_prctl(*args: int) -> int:
        seen.append(args)
        return 0

    monkeypatch.setattr(_syscall, "prctl", fake_prctl)
    ambient_clear(Cap.CAP_MKNOD)
    ambient_reset()
    assert seen == [
        (_syscall.PR_CAP_AMBIENT, _syscall.PR_CAP_AMBIENT_LOWER, 27, 0, 0),
        (_syscall.PR_CAP_AMBIENT, _syscall.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0),
    ]


def test_cap_ops_reject_unknown_index() -> None:
    with pytest.raises(ValueError, match="range"):
        drop_bounding(63)
    with pytest.raises(ValueError, match="range"):
        ambient_raise(63)


def test_cap_last_cap_falls_back_when_proc_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_enoent(*args: object, **kwargs: object) -> str:
        raise FileNotFoundError("no such file")

    monkeypatch.setattr(
        "posixcaps.caps._CAP_LAST_CAP_PATH",
        SimpleNamespace(read_text=raise_enoent),
    )
    assert cap_last_cap() == int(Cap.CAP_CHECKPOINT_RESTORE)


def test_errors_carry_errno() -> None:
    err = CapError(errno.EACCES, "denied")
    assert err.errno == errno.EACCES
    assert isinstance(err, OSError)
    assert isinstance(UnsupportedError(errno.ENOSYS, "x"), CapError)
