# SPDX-License-Identifier: 0BSD
"""Securebits tests: enum values, prctl marshalling and real-kernel behavior.

Read tests need no privilege. Mutation tests run in a forked child so
the test process keeps its own securebits, and skip when the required
capability or kernel feature is missing.
"""

import ctypes
import errno
import os
from enum import IntFlag
from types import SimpleNamespace

import pytest

from posixcaps import (
    Cap,
    Capabilities,
    CapError,
    SecureBits,
    _syscall,
    issecure,
    securebits,
    set_securebits,
)

from .conftest import requires_linux, requires_setpcap

EXPECTED = {
    "NOROOT": 1 << 0,
    "NOROOT_LOCKED": 1 << 1,
    "NO_SETUID_FIXUP": 1 << 2,
    "NO_SETUID_FIXUP_LOCKED": 1 << 3,
    "KEEP_CAPS": 1 << 4,
    "KEEP_CAPS_LOCKED": 1 << 5,
    "NO_CAP_AMBIENT_RAISE": 1 << 6,
    "NO_CAP_AMBIENT_RAISE_LOCKED": 1 << 7,
    "EXEC_RESTRICT_FILE": 1 << 8,
    "EXEC_RESTRICT_FILE_LOCKED": 1 << 9,
    "EXEC_DENY_INTERACTIVE": 1 << 10,
    "EXEC_DENY_INTERACTIVE_LOCKED": 1 << 11,
}


def _wait_code(pid: int) -> int:
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def test_enum_values_match_kernel_header() -> None:
    assert issubclass(SecureBits, IntFlag)
    for name, value in EXPECTED.items():
        assert SecureBits[name] == value, name
    assert len(list(SecureBits)) == 12


def test_prctl_constants() -> None:
    assert _syscall.PR_GET_SECUREBITS == 27
    assert _syscall.PR_SET_SECUREBITS == 28


def test_securebits_decodes_mask(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_prctl(option: int, *rest: int) -> int:
        assert option == _syscall.PR_GET_SECUREBITS
        return (1 << 0) | (1 << 3) | (1 << 6)

    monkeypatch.setattr(_syscall, "prctl", fake_prctl)
    bits = securebits()
    assert isinstance(bits, SecureBits)
    assert bits == (
        SecureBits.NOROOT
        | SecureBits.NO_SETUID_FIXUP_LOCKED
        | SecureBits.NO_CAP_AMBIENT_RAISE
    )


def test_securebits_keeps_unknown_bits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "prctl", lambda *args: 1 << 20)
    assert securebits() == SecureBits(1 << 20)


def test_set_securebits_marshals_mask(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake_prctl(*args: int) -> int:
        calls.args = args
        return 0

    monkeypatch.setattr(_syscall, "prctl", fake_prctl)
    set_securebits(SecureBits.NOROOT | SecureBits.NOROOT_LOCKED)
    assert calls.args == (_syscall.PR_SET_SECUREBITS, 0b11, 0, 0, 0)


def test_set_securebits_accepts_int(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = SimpleNamespace(args=None)

    def fake_prctl(*args: int) -> int:
        calls.args = args
        return 0

    monkeypatch.setattr(_syscall, "prctl", fake_prctl)
    set_securebits(0b101)
    assert calls.args == (_syscall.PR_SET_SECUREBITS, 0b101, 0, 0, 0)


def test_set_securebits_surfaces_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_eperm(*args: int) -> int:
        raise CapError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(_syscall, "prctl", raise_eperm)
    with pytest.raises(CapError) as excinfo:
        set_securebits(SecureBits.NOROOT)
    assert excinfo.value.errno == errno.EPERM


def test_issecure_tests_single_bit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "prctl", lambda *args: 1 << 4)
    assert issecure(SecureBits.KEEP_CAPS)
    assert not issecure(SecureBits.NOROOT)
    assert not issecure(SecureBits.KEEP_CAPS_LOCKED)


def test_prctl_securebits_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    libc = SimpleNamespace(prctl=lambda *args: -1)
    monkeypatch.setattr(_syscall, "_get_libc", lambda: libc)
    ctypes.set_errno(errno.EINVAL)
    with pytest.raises(CapError) as excinfo:
        _syscall.prctl(_syscall.PR_GET_SECUREBITS, 0)
    assert excinfo.value.errno == errno.EINVAL


@requires_linux
def test_securebits_read_is_unprivileged() -> None:
    bits = securebits()
    assert isinstance(bits, SecureBits)
    # The kernel mask only ever contains defined SECBIT_ positions.
    assert int(bits) < (1 << 32)


@requires_linux
def test_issecure_matches_securebits() -> None:
    bits = securebits()
    for bit in SecureBits:
        assert issecure(bit) == bool(bits & bit)


@requires_linux
def test_set_unprivileged_exec_bit_in_child() -> None:
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            old = securebits()
            set_securebits(old | SecureBits.EXEC_RESTRICT_FILE)
            if not issecure(SecureBits.EXEC_RESTRICT_FILE):
                code = 1
        except CapError as exc:
            code = 3 if exc.errno == errno.EPERM else 2
        os._exit(code)
    code = _wait_code(pid)
    if code == 3:
        pytest.skip("kernel lacks the unprivileged exec securebits")
    assert code == 0


@requires_linux
def test_locked_bit_cannot_be_cleared_in_child() -> None:
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            bits = SecureBits.EXEC_RESTRICT_FILE | SecureBits.EXEC_RESTRICT_FILE_LOCKED
            set_securebits(securebits() | bits)
            if securebits() & bits != bits:
                os._exit(1)
            try:
                set_securebits(securebits() & ~SecureBits.EXEC_RESTRICT_FILE)
            except CapError as exc:
                code = 0 if exc.errno == errno.EPERM else 2
            else:
                code = 1
        except CapError as exc:
            code = 3 if exc.errno == errno.EPERM else 2
        os._exit(code)
    code = _wait_code(pid)
    if code == 3:
        pytest.skip("kernel lacks the unprivileged exec securebits")
    assert code == 0


@requires_linux
def test_privileged_bit_eperm_without_setpcap_in_child() -> None:
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            caps = Capabilities.for_self()
            caps.set(effective=caps.effective - {Cap.CAP_SETPCAP})
            try:
                set_securebits(securebits() | SecureBits.NOROOT)
            except CapError as exc:
                code = 0 if exc.errno == errno.EPERM else 2
            else:
                code = 1
        except OSError:
            code = 2
        os._exit(code)
    assert _wait_code(pid) == 0


@requires_linux
@requires_setpcap
def test_lock_classic_bit_in_child() -> None:
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            bits = SecureBits.NOROOT | SecureBits.NOROOT_LOCKED
            set_securebits(securebits() | bits)
            if securebits() & bits != bits:
                os._exit(1)
            try:
                set_securebits(securebits() & ~SecureBits.NOROOT)
            except CapError as exc:
                code = 0 if exc.errno == errno.EPERM else 2
            else:
                code = 1
        except OSError:
            code = 2
        os._exit(code)
    assert _wait_code(pid) == 0
