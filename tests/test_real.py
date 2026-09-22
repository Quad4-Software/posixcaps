# SPDX-License-Identifier: 0BSD
"""Tests against the running kernel.

Reads like capget(2), PR_CAPBSET_READ and PR_CAP_AMBIENT_IS_SET need no
privilege. Mutating tests run in a forked child so the test process
keeps its own sets, and are skipped when the required capability is
missing from the caller's effective set.
"""

import errno
import os
import re
from pathlib import Path

import pytest

from posixcaps import (
    Cap,
    Capabilities,
    CapError,
    ambient,
    ambient_clear,
    ambient_raise,
    ambient_reset,
    bounding,
    cap_last_cap,
    drop_bounding,
    get,
    get_file_caps,
    set_file_caps,
)

from .conftest import requires_linux, requires_setfcap, requires_setpcap


def _proc_mask(name: str) -> int:
    match = re.search(
        rf"^{name}:\s*([0-9a-fA-F]+)",
        Path("/proc/self/status").read_text(),
        re.MULTILINE,
    )
    assert match is not None
    return int(match.group(1), 16)


def _mask_set(mask: int) -> frozenset[Cap]:
    return frozenset(cap for cap in Cap if mask & (1 << cap.value))


@requires_linux
def test_for_self_matches_proc_status() -> None:
    caps = Capabilities.for_self()
    assert caps.effective == _mask_set(_proc_mask("CapEff"))
    assert caps.permitted == _mask_set(_proc_mask("CapPrm"))
    assert caps.inheritable == _mask_set(_proc_mask("CapInh"))
    assert caps.effective <= caps.permitted  # kernel invariant
    assert caps.pid == 0


@requires_linux
def test_for_pid_self_equals_for_self() -> None:
    by_pid = Capabilities.for_pid(os.getpid())
    direct = get()
    assert (by_pid.effective, by_pid.permitted, by_pid.inheritable) == (
        direct.effective,
        direct.permitted,
        direct.inheritable,
    )
    assert by_pid.pid == os.getpid()


@requires_linux
def test_unknown_pid_raises_esrch() -> None:
    with pytest.raises(CapError) as excinfo:
        Capabilities.for_pid(2**30)
    assert excinfo.value.errno == errno.ESRCH


@requires_linux
def test_cap_last_cap_matches_proc() -> None:
    proc_value = int(
        Path("/proc/sys/kernel/cap_last_cap").read_text(encoding="ascii").strip()
    )
    assert cap_last_cap() == proc_value
    assert cap_last_cap() >= int(Cap.CAP_AUDIT_READ)


@requires_linux
def test_bounding_matches_proc_status() -> None:
    assert bounding() == _mask_set(_proc_mask("CapBnd"))


@requires_linux
def test_ambient_matches_proc_status() -> None:
    assert ambient() == _mask_set(_proc_mask("CapAmb"))
    caps = Capabilities.for_self()
    assert ambient() <= caps.permitted & caps.inheritable  # kernel invariant


@requires_linux
def test_ambient_reset_is_unprivileged() -> None:
    ambient_reset()
    assert ambient() == frozenset()


@requires_linux
@requires_setpcap
def test_drop_bounding_in_child() -> None:
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            bnd = bounding()
            if not bnd:
                os._exit(3)
            target = min(bnd, key=int)
            drop_bounding(target)
            if target in bounding():
                code = 1
        except OSError:
            code = 2
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code == 3:
        pytest.skip("bounding set is empty")
    assert code == 0


@requires_linux
@requires_setpcap
def test_ambient_roundtrip_in_child() -> None:
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            caps = Capabilities.for_self()
            candidates = sorted(caps.permitted & bounding(), key=int)
            if not candidates:
                os._exit(3)
            target = candidates[0]
            caps.set(inheritable=caps.inheritable | {target})
            ambient_raise(target)
            if target not in ambient():
                code = 1
            else:
                ambient_clear(target)
                if target in ambient():
                    code = 2
            ambient_reset()
        except OSError:
            code = 4
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code == 3:
        pytest.skip("no candidate capability in permitted and bounding")
    assert code == 0


@requires_linux
@requires_setfcap
def test_file_caps_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "tool"
    target.write_bytes(b"#!/bin/sh\nexit 0\n")
    try:
        set_file_caps(
            target,
            effective=True,
            permitted={Cap.CAP_NET_BIND_SERVICE, Cap.CAP_SETFCAP},
            inheritable={Cap.CAP_NET_RAW},
        )
    except OSError as exc:
        pytest.skip(f"filesystem cannot store capability xattrs: {exc}")
    caps = get_file_caps(target)
    assert caps is not None
    assert caps.effective
    assert caps.permitted == frozenset({Cap.CAP_NET_BIND_SERVICE, Cap.CAP_SETFCAP})
    assert caps.inheritable == frozenset({Cap.CAP_NET_RAW})
    os.removexattr(target, "security.capability")
    assert get_file_caps(target) is None
