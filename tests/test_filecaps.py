# SPDX-License-Identifier: 0BSD
"""File capability xattr logic: pack/unpack and get/set through os xattrs."""

import errno
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from posixcaps import Cap, FileCaps, filecaps, get_file_caps, set_file_caps


def test_xattr_name_and_sizes() -> None:
    assert filecaps._XATTR_NAME == "security.capability"
    assert filecaps._XATTR_SIZE_V1 == 12
    assert filecaps._XATTR_SIZE_V2 == 20
    assert filecaps._XATTR_SIZE_V3 == 24


@given(
    effective=st.booleans(),
    permitted=st.frozensets(st.sampled_from(list(Cap))),
    inheritable=st.frozensets(st.sampled_from(list(Cap))),
    rootid=st.integers(0, 0xFFFFFFFF),
)
def test_pack_unpack_roundtrip(
    effective: bool,
    permitted: frozenset[Cap],
    inheritable: frozenset[Cap],
    rootid: int,
) -> None:
    caps = FileCaps(effective, permitted, inheritable, rootid)
    assert filecaps._unpack(filecaps._pack(caps)) == caps


def test_get_file_caps_missing_xattr(tmp_path: Path) -> None:
    target = tmp_path / "plain"
    target.write_bytes(b"#!/bin/sh\nexit 0\n")
    assert get_file_caps(target) is None


def test_get_file_caps_decodes_blob(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    blob = filecaps._pack(
        FileCaps(
            effective=True,
            permitted=frozenset({Cap.CAP_NET_BIND_SERVICE}),
            inheritable=frozenset(),
            rootid=0,
        )
    )
    monkeypatch.setattr(os, "getxattr", lambda path, name: blob)
    caps = get_file_caps(tmp_path / "tool")
    assert caps is not None
    assert caps.effective
    assert caps.permitted == frozenset({Cap.CAP_NET_BIND_SERVICE})


def test_get_file_caps_enodata_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_enodata(path: object, name: str) -> bytes:
        raise OSError(errno.ENODATA, "No data available")

    monkeypatch.setattr(os, "getxattr", raise_enodata)
    assert get_file_caps("whatever") is None


def test_get_file_caps_other_errnos_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_eacces(path: object, name: str) -> bytes:
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(os, "getxattr", raise_eacces)
    with pytest.raises(OSError, match="Permission denied") as excinfo:
        get_file_caps("whatever")
    assert excinfo.value.errno == errno.EACCES


def test_set_file_caps_writes_v3_blob(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = SimpleNamespace(args=None)

    def fake_setxattr(path: object, name: str, value: bytes) -> None:
        calls.args = (path, name, value)

    monkeypatch.setattr(os, "setxattr", fake_setxattr)
    set_file_caps(
        tmp_path / "tool",
        effective=True,
        permitted={Cap.CAP_SYS_ADMIN, Cap.CAP_PERFMON},
        inheritable={Cap.CAP_CHOWN},
        rootid=7,
    )
    _path, name, value = calls.args
    assert name == "security.capability"
    caps = filecaps._unpack(value)
    assert caps == FileCaps(
        effective=True,
        permitted=frozenset({Cap.CAP_SYS_ADMIN, Cap.CAP_PERFMON}),
        inheritable=frozenset({Cap.CAP_CHOWN}),
        rootid=7,
    )
    assert len(value) == 24


def test_set_file_caps_surfaces_errno(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def raise_eperm(path: object, name: str, value: bytes) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "setxattr", raise_eperm)
    with pytest.raises(OSError, match="Operation not permitted") as excinfo:
        set_file_caps(tmp_path / "tool", permitted={Cap.CAP_CHOWN})
    assert excinfo.value.errno == errno.EPERM
