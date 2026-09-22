# SPDX-License-Identifier: 0BSD

import posixcaps


def test_all_exports_resolve() -> None:
    for name in posixcaps.__all__:
        assert getattr(posixcaps, name) is not None, name


def test_version_is_exposed() -> None:
    parts = posixcaps.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
