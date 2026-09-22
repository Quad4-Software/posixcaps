# SPDX-License-Identifier: 0BSD

import sys

import pytest

from posixcaps import Cap, Capabilities


def _in_effective(cap: Cap) -> bool:
    try:
        return cap in Capabilities.for_self().effective
    except OSError:
        return False


requires_linux = pytest.mark.skipif(sys.platform != "linux", reason="Linux only")

requires_setpcap = pytest.mark.skipif(
    not _in_effective(Cap.CAP_SETPCAP),
    reason="requires CAP_SETPCAP in the effective set",
)

requires_setfcap = pytest.mark.skipif(
    not _in_effective(Cap.CAP_SETFCAP),
    reason="requires CAP_SETFCAP in the effective set",
)
