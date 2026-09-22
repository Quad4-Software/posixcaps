# posixcaps

[![CI](https://github.com/Quad4-Software/posixcaps/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/posixcaps/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/posixcaps/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/posixcaps/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/posixcaps/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/posixcaps)
[![PyPI](https://img.shields.io/pypi/v/posixcaps.svg)](https://pypi.org/project/posixcaps/)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

Dependency-free Python bindings for Linux capabilities. Read and modify
the effective, permitted, inheritable, bounding and ambient capability
sets of threads, and the file capabilities stored in the
`security.capability` extended attribute. Everything goes through
capget(2)/capset(2), prctl(2) and getxattr(2)/setxattr(2) via ctypes.
There are no runtime dependencies.

Requires Python 3.10+ and Linux.

## Install

    pip install posixcaps

## Usage

```python
from posixcaps import Cap, Capabilities, ambient, bounding

caps = Capabilities.for_self()
print(caps.effective)  # frozenset of Cap
print(caps.permitted)
print(caps.inheritable)

caps.set(effective=caps.permitted)  # capset(2), kernel rules enforced

print(bounding())  # prctl(PR_CAPBSET_READ) per capability
print(ambient())  # prctl(PR_CAP_AMBIENT_IS_SET) per capability
```

File capabilities live in the `security.capability` xattr:

```python
from posixcaps import Cap, get_file_caps, set_file_caps

set_file_caps(  # requires CAP_SETFCAP
    "/usr/local/bin/mydaemon",
    effective=True,
    permitted={Cap.CAP_NET_BIND_SERVICE},
)
print(get_file_caps("/usr/local/bin/mydaemon"))
```

`posixcaps.cap_last_cap()` reports the highest capability index the
running kernel supports, from /proc/sys/kernel/cap_last_cap.

Thread securebits (prctl(2)) are exposed as a flag mask:

```python
from posixcaps import SecureBits, securebits, set_securebits

print(securebits())  # current SECBIT_* mask
set_securebits(  # classic bits need CAP_SETPCAP, locks are one-way
    securebits() | SecureBits.NOROOT | SecureBits.NOROOT_LOCKED
)
```

## Documentation

- API: docstrings in `src/posixcaps/`, mostly `caps.py` and `filecaps.py`
- capabilities(7): https://man7.org/linux/man-pages/man7/capabilities.7.html
- capget(2): https://man7.org/linux/man-pages/man2/capget.2.html

License: 0BSD.
