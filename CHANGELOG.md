# Changelog

## [Unreleased]

## 0.1.0 - 2026-09-22

Initial release.

- Cap enum covering all 41 capabilities (CAP_CHOWN through
  CAP_CHECKPOINT_RESTORE) from linux/capability.h.
- Capabilities snapshots of the effective, permitted and inheritable
  sets via capget(2) (_LINUX_CAPABILITY_VERSION_3), written back with
  capset(2) through Capabilities.set().
- Bounding set operations: bounding() and drop_bounding() via
  prctl(PR_CAPBSET_READ/PR_CAPBSET_DROP).
- Ambient set operations: ambient(), ambient_raise(), ambient_clear()
  and ambient_reset() via prctl(PR_CAP_AMBIENT_*).
- File capabilities: get_file_caps() and set_file_caps() for the
  security.capability xattr, reading v1/v2/v3 vfs_cap_data layouts and
  writing the v3 vfs_ns_cap_data layout with rootid.
- cap_last_cap() discovery through /proc/sys/kernel/cap_last_cap.
- Typed errors: CapError and UnsupportedError carry the kernel errno.
