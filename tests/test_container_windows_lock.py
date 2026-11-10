import sys
import types
from pathlib import Path

import pytest

import decent_wallet.container as container_module


class _MsvcrtLocking:
    LK_NBLCK = 1
    LK_UNLCK = 2

    def __init__(self):
        self.held = set()
        self.calls = []
        self.busy = False
        self.error = None

    def locking(self, descriptor, mode, count):
        import os

        self.calls.append((descriptor, mode, count))
        identity = (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
        if mode == self.LK_NBLCK:
            if self.error is not None:
                raise self.error
            if self.busy or identity in self.held:
                import errno
                raise OSError(errno.EACCES, "already locked")
            self.held.add(identity)
        else:
            self.held.discard(identity)


def _windows_locking(monkeypatch):
    locking = _MsvcrtLocking()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(container_module, "_windows_owned_by_current_user", lambda _path: True)
    monkeypatch.setattr(container_module, "_windows_acl_is_safe", lambda _path: True)
    monkeypatch.setitem(sys.modules, "msvcrt", types.SimpleNamespace(
        LK_NBLCK=locking.LK_NBLCK,
        LK_UNLCK=locking.LK_UNLCK,
        get_osfhandle=lambda descriptor: descriptor,
        locking=locking.locking,
    ))
    return locking


def test_windows_wallet_guard_uses_stable_sidecar_and_releases_it(tmp_path, monkeypatch):
    locking = _windows_locking(monkeypatch)
    wallet_path = tmp_path / "wallet.dw"

    with container_module._container_guard(wallet_path):
        sidecar = tmp_path / ".wallet.dw.lock"
        assert sidecar.is_file()
        assert sidecar.stat().st_size == 0
        assert list(locking.held)

    assert locking.held == set()
    assert len(locking.calls) == 2
    assert locking.calls[0][1:] == (locking.LK_NBLCK, 1)
    assert locking.calls[1][1:] == (locking.LK_UNLCK, 1)


def test_windows_wallet_guard_serializes_independently_opened_lock_descriptors(tmp_path, monkeypatch):
    from decent_wallet import StorageFailure

    locking = _windows_locking(monkeypatch)
    ticks = iter((0.0, 0.0, 5.1))
    monkeypatch.setattr(container_module.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(container_module.time, "sleep", lambda _delay: None)
    path = tmp_path / "wallet.dw"

    with container_module._container_guard(path):
        with pytest.raises(StorageFailure):
            with container_module._container_guard(path):
                pytest.fail("two independently opened descriptors must not enter together")
        assert len(locking.held) == 1

    assert locking.held == set()


def test_windows_wallet_guard_times_out_on_contention_and_closes_descriptor(tmp_path, monkeypatch):
    from decent_wallet import StorageFailure

    locking = _windows_locking(monkeypatch)
    locking.busy = True
    ticks = iter((0.0, 5.1))
    monkeypatch.setattr(container_module.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(container_module.time, "sleep", lambda _delay: None)

    with pytest.raises(StorageFailure):
        with container_module._container_guard(tmp_path / "wallet.dw"):
            pytest.fail("a contended wallet lock must not be entered")

    assert locking.held == set()
    assert [call[1] for call in locking.calls] == [locking.LK_NBLCK]


def test_windows_wallet_guard_fails_closed_on_lock_error_and_cleans_up(tmp_path, monkeypatch):
    import errno

    from decent_wallet import StorageFailure

    locking = _windows_locking(monkeypatch)
    locking.error = OSError(errno.EIO, "lock backend unavailable")

    with pytest.raises(StorageFailure):
        with container_module._container_guard(tmp_path / "wallet.dw"):
            pytest.fail("an unavailable lock primitive must fail closed")

    assert locking.held == set()


def test_windows_wallet_guard_unlocks_when_operation_raises(tmp_path, monkeypatch):
    locking = _windows_locking(monkeypatch)

    with pytest.raises(RuntimeError, match="operation failed"):
        with container_module._container_guard(tmp_path / "wallet.dw"):
            raise RuntimeError("operation failed")

    assert locking.held == set()


def test_windows_wallet_guard_rejects_directory_not_owned_by_current_user(tmp_path, monkeypatch):
    from decent_wallet import StorageFailure

    _windows_locking(monkeypatch)
    monkeypatch.setattr(container_module, "_windows_owned_by_current_user", lambda _path: False)

    with pytest.raises(StorageFailure):
        with container_module._container_guard(tmp_path / "wallet.dw"):
            pytest.fail("unowned wallet directory must be rejected")


@pytest.mark.parametrize("dangerous_ace", ["foreign-write", "delete-child", "delete", "write-dac"])
def test_windows_wallet_guard_rejects_foreign_directory_acl_rights(
    tmp_path, monkeypatch, dangerous_ace
):
    from decent_wallet import StorageFailure

    _windows_locking(monkeypatch)
    checked = []

    # This adapter stands in for the Win32 ACL query/parser. Ownership alone is
    # deliberately insufficient: the current-user-owned parent has a foreign
    # principal with a lock-replacement capability.
    def acl_is_safe(path):
        checked.append(Path(path))
        return False

    monkeypatch.setattr(container_module, "_windows_acl_is_safe", acl_is_safe, raising=False)

    with pytest.raises(StorageFailure):
        with container_module._container_guard(tmp_path / "wallet.dw"):
            pytest.fail(f"foreign {dangerous_ace} ACE must block the lock")

    assert checked == [tmp_path]


def test_windows_wallet_guard_checks_directory_and_open_sidecar_acl(tmp_path, monkeypatch):
    locking = _windows_locking(monkeypatch)
    checked = []

    def acl_is_safe(path):
        checked.append(path)
        return True

    monkeypatch.setattr(container_module, "_windows_acl_is_safe", acl_is_safe, raising=False)

    with container_module._container_guard(tmp_path / "wallet.dw"):
        assert len(locking.held) == 1

    assert checked == [tmp_path, next(p for p in checked if isinstance(p, int))]


@pytest.mark.parametrize(
    ("ace_type", "sid", "expected"),
    [
        ("allow", "owner", True),
        ("deny", "owner", True),
        ("allow", "current-user", True),
        ("allow", "SYSTEM", True),
        ("allow", "Administrators", True),
        ("allow", "foreign", False),
        ("allow", "foreign-write", False),
        ("allow", "foreign-delete-child", False),
        ("allow", "foreign-delete", False),
        ("allow", "foreign-write-dac", False),
        ("unknown", "owner", False),
        ("object-allow", "owner", False),
        ("callback-allow", "owner", False),
    ],
)
def test_windows_acl_production_predicate_classifies_synthetic_aces(ace_type, sid, expected):
    predicate = getattr(container_module, "_windows_acl_entries_are_safe", None)
    assert callable(predicate), "ACL ACE decisions must use the production pure predicate"

    assert predicate([(ace_type, sid)], {"owner", "current-user", "SYSTEM", "Administrators"}) is expected


@pytest.mark.parametrize(
    ("aces", "trusted_sids", "dacl_present", "query_succeeded"),
    [
        ([], {"owner"}, False, True),
        ([], {"owner"}, True, False),
        ([("allow", "owner")], set(), True, True),
    ],
)
def test_windows_acl_production_predicate_fails_closed(
    aces, trusted_sids, dacl_present, query_succeeded
):
    predicate = getattr(container_module, "_windows_acl_entries_are_safe", None)
    assert callable(predicate), "ACL query failures and null DACLs need a production predicate"

    assert not predicate(
        aces, trusted_sids, dacl_present=dacl_present, query_succeeded=query_succeeded
    )


def test_windows_wallet_guard_rejects_sidecar_acl_that_changes_after_parent_check(
    tmp_path, monkeypatch
):
    from decent_wallet import StorageFailure

    _windows_locking(monkeypatch)
    checked = []

    def acl_is_safe(path):
        checked.append(path)
        return len(checked) == 1  # safe parent; unsafe descriptor-backed sidecar

    monkeypatch.setattr(container_module, "_windows_acl_is_safe", acl_is_safe)

    with pytest.raises(StorageFailure):
        with container_module._container_guard(tmp_path / "wallet.dw"):
            pytest.fail("unsafe sidecar ACL must reject before yielding the guard")

    assert checked[0] == tmp_path
    assert isinstance(checked[1], int)


def test_windows_container_path_aliases_share_one_lock_identity(tmp_path):
    directory = tmp_path / "wallets"
    directory.mkdir()
    try:
        (tmp_path / "alias").symlink_to(directory, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks unavailable: {error}")

    canonical = container_module._container_path(directory / "wallet.dw")
    alias = container_module._container_path(tmp_path / "alias" / "wallet.dw")

    assert canonical == alias
