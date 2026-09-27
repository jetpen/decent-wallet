import io
import json
import warnings
from collections.abc import Iterable
from pathlib import Path

import pytest

import decent_wallet.desktop_cli as desktop_cli
from decent_wallet import UnsupportedFormat, Wallet


TEST_PASSPHRASE = "correct horse battery staple"
LEGACY_V1_FIXTURE = Path(__file__).parent / "fixtures" / "wallet-v1-pending-rotation.dw"


class _TerminalInput(io.StringIO):
    def isatty(self) -> bool:
        return True


def _enable_password_prompts(
    monkeypatch: pytest.MonkeyPatch, passwords: Iterable[str]
) -> None:
    prompts = iter(passwords)
    monkeypatch.setattr(desktop_cli.sys, "stdin", _TerminalInput())
    monkeypatch.setattr(
        desktop_cli.getpass,
        "getpass",
        lambda _prompt="Password: ", stream=None: next(prompts),
    )


def test_create_export_and_import_preserve_exact_container_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "source.dw"
    exported = tmp_path / "backup.dw"
    restored = tmp_path / "restored.dw"

    _enable_password_prompts(monkeypatch, [TEST_PASSPHRASE, TEST_PASSPHRASE])
    assert desktop_cli.main(["create", str(source)]) == 0
    created_output = capsys.readouterr()
    assert "created" in created_output.out.lower()
    assert TEST_PASSPHRASE not in created_output.out + created_output.err
    assert source.stat().st_mode & 0o777 == 0o600
    created_wallet = Wallet.open(source, TEST_PASSPHRASE)
    pending_public_key = created_wallet.prepare_signing_key_rotation()
    created_wallet.lock()
    original = source.read_bytes()
    assert json.loads(original)["version"] == 2

    _enable_password_prompts(monkeypatch, [TEST_PASSPHRASE])
    assert desktop_cli.main(["export", str(source), str(exported)]) == 0
    assert exported.read_bytes() == original
    assert exported.stat().st_mode & 0o777 == 0o600

    _enable_password_prompts(monkeypatch, [TEST_PASSPHRASE])
    assert desktop_cli.main(["import", str(restored), str(exported)]) == 0
    assert restored.read_bytes() == original

    wallet = Wallet.open(restored, TEST_PASSPHRASE)
    assert wallet.pending_signing_public_key == pending_public_key
    wallet.lock()


def test_export_and_import_never_overwrite_existing_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "source.dw"
    backup = tmp_path / "backup.dw"
    restored = tmp_path / "restored.dw"
    Wallet.create_with_generated_key(source, TEST_PASSPHRASE, TEST_PASSPHRASE).lock()
    backup.write_bytes(b"do not overwrite")

    _enable_password_prompts(monkeypatch, [TEST_PASSPHRASE])
    assert desktop_cli.main(["export", str(source), str(backup)]) != 0
    assert backup.read_bytes() == b"do not overwrite"

    _enable_password_prompts(monkeypatch, [TEST_PASSPHRASE])
    assert desktop_cli.main(["import", str(restored), str(source)]) == 0
    before = restored.read_bytes()
    _enable_password_prompts(monkeypatch, [TEST_PASSPHRASE])
    assert desktop_cli.main(["import", str(restored), str(source)]) != 0
    assert restored.read_bytes() == before
    assert "do not overwrite" not in capsys.readouterr().err


def test_migrate_is_explicit_and_preserves_v1_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wallet_path = tmp_path / "legacy.dw"
    original = LEGACY_V1_FIXTURE.read_bytes()
    wallet_path.write_bytes(original)

    _enable_password_prompts(monkeypatch, [TEST_PASSPHRASE])
    assert desktop_cli.main(["migrate", str(wallet_path)]) == 0
    migrated = wallet_path.read_bytes()
    assert json.loads(migrated)["version"] == 2
    assert migrated != original
    opened = Wallet.open(wallet_path, TEST_PASSPHRASE)
    assert opened.public_key.hex() == (
        "9f8544ce97a2bae6d53c788ca472ca29a58f156ab7cf481f8a6512af86f3c68e"
    )
    opened.lock()


def test_migration_failure_does_not_rewrite_legacy_wallet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wallet_path = tmp_path / "legacy.dw"
    original = LEGACY_V1_FIXTURE.read_bytes()
    wallet_path.write_bytes(original)

    _enable_password_prompts(monkeypatch, ["incorrect but long passphrase"])
    assert desktop_cli.main(["migrate", str(wallet_path)]) != 0
    assert wallet_path.read_bytes() == original
    with pytest.raises(UnsupportedFormat):
        Wallet.open(wallet_path, TEST_PASSPHRASE)


def test_passwords_require_a_tty_and_are_never_echoed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "wallet.dw"
    monkeypatch.setattr(desktop_cli.sys, "stdin", io.StringIO("not-a-tty-secret"))
    monkeypatch.setattr(
        desktop_cli.getpass,
        "getpass",
        lambda *_args, **_kwargs: pytest.fail("password prompt must not fall back"),
    )

    assert desktop_cli.main(["create", str(path)]) != 0
    captured = capsys.readouterr()
    assert not path.exists()
    assert "not-a-tty-secret" not in captured.out + captured.err
    assert "password" in captured.err.lower() or "terminal" in captured.err.lower()


def test_cli_errors_do_not_echo_secret_bearing_exception_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    wallet_path = tmp_path / "wallet.dw"
    monkeypatch.setattr(
        desktop_cli.Wallet,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("do-not-print-this-sensitive-path")
        ),
    )
    _enable_password_prompts(monkeypatch, [TEST_PASSPHRASE])

    backup_path = tmp_path / "backup.dw"
    assert desktop_cli.main(["export", str(wallet_path), str(backup_path)]) != 0
    captured = capsys.readouterr()
    assert "do-not-print-this-sensitive-path" not in captured.out + captured.err


def test_cli_rejects_password_arguments_without_echoing_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate = "synthetic-command-line-value"
    with pytest.raises(SystemExit):
        desktop_cli.main(["create", str(tmp_path / "wallet.dw"), "--password", candidate])
    captured = capsys.readouterr()
    assert candidate not in captured.out + captured.err


def test_getpass_echo_fallback_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "wallet.dw"
    monkeypatch.setattr(desktop_cli.sys, "stdin", _TerminalInput())

    def warn_about_echo(*_args, **_kwargs):
        warnings.warn("echo fallback", desktop_cli.getpass.GetPassWarning)
        return "never-return-this-password"

    monkeypatch.setattr(desktop_cli.getpass, "getpass", warn_about_echo)

    assert desktop_cli.main(["create", str(path)]) != 0
    captured = capsys.readouterr()
    assert not path.exists()
    assert "never-return-this-password" not in captured.out + captured.err
    assert "secure terminal" in captured.err
