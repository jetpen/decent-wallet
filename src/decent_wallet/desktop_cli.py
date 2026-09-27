"""Minimal, non-secret desktop interface for portable wallet containers."""

from __future__ import annotations

import argparse
import getpass
import stat
import sys
import warnings
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NoReturn

from . import (
    InvalidContainer,
    PasswordPolicyError,
    StorageFailure,
    StorageOutcomeUnknown,
    UnlockFailed,
    UnsupportedFormat,
    Wallet,
    WalletError,
)
from .container import _MAX_CONTAINER_BYTES, _atomic_write


class _CliInputError(Exception):
    """A safe, user-facing CLI error with no untrusted values."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        self.print_usage(sys.stderr)
        self.exit(2, "invalid arguments\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="decent-wallet",
        description="Manage encrypted wallet containers without exposing secrets.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="create a new v2 signing wallet")
    create.add_argument("wallet", metavar="WALLET_PATH")

    import_command = commands.add_parser(
        "import", help="authenticate and import an encrypted container"
    )
    import_command.add_argument("wallet", metavar="WALLET_PATH")
    import_command.add_argument("backup", metavar="BACKUP_PATH")

    export = commands.add_parser(
        "export", help="export exact encrypted bytes to a new file"
    )
    export.add_argument("wallet", metavar="WALLET_PATH")
    export.add_argument("backup", metavar="BACKUP_PATH")

    migrate = commands.add_parser(
        "migrate", help="explicitly migrate a v1 wallet container to v2"
    )
    migrate.add_argument("wallet", metavar="WALLET_PATH")
    return parser


def _read_password(prompt: str) -> str:
    if not sys.stdin.isatty():
        raise _CliInputError("password input requires an interactive terminal")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt, stream=sys.stderr)
    except (EOFError, OSError, getpass.GetPassWarning):
        raise _CliInputError("password input requires a secure terminal") from None


def _read_backup(path: Path) -> bytes:
    try:
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_CONTAINER_BYTES
        ):
            raise _CliInputError("backup is not a supported regular file")
        with path.open("rb") as handle:
            data = handle.read(_MAX_CONTAINER_BYTES + 1)
    except _CliInputError:
        raise
    except OSError:
        raise _CliInputError("backup could not be read") from None
    if len(data) > _MAX_CONTAINER_BYTES:
        raise _CliInputError("backup exceeds the supported size")
    return data


def _with_locked_session(
    wallet: Wallet,
    message: str,
    action: Callable[[], None] | None = None,
) -> None:
    try:
        if action is not None:
            action()
        print(message)
    finally:
        wallet.lock()


def _run_create(wallet_path: Path) -> None:
    password = _read_password("New wallet password: ")
    confirmation = _read_password("Confirm wallet password: ")
    wallet = Wallet.create_with_generated_key(wallet_path, password, confirmation)
    _with_locked_session(wallet, "wallet created")


def _run_import(wallet_path: Path, backup_path: Path) -> None:
    backup = _read_backup(backup_path)
    password = _read_password("Wallet password: ")
    wallet = Wallet.import_container(wallet_path, backup, password)
    _with_locked_session(wallet, "wallet imported")


def _run_export(wallet_path: Path, backup_path: Path) -> None:
    password = _read_password("Wallet password: ")
    wallet = Wallet.open(wallet_path, password)

    def write_export() -> None:
        _atomic_write(backup_path, wallet.export_container(), replace=False)

    _with_locked_session(wallet, "encrypted backup exported", write_export)


def _run_migrate(wallet_path: Path) -> None:
    password = _read_password("Wallet password: ")
    wallet = Wallet.migrate_container(wallet_path, password)
    _with_locked_session(wallet, "wallet migrated to v2")


def _report_error(error: Exception) -> int:
    if isinstance(error, _CliInputError):
        message = error.message
    elif isinstance(error, UnlockFailed):
        message = "wallet unlock failed"
    elif isinstance(error, UnsupportedFormat):
        message = "unsupported wallet-container format"
    elif isinstance(error, InvalidContainer):
        message = "invalid wallet container"
    elif isinstance(error, PasswordPolicyError):
        message = "password rejected by wallet policy"
    elif isinstance(error, StorageOutcomeUnknown):
        message = "wallet storage outcome is unknown; stop and inspect before continuing"
    elif isinstance(error, StorageFailure):
        message = "wallet storage operation failed"
    elif isinstance(error, WalletError):
        message = "wallet operation failed"
    else:
        message = "desktop wallet operation failed"
    print(message, file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run the desktop CLI; passwords are accepted only from a secure TTY."""
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "create":
            _run_create(Path(args.wallet))
        elif args.command == "import":
            _run_import(Path(args.wallet), Path(args.backup))
        elif args.command == "export":
            _run_export(Path(args.wallet), Path(args.backup))
        elif args.command == "migrate":
            _run_migrate(Path(args.wallet))
        else:
            raise _CliInputError("invalid command")
    except Exception as error:
        return _report_error(error)
    return 0
