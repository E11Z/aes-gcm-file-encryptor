"""Command line interface: encrypt or decrypt a file with a password."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import tempfile
from pathlib import Path

from encryptor import DecryptionError, decrypt_bytes, encrypt_bytes


def build_parser() -> argparse.ArgumentParser:
    # Deliberately no --password option: arguments end up in shell history
    # and are visible to other users via `ps`.
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt files with AES-256-GCM (scrypt-derived key)."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name, help=f"{name} a file")
        p.add_argument("input", type=Path, help="file to read")
        p.add_argument("output", type=Path, help="file to write")
        p.add_argument(
            "-f", "--force", action="store_true", help="overwrite output if it exists"
        )
    return parser


def prompt_password(confirm: bool) -> bytes:
    password = getpass.getpass("Password: ")
    if not password:
        raise ValueError("Password must not be empty.")
    if confirm and getpass.getpass("Confirm password: ") != password:
        raise ValueError("Passwords do not match.")
    return password.encode("utf-8")


def write_atomic(path: Path, data: bytes) -> None:
    # Write to a temp file in the same directory, then rename. A crash or
    # error part way through can never leave a half-written output file.
    fd, tmp = tempfile.mkstemp(dir=path.parent or ".", prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def run(args: argparse.Namespace) -> None:
    if args.output.exists() and not args.force:
        raise ValueError(f"{args.output} already exists (use --force to overwrite).")
    data = args.input.read_bytes()
    if args.command == "encrypt":
        result = encrypt_bytes(data, prompt_password(confirm=True))
    else:
        # Decryption is fully verified in memory before anything is written,
        # so a wrong password or tampered file produces no output at all.
        result = decrypt_bytes(data, prompt_password(confirm=False))
    write_atomic(args.output, result)
    print(f"{args.command.capitalize()}ed {args.input} -> {args.output}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run(args)
    except (DecryptionError, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
