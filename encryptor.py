"""Core AES-256-GCM file encryption with scrypt password-based key derivation.

File format (version 1):

    magic   4 bytes   b"AGCM"
    version 1 byte    0x01
    salt    16 bytes  random, input to scrypt
    nonce   12 bytes  random, input to AES-GCM
    body    N bytes   ciphertext followed by the 16 byte GCM tag
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AGCM"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16

# Params are tied to the version byte rather than stored per file, so an
# attacker cannot downgrade the work factor by editing the header.
# n=2**17 costs ~128 MiB and a fraction of a second: cheap for one user,
# expensive for someone guessing millions of passwords.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

_HEADER_FORMAT = f">4sB{SALT_SIZE}s{NONCE_SIZE}s"
HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)


class DecryptionError(Exception):
    """Raised when a file cannot be decrypted. The message is safe to show."""


@dataclass(frozen=True)
class Header:
    version: int
    salt: bytes
    nonce: bytes

    def pack(self) -> bytes:
        return struct.pack(_HEADER_FORMAT, MAGIC, self.version, self.salt, self.nonce)


def parse_header(blob: bytes) -> Header:
    if len(blob) < HEADER_SIZE + TAG_SIZE:
        raise DecryptionError("File is too short to be an encrypted file.")
    magic, version, salt, nonce = struct.unpack(_HEADER_FORMAT, blob[:HEADER_SIZE])
    if magic != MAGIC:
        raise DecryptionError("Not an encrypted file (bad magic value).")
    if version != VERSION:
        raise DecryptionError(f"Unsupported file version {version}.")
    return Header(version=version, salt=salt, nonce=nonce)


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password)


def encrypt_bytes(plaintext: bytes, password: bytes) -> bytes:
    if not password:
        raise ValueError("Password must not be empty.")
    # Fresh salt per file means the same password gives a different key
    # every time, so precomputed tables are useless.
    header = Header(VERSION, os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE))
    header_bytes = header.pack()
    key = derive_key(password, header.salt)
    # Header is passed as associated data so any edit to it (e.g. the
    # version byte) breaks the tag, not just edits to the ciphertext.
    body = AESGCM(key).encrypt(header.nonce, plaintext, header_bytes)
    return header_bytes + body


def decrypt_bytes(blob: bytes, password: bytes) -> bytes:
    header = parse_header(blob)
    key = derive_key(password, header.salt)
    try:
        return AESGCM(key).decrypt(header.nonce, blob[HEADER_SIZE:], blob[:HEADER_SIZE])
    except InvalidTag:
        # GCM cannot tell a wrong key from modified data, and saying which
        # would not help a legitimate user anyway.
        raise DecryptionError(
            "Decryption failed: wrong password or the file was modified."
        ) from None
