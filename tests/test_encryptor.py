from __future__ import annotations

from pathlib import Path

import pytest

import encryptor
import main
from encryptor import HEADER_SIZE, MAGIC, DecryptionError, decrypt_bytes, encrypt_bytes
from scripts.make_sample import make_text

PASSWORD = b"correct horse battery staple"


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    # The real work factor is slow on purpose; tests only need correctness.
    monkeypatch.setattr(encryptor, "SCRYPT_N", 2**10)


@pytest.fixture
def sample() -> bytes:
    return make_text(lines=20, seed=1).encode("utf-8")


def fake_getpass(monkeypatch: pytest.MonkeyPatch, password: str) -> None:
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt="": password)


# --- core ---------------------------------------------------------------


def test_round_trip(sample: bytes) -> None:
    assert decrypt_bytes(encrypt_bytes(sample, PASSWORD), PASSWORD) == sample


def test_round_trip_with_real_scrypt_params(
    monkeypatch: pytest.MonkeyPatch, sample: bytes
) -> None:
    monkeypatch.undo()
    assert encryptor.SCRYPT_N == 2**17
    assert decrypt_bytes(encrypt_bytes(sample, PASSWORD), PASSWORD) == sample


def test_round_trip_empty_file() -> None:
    assert decrypt_bytes(encrypt_bytes(b"", PASSWORD), PASSWORD) == b""


def test_header_layout(sample: bytes) -> None:
    blob = encrypt_bytes(sample, PASSWORD)
    assert blob[:4] == MAGIC
    assert blob[4] == encryptor.VERSION
    assert len(blob) == HEADER_SIZE + len(sample) + encryptor.TAG_SIZE


def test_salt_and_nonce_are_random(sample: bytes) -> None:
    a = encrypt_bytes(sample, PASSWORD)
    b = encrypt_bytes(sample, PASSWORD)
    assert a[:HEADER_SIZE] != b[:HEADER_SIZE]
    assert a[HEADER_SIZE:] != b[HEADER_SIZE:]


def test_wrong_password(sample: bytes) -> None:
    blob = encrypt_bytes(sample, PASSWORD)
    with pytest.raises(DecryptionError, match="wrong password"):
        decrypt_bytes(blob, b"not the password")


@pytest.mark.parametrize(
    "offset",
    [
        4,  # version byte (protected as associated data)
        5,  # first salt byte
        HEADER_SIZE - 1,  # last nonce byte
        HEADER_SIZE,  # first ciphertext byte
        -1,  # last tag byte
    ],
)
def test_modified_file(sample: bytes, offset: int) -> None:
    blob = bytearray(encrypt_bytes(sample, PASSWORD))
    blob[offset] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_bytes(bytes(blob), PASSWORD)


def test_truncated_file(sample: bytes) -> None:
    blob = encrypt_bytes(sample, PASSWORD)
    with pytest.raises(DecryptionError):
        decrypt_bytes(blob[:-1], PASSWORD)
    with pytest.raises(DecryptionError, match="too short"):
        decrypt_bytes(blob[:10], PASSWORD)


def test_bad_magic(sample: bytes) -> None:
    blob = b"XXXX" + encrypt_bytes(sample, PASSWORD)[4:]
    with pytest.raises(DecryptionError, match="magic"):
        decrypt_bytes(blob, PASSWORD)


def test_empty_password_rejected(sample: bytes) -> None:
    with pytest.raises(ValueError):
        encrypt_bytes(sample, b"")


# --- CLI ----------------------------------------------------------------


def test_cli_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample: bytes
) -> None:
    src, enc, dec = tmp_path / "in.txt", tmp_path / "in.enc", tmp_path / "out.txt"
    src.write_bytes(sample)
    fake_getpass(monkeypatch, "pw-for-tests")
    assert main.main(["encrypt", str(src), str(enc)]) == 0
    assert main.main(["decrypt", str(enc), str(dec)]) == 0
    assert dec.read_bytes() == sample


def test_cli_wrong_password_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample: bytes
) -> None:
    enc, out = tmp_path / "in.enc", tmp_path / "out.txt"
    enc.write_bytes(encrypt_bytes(sample, PASSWORD))
    fake_getpass(monkeypatch, "wrong")
    assert main.main(["decrypt", str(enc), str(out)]) == 1
    assert not out.exists()
    # No leftover temp files either.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in.enc"]


def test_cli_modified_file_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample: bytes
) -> None:
    blob = bytearray(encrypt_bytes(sample, PASSWORD))
    blob[HEADER_SIZE + 3] ^= 0xFF
    enc, out = tmp_path / "in.enc", tmp_path / "out.txt"
    enc.write_bytes(bytes(blob))
    fake_getpass(monkeypatch, PASSWORD.decode())
    assert main.main(["decrypt", str(enc), str(out)]) == 1
    assert not out.exists()


def test_cli_failed_decrypt_keeps_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample: bytes
) -> None:
    enc, out = tmp_path / "in.enc", tmp_path / "out.txt"
    enc.write_bytes(encrypt_bytes(sample, PASSWORD))
    out.write_bytes(b"keep me")
    fake_getpass(monkeypatch, "wrong")
    assert main.main(["decrypt", "--force", str(enc), str(out)]) == 1
    assert out.read_bytes() == b"keep me"


def test_cli_refuses_to_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample: bytes
) -> None:
    src, enc = tmp_path / "in.txt", tmp_path / "in.enc"
    src.write_bytes(sample)
    enc.write_bytes(b"existing")
    fake_getpass(monkeypatch, "pw")
    assert main.main(["encrypt", str(src), str(enc)]) == 1
    assert enc.read_bytes() == b"existing"


def test_cli_password_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sample: bytes
) -> None:
    src, enc = tmp_path / "in.txt", tmp_path / "in.enc"
    src.write_bytes(sample)
    answers = iter(["first", "second"])
    monkeypatch.setattr(main.getpass, "getpass", lambda prompt="": next(answers))
    assert main.main(["encrypt", str(src), str(enc)]) == 1
    assert not enc.exists()


def test_cli_has_no_password_argument() -> None:
    with pytest.raises(SystemExit):
        main.main(["encrypt", "a", "b", "--password", "secret"])
