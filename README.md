# AES-GCM File Encryptor

A small command line tool that encrypts and decrypts files with a password using AES-256-GCM, so a lost laptop or leaked backup doesn't expose the contents, and any tampering is caught instead of silently accepted.

## How it works
1. **You type a password at a hidden prompt.** It is never accepted as a command line argument, because arguments end up in shell history and are visible to other users through `ps`. When encrypting, you type it twice so a typo doesn't lock you out.
2. **A key is derived from the password with scrypt.** A random 16 byte salt is generated for every file, so the same password gives a different key each time and precomputed password tables are useless. scrypt is deliberately slow and memory hungry (n=2^17, r=8, p=1, about 128 MiB and a quarter of a second). That costs you nothing once, but makes guessing millions of passwords very expensive.
3. **The file is encrypted with AES-256-GCM** using a random 12 byte nonce. GCM is *authenticated* encryption: besides the ciphertext it produces a 16 byte tag that only matches if the key and every byte of the data are correct.
4. **A small header is written before the ciphertext:**

   | Field   | Size     | Purpose                                  |
   |---------|----------|------------------------------------------|
   | magic   | 4 bytes  | `AGCM`, so the tool can reject random files |
   | version | 1 byte   | allows the format to change later        |
   | salt    | 16 bytes | input to scrypt                          |
   | nonce   | 12 bytes | input to AES-GCM                         |

   The header is fed to GCM as *associated data*. It stays readable, but changing even one bit of it (for example the version byte) breaks the tag.
5. **Decryption checks everything before writing anything.** The whole file is decrypted and verified in memory. If the tag doesn't match, the tool prints one error and exits with code 1, and no output file is created. A wrong password and a modified file look identical to GCM, so the message says "wrong password or the file was modified".
6. **Output is written atomically.** Data goes to a temp file in the same folder, which is then renamed into place, so a crash can't leave a half-written file. Existing output files are not overwritten unless you pass `--force`.

### Design choices
- **scrypt parameters are tied to the version byte, not stored in the header.** If they were stored, an attacker could edit a file to claim a weak work factor. Changing them later means bumping the version.
- **AES-GCM from the `cryptography` package** rather than hand-rolled crypto. The library is widely reviewed and uses OpenSSL underneath.
- **Whole file in memory.** This keeps the "verify before writing" rule simple and correct. Streaming GCM safely needs a chunked construction, which is out of scope here.

## Install
    git clone <repo-url>
    cd aes-gcm-file-encryptor
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt

## Usage
Generate a fake sample file (written to `samples/`, which is git-ignored):

    .venv/bin/python scripts/make_sample.py

Encrypt and decrypt it:

    .venv/bin/python main.py encrypt samples/notes.txt samples/notes.txt.enc
    .venv/bin/python main.py decrypt samples/notes.txt.enc samples/notes.out.txt

Overwrite an existing output file:

    .venv/bin/python main.py decrypt --force samples/notes.txt.enc samples/notes.out.txt

Run the scripted demo, which drives the CLI through a pseudo-terminal with a fake password:

    .venv/bin/python scripts/demo.py

## Example output
Real run of `scripts/demo.py` (passwords are typed but not echoed):

    $ python main.py encrypt samples/notes.txt samples/notes.txt.enc
    Password:
    Confirm password:
    Encrypted samples/notes.txt -> samples/notes.txt.enc
    (exit code 0)

    $ python main.py decrypt samples/notes.txt.enc samples/wrong.txt
    Password:
    Error: Decryption failed: wrong password or the file was modified.
    (exit code 1)

    $ python main.py decrypt samples/notes.txt.enc samples/notes.out.txt
    Password:
    Decrypted samples/notes.txt.enc -> samples/notes.out.txt
    (exit code 0)

    Header bytes: 41 47 43 4d 01 93 57 3f 61 93 97 6a 23 b3 13 3b 94 45 9b 10 69 53 10 1c 37 ec f2 12 77 17 d5 b3 9f
    Round trip identical: True
    wrong.txt written: False

The header starts with `41 47 43 4d` ("AGCM") and `01` (version 1), followed by the random salt and nonce.

## Tests
    .venv/bin/python -m pytest

The tests cover:
- round trips: normal data, an empty file, and one with the real scrypt parameters
- wrong password
- modified files: a flipped bit in the version byte, salt, nonce, ciphertext or tag
- truncated files and bad magic values
- CLI behaviour: no output (and no leftover temp file) after a failed decrypt, an existing file left untouched, refusal to overwrite, mismatched passwords, and no `--password` option

Most tests lower scrypt's work factor for speed. One test runs with the real parameters.

## What I learned
- Encryption alone isn't enough. Without authentication, flipped ciphertext bits decrypt to garbage silently. GCM's tag turns tampering into a clean failure.
- Associated data lets you protect a header that has to stay readable, like the salt and nonce.
- A wrong key and modified data are indistinguishable to GCM, and that's fine. The safe response is the same either way.
- "Fail without writing output" needs care: decrypt fully in memory, then write to a temp file and rename it.
- `getpass` reads from the terminal, not stdin, and flushes typed-ahead input. Scripting it needs a pseudo-terminal that waits for each prompt.

## Limitations
- The whole file is loaded into memory, so it isn't suited to multi-gigabyte files.
- The encryption is only as strong as the password. scrypt slows guessing but can't save a weak password.
- The password exists briefly in process memory as a Python string, which can't be reliably wiped.
- File names, sizes (plaintext size = file size − 49 bytes) and timestamps are not hidden.
- `scripts/demo.py` uses `pty`, so it is POSIX only. The tool itself is cross-platform.

## Disclaimer
For educational use on systems you own or have permission to test.
