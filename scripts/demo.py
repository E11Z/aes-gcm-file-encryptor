"""End-to-end demo: drive main.py through a pseudo-terminal with a fake password.

getpass reads from the terminal, not stdin, so a pty is the only way to feed
it the way a human would. Run scripts/make_sample.py first. POSIX only.
"""

from __future__ import annotations

import os
import pty
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "samples"
DEMO_PASSWORD = "demo-pass"  # fake, only ever used on generated sample data


def run(argv: list[str], answers: list[str]) -> int:
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(REPO)
        os.execv(sys.executable, [sys.executable, "main.py", *argv])
    out = b""
    for sent, answer in enumerate(answers):
        # Wait for a *new* prompt before answering: getpass flushes pending
        # terminal input, so typing ahead would be silently discarded.
        while out.count(b"assword: ") <= sent:
            out += os.read(fd, 1024)
        os.write(fd, answer.encode() + b"\n")
    try:
        while chunk := os.read(fd, 1024):
            out += chunk
    except OSError:  # raised on Linux when the child closes the pty
        pass
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    print("$ python main.py " + " ".join(argv))
    print(out.decode().replace("\r", "").strip())
    print(f"(exit code {code})\n")
    return code


def main() -> int:
    plain = SAMPLES / "notes.txt"
    if not plain.exists():
        print("Run scripts/make_sample.py first.", file=sys.stderr)
        return 1
    for name in ("notes.txt.enc", "notes.out.txt", "wrong.txt"):
        (SAMPLES / name).unlink(missing_ok=True)

    run(["encrypt", "samples/notes.txt", "samples/notes.txt.enc"],
        [DEMO_PASSWORD, DEMO_PASSWORD])
    run(["decrypt", "samples/notes.txt.enc", "samples/wrong.txt"], ["not-it"])
    run(["decrypt", "samples/notes.txt.enc", "samples/notes.out.txt"], [DEMO_PASSWORD])

    blob = (SAMPLES / "notes.txt.enc").read_bytes()
    print("Header bytes:", blob[:33].hex(" "))
    print("Round trip identical:", plain.read_bytes() == (SAMPLES / "notes.out.txt").read_bytes())
    print("wrong.txt written:", (SAMPLES / "wrong.txt").exists())
    return 0


if __name__ == "__main__":
    sys.exit(main())
