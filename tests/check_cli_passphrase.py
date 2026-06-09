#!/usr/bin/env python3
"""
check_cli_passphrase.py - drive gnomint-cli under a pty so we can feed
passphrases through getpass() (which reads from /dev/tty, not stdin).

Covers commands the other CLI tests can't exercise via stdin:
  - extractcertpkey
  - changepassword

The trick: getpass() writes its "Insert passphrase:" prompt to
/dev/tty AFTER putting the terminal into no-echo mode, and the
no-echo mode also seems to defer the write through the pty master
until input is received. Surrounding `printf` messages DO come
through, so we trigger on the intro text and then blind-write the
password twice (entry + confirm).
"""

import sys

if sys.platform == "win32":
    print("SKIP: pty/termios not available on Windows", file=sys.stderr)
    sys.exit(77)

import errno
import os
import pty
import re
import select
import shutil
import subprocess
import tempfile
import time


CLI = os.environ.get("GNOMINT_CLI", "../src/gnomint-cli")
PASSPHRASE = "the-correct-horse-staple-passphrase"


def spawn_cli(db_path):
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["LC_ALL"] = "C"
        try:
            os.execv(CLI, [CLI, db_path])
        except FileNotFoundError:
            os.write(2, b"SKIP: cli not found\n")
            os._exit(77)
        except OSError as e:
            os.write(2, f"FAIL: exec: {e}\n".encode())
            os._exit(1)
    # Give the child a tick to start producing output before any expect().
    # Without this the first select() can return spuriously before exec
    # has completed inside the child, leaving expect() running its loop
    # over a pty whose buffer is still empty.
    time.sleep(0.3)
    return pid, fd


# expect() and expect_any() share a per-fd leftover buffer so bytes
# that arrive AFTER the matched pattern aren't lost between calls.
# Without this, "CA generated successfully\n[?2004hgnoMint > " arrives
# as one chunk, the first expect("CA generated successfully") returns,
# and the trailing "gnoMint > " is discarded — so the next expect()
# waits forever for a prompt the child already emitted.
_expect_leftover = {}  # fd -> bytes left in our buffer after last match


def expect(fd, pattern, timeout=15):
    """Read until `pattern` (string substring) appears. Returns the
    bytes consumed up to and including the match. Any bytes after the
    match are stashed for the next expect call on the same fd."""
    needle = pattern.encode() if isinstance(pattern, str) else pattern
    buf = _expect_leftover.pop(fd, b"")
    deadline = time.time() + timeout
    while True:
        idx = buf.find(needle)
        if idx >= 0:
            cut = idx + len(needle)
            _expect_leftover[fd] = buf[cut:]
            return buf[:cut]
        if time.time() >= deadline:
            break
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError as e:
                if e.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            buf += chunk
    _expect_leftover[fd] = buf
    raise TimeoutError(
        f"timeout waiting for {needle!r}; got {len(buf)} bytes:\n"
        + buf.decode("utf-8", errors="replace")
    )


def expect_any(fd, patterns, timeout=15):
    """Like expect, but waits for the first of multiple needles."""
    needles = [p.encode() if isinstance(p, str) else p for p in patterns]
    buf = _expect_leftover.pop(fd, b"")
    deadline = time.time() + timeout
    while True:
        for n in needles:
            idx = buf.find(n)
            if idx >= 0:
                cut = idx + len(n)
                _expect_leftover[fd] = buf[cut:]
                return n, buf[:cut]
        if time.time() >= deadline:
            break
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError as e:
                if e.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            buf += chunk
    _expect_leftover[fd] = buf
    raise TimeoutError(
        f"timeout waiting for any of {needles!r}; got {len(buf)} bytes:\n"
        + buf.decode("utf-8", errors="replace")
    )


def send(fd, line):
    os.write(fd, (line + "\n").encode())


def send_passphrase(fd, passphrase):
    """Blind-write a passphrase twice (entry + confirm). The
    surrounding getpass() prompts won't reach the master until
    after we type, but the underlying code is waiting for them."""
    time.sleep(0.5)
    os.write(fd, (passphrase + "\n").encode())
    time.sleep(0.5)
    os.write(fd, (passphrase + "\n").encode())


def bootstrap_ca(fd, cn):
    """Drive addca to create a single CA. Assumes we're at the prompt."""
    send(fd, "addca")
    for _ in range(5):
        expect(fd, ": ")
        send(fd, "")           # blank C/ST/L/O/OU
    expect(fd, ": ")
    send(fd, cn)               # CN
    expect(fd, ": ")
    send(fd, "")               # email
    expect(fd, ": ")
    send(fd, "")               # SAN
    expect(fd, "[RSA]")
    send(fd, "RSA")
    expect(fd, "1024")
    send(fd, "1024")
    expect(fd, "240")
    send(fd, "12")
    expect(fd, "change anything")
    send(fd, "no")
    expect(fd, "Are you sure")
    send(fd, "yes")
    expect(fd, "CA generated successfully")
    expect(fd, "gnoMint > ")


def bootstrap_csr(fd, cn):
    """Drive addcsr (no inheritance) to create one CSR. Same prompt
    sequence as bootstrap_ca minus the months-before-expiration step
    (CSRs take validity from the CA at signing time)."""
    send(fd, "addcsr")
    for _ in range(5):
        expect(fd, ": ")
        send(fd, "")           # blank C/ST/L/O/OU
    expect(fd, ": ")
    send(fd, cn)               # CN
    expect(fd, ": ")
    send(fd, "")               # email
    expect(fd, ": ")
    send(fd, "")               # SAN
    expect(fd, "[RSA]")
    send(fd, "RSA")
    expect(fd, "1024")
    send(fd, "1024")
    expect(fd, "change anything")
    send(fd, "no")
    expect(fd, "Are you sure")
    send(fd, "yes")
    expect(fd, "CSR generated successfully")
    expect(fd, "gnoMint > ")


def scenario_extractcertpkey(tmpdir):
    db = os.path.join(tmpdir, "ec.gnomint")
    key_out = os.path.join(tmpdir, "ec.key.pem")

    pid, fd = spawn_cli(db)
    try:
        expect(fd, "gnoMint > ")
        bootstrap_ca(fd, "Extract CA")

        send(fd, f"extractcertpkey 1 {key_out}")
        # The intro printf reaches the master before the getpass prompts.
        expect(fd, "supply a passphrase")
        send_passphrase(fd, PASSPHRASE)
        expect(fd, "extracted successfully")
        expect(fd, "gnoMint > ")
        send(fd, "quit")
        time.sleep(0.3)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass

    if not os.path.isfile(key_out):
        raise AssertionError(f"extractcertpkey didn't create {key_out}")
    with open(key_out) as f:
        data = f.read()
    expected_markers = (
        "BEGIN ENCRYPTED PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
    )
    if not any(m in data for m in expected_markers):
        raise AssertionError(
            f"extracted key lacks PEM markers (got: {data[:80]!r})"
        )
    print("  scenario_extractcertpkey OK")


def scenario_extractcsrpkey(tmpdir):
    """Same shape as scenario_extractcertpkey but for a CSR row."""
    db = os.path.join(tmpdir, "ecsr.gnomint")
    key_out = os.path.join(tmpdir, "ecsr.key.pem")

    pid, fd = spawn_cli(db)
    try:
        expect(fd, "gnoMint > ")
        bootstrap_ca(fd, "CSR Parent CA")
        bootstrap_csr(fd, "Throwaway CSR")

        send(fd, f"extractcsrpkey 1 {key_out}")
        expect(fd, "supply a passphrase")
        send_passphrase(fd, PASSPHRASE)
        expect(fd, "extracted successfully")
        expect(fd, "gnoMint > ")
        send(fd, "quit")
        time.sleep(0.3)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass

    if not os.path.isfile(key_out):
        raise AssertionError(f"extractcsrpkey didn't create {key_out}")
    with open(key_out) as f:
        data = f.read()
    expected_markers = (
        "BEGIN ENCRYPTED PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
    )
    if not any(m in data for m in expected_markers):
        raise AssertionError(
            f"extracted CSR key lacks PEM markers (got: {data[:80]!r})"
        )
    print("  scenario_extractcsrpkey OK")


def scenario_changepassword(tmpdir):
    db = os.path.join(tmpdir, "cp.gnomint")
    new_password = "new-db-password-12345"

    pid, fd = spawn_cli(db)
    try:
        expect(fd, "gnoMint > ")
        bootstrap_ca(fd, "CP Test CA")

        send(fd, "changepassword")
        # First, gnomint-cli asks "Do you want to password protect it?
        # [Yes]/No". Just hit Enter to accept the default Yes.
        expect(fd, "password protect")
        send(fd, "")
        # Then the dialog_get_password intro printf, then two getpass()
        # calls (entry + confirm). The intro phrase is the trigger.
        expect(fd, "supply a password")
        send_passphrase(fd, new_password)
        # Success: returns to the prompt without an error line.
        n, buf = expect_any(fd, ["gnoMint > ", "Error"])
        if b"Error" in buf:
            raise AssertionError(
                "changepassword reported an error:\n"
                + buf.decode("utf-8", errors="replace")
            )
        send(fd, "quit")
        time.sleep(0.3)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass

    print("  scenario_changepassword OK")


def main():
    if not (shutil.which(CLI) or os.path.isfile(CLI)):
        print(f"SKIP: {CLI} not found", file=sys.stderr)
        return 77

    if sys.platform == "darwin":
        print("SKIP: macOS getpass() bypasses the pty slave, "
              "making pty-driven passphrase tests impossible",
              file=sys.stderr)
        return 77

    tmpdir = tempfile.mkdtemp(prefix="gnomint-pty-")
    try:
        scenario_extractcertpkey(tmpdir)
        scenario_extractcsrpkey(tmpdir)
        scenario_changepassword(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("PASS: extractcertpkey + extractcsrpkey + changepassword "
          "exercised under a pty")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TimeoutError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
    except AssertionError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
