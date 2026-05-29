#!/usr/bin/env python3
"""
check_gui_workflow.py — Black-box GUI workflow test for gnomint.

Launches gnomint under Xvfb + openbox, uses AT-SPI to discover widgets,
activate GActions, fill form entries, and click buttons. Verifies results
by inspecting the .gnomint SQLite database.

Workflow:
  1. App starts with fresh database
  2. Create a self-signed CA (3-page wizard)
  3. Verify CA in database
  4. Create a CSR (3-page wizard)
  5. Verify CSR in database

Run:  tests/run-xvfb.sh python3 tests/check_gui_workflow.py
Deps: xdotool, openbox, xvfb, python3-gi (Atspi-2.0), sqlite3
"""

import gi
gi.require_version("Atspi", "2.0")

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

from gi.repository import Atspi, GLib

GNOMINT = os.environ.get("GNOMINT_BIN", "src/gnomint")
TIMEOUT = 20

Atspi.init()


def pump(secs=0.3):
    ctx = GLib.MainContext.default()
    end = time.time() + secs
    while time.time() < end:
        ctx.iteration(False)
        time.sleep(0.02)


def find_all(node, role=None, name=None, depth=0, max_depth=15):
    results = []
    if node is None or depth > max_depth:
        return results
    try:
        n = node.get_child_count()
    except Exception:
        return results
    for i in range(n):
        c = node.get_child_at_index(i)
        if c is None:
            continue
        match = True
        if role is not None and c.get_role() != role:
            match = False
        if name is not None and name not in (c.get_name() or ""):
            match = False
        if match:
            results.append(c)
        results.extend(find_all(c, role, name, depth + 1, max_depth))
    return results


def atspi_click(node):
    ai = node.get_action_iface()
    if ai and ai.get_n_actions() > 0:
        ai.do_action(0)
        pump(0.3)
        return True
    return False


def atspi_set_text(node, text):
    ei = node.get_editable_text_iface()
    ti = node.get_text_iface()
    if ei:
        length = ti.get_character_count() if ti else 0
        if length > 0:
            ei.delete_text(0, length)
        ei.insert_text(0, text, len(text))
    pump(0.1)


def find_atspi_app(name, timeout=TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        desktop = Atspi.get_desktop(0)
        for i in range(desktop.get_child_count()):
            a = desktop.get_child_at_index(i)
            if a and a.get_name() == name:
                return a
        pump(0.3)
    raise TimeoutError("AT-SPI: app '%s' not found" % name)


def find_atspi_window(app, name_sub, timeout=TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for i in range(app.get_child_count()):
            w = app.get_child_at_index(i)
            if w and name_sub in (w.get_name() or ""):
                return w
        pump(0.3)
    raise TimeoutError("Window '%s' not found" % name_sub)


def activate_action(app, action_name):
    frame = app.get_child_at_index(0)
    ai = frame.get_action_iface()
    for j in range(ai.get_n_actions()):
        if ai.get_action_name(j) == action_name:
            ai.do_action(j)
            pump(0.5)
            return
    raise RuntimeError("Action '%s' not found" % action_name)


def dismiss_dialogs(app, main_name="gnoMint", max_tries=20):
    for _ in range(max_tries):
        found = False
        for i in range(app.get_child_count()):
            w = app.get_child_at_index(i)
            if w is None:
                continue
            wn = w.get_name() or ""
            if wn == main_name:
                continue
            btns = find_all(w, role=Atspi.Role.PUSH_BUTTON)
            for b in btns:
                bn = (b.get_name() or "").lower()
                if bn in ("close", "ok", ""):
                    atspi_click(b)
                    found = True
                    break
            if not found:
                ai = w.get_action_iface()
                if ai:
                    for j in range(ai.get_n_actions()):
                        if "close" in ai.get_action_name(j):
                            ai.do_action(j)
                            found = True
                            break
            if found:
                pump(0.5)
                break
        if not found:
            break


def db_query(path, sql):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


_step = ""

def step(name):
    global _step
    _step = name
    print("  %s..." % name, end="", flush=True)

def ok(detail=""):
    print(" OK" + (" (%s)" % detail if detail else ""))


def run():
    tmpdir = tempfile.mkdtemp(prefix="gnomint-gui-")
    db = os.path.join(tmpdir, "test.gnomint")

    proc = subprocess.Popen(
        [GNOMINT, db],
        env={**os.environ, "LC_ALL": "C"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        # 1. App startup
        step("App startup")
        app = find_atspi_app("gnomint")
        frame = find_atspi_window(app, "gnoMint")
        pump(1.0)
        ok()

        # 2. Create CA
        step("Create CA")
        activate_action(app, "win.add-ca")
        ca_win = find_atspi_window(app, "New CA")

        # Find text entries — CN is entry[4] (ST, City, O, OU, CN)
        entries = find_all(ca_win, role=Atspi.Role.TEXT)
        assert len(entries) >= 5, "Expected >=5 entries, got %d" % len(entries)
        atspi_set_text(entries[4], "Test Root CA")

        # Click Next (now always sensitive; validates CN on click)
        next_btns = find_all(ca_win, role=Atspi.Role.PUSH_BUTTON, name="Next")
        assert next_btns, "Next button not found"
        atspi_click(next_btns[0])
        pump(0.5)

        # Page 2: accept defaults. Click Next (page 2's Next).
        # After page switch, re-scan buttons. The notebook makes
        # page-2 buttons the visible ones.
        next_btns = find_all(ca_win, role=Atspi.Role.PUSH_BUTTON, name="Next")
        if len(next_btns) >= 2:
            atspi_click(next_btns[1])
        elif next_btns:
            atspi_click(next_btns[-1])
        pump(0.5)

        # Page 3: Click OK
        ok_btns = find_all(ca_win, role=Atspi.Role.PUSH_BUTTON, name="OK")
        if not ok_btns:
            ok_btns = find_all(ca_win, role=Atspi.Role.PUSH_BUTTON, name="_OK")
        assert ok_btns, "OK button not found on page 3"
        atspi_click(ok_btns[-1])

        # Wait for key generation
        pump(10.0)
        dismiss_dialogs(app)
        pump(1.0)

        # Verify
        rows = db_query(db, "SELECT subject FROM certificates WHERE is_ca=1")
        assert len(rows) >= 1, "No CA in database"
        ok("'%s'" % rows[0][0])

        # 3. Create CSR
        step("Create CSR")
        activate_action(app, "win.add-csr")
        pump(1.0)

        # Find the CSR window (any non-main window)
        csr_win = None
        for i in range(app.get_child_count()):
            w = app.get_child_at_index(i)
            if w and (w.get_name() or "") != "gnoMint":
                csr_win = w
                break
        assert csr_win, "CSR window not found"

        # CSR page 1: CA selector. Click Next to go to page 2.
        next_btns = find_all(csr_win, role=Atspi.Role.PUSH_BUTTON, name="Next")
        if next_btns:
            atspi_click(next_btns[0])
        pump(0.5)

        # CSR page 2: fill CN. Re-scan entries from csr_win.
        entries = find_all(csr_win, role=Atspi.Role.TEXT)
        # CN entry — find by trying several indices
        cn_set = False
        for idx in [4, 3, 5, 0]:
            if idx < len(entries):
                atspi_set_text(entries[idx], "Web Server Test")
                ti = entries[idx].get_text_iface()
                if ti and "Web Server" in ti.get_text(0, 30):
                    cn_set = True
                    break
        if not cn_set and entries:
            atspi_set_text(entries[-1], "Web Server Test")

        # Click Next (page 2 -> page 3)
        next_btns = find_all(csr_win, role=Atspi.Role.PUSH_BUTTON, name="Next")
        if len(next_btns) >= 2:
            atspi_click(next_btns[-1])
        elif next_btns:
            atspi_click(next_btns[0])
        pump(0.5)

        # Page 3: Click OK/Commit
        ok_btns = find_all(csr_win, role=Atspi.Role.PUSH_BUTTON, name="OK")
        if not ok_btns:
            ok_btns = find_all(csr_win, role=Atspi.Role.PUSH_BUTTON, name="_OK")
        if ok_btns:
            atspi_click(ok_btns[-1])

        pump(10.0)
        dismiss_dialogs(app)
        pump(1.0)

        # Verify
        csr_rows = db_query(db, "SELECT subject FROM certificate_requests")
        assert len(csr_rows) >= 1, "No CSR in database"
        ok("'%s'" % csr_rows[0][0])

        # 4. Final check
        step("Final DB check")
        n_certs = db_query(db, "SELECT COUNT(*) FROM certificates")[0][0]
        n_csrs = db_query(db, "SELECT COUNT(*) FROM certificate_requests")[0][0]
        ok("certs=%d, CSRs=%d" % (n_certs, n_csrs))

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    if not os.path.isfile(GNOMINT):
        if not shutil.which(GNOMINT):
            print("SKIP: %s not found" % GNOMINT, file=sys.stderr)
            return 77
    for dep in ("xdotool", "openbox"):
        if not shutil.which(dep):
            print("SKIP: %s not found" % dep, file=sys.stderr)
            return 77

    print("==> gnomint GUI workflow (black-box, AT-SPI + xdotool)")
    run()
    print("PASS: GUI workflow — CA + CSR creation verified end-to-end")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (TimeoutError, AssertionError) as e:
        print("\nFAIL [%s]: %s" % (_step, e), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("\nFAIL [%s]: %s" % (_step, e), file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
