#!/usr/bin/env python3
"""
check_gui_workflow.py — Black-box GUI workflow test for gnomint.

Uses Xvfb + openbox + XTest (via x11type.py) for input,
xdotool for window management, AT-SPI (in subprocess) for
GAction activation, and SQLite for result verification.

Run:  tests/run-xvfb.sh python3 tests/check_gui_workflow.py
"""

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

GNOMINT = os.environ.get("GNOMINT_BIN", "src/gnomint")
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
TIMEOUT = 20


def _x11(script):
    subprocess.run([sys.executable, "-c",
                    "import sys, time; sys.path.insert(0, %r); "
                    "from x11type import type_text, send_key, click\n%s"
                    % (TESTS_DIR, script)],
                   check=False, timeout=30)
    time.sleep(0.05)


def activate_action(action_name):
    subprocess.run([sys.executable, "-c",
        "import gi; gi.require_version('Atspi','2.0')\n"
        "from gi.repository import Atspi; import time\n"
        "Atspi.init(); time.sleep(0.5)\n"
        "d=Atspi.get_desktop(0)\n"
        "for i in range(d.get_child_count()):\n"
        "  a=d.get_child_at_index(i)\n"
        "  if a and a.get_name()=='gnomint':\n"
        "    f=a.get_child_at_index(0); ai=f.get_action_iface()\n"
        "    for j in range(ai.get_n_actions()):\n"
        "      if ai.get_action_name(j)==%r:\n"
        "        try: ai.do_action(j)\n"
        "        except: pass\n"
        "        break\n"
        "    break\n" % action_name
    ], check=False, timeout=10)
    time.sleep(1.0)


def xdo_find(name, timeout=TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(["xdotool", "search", "--name", name],
                           capture_output=True, text=True)
        wids = [w for w in r.stdout.strip().split("\n") if w]
        if wids:
            return wids[0]
        time.sleep(0.3)
    raise TimeoutError("Window '%s' not found" % name)


def xdo(*a):
    subprocess.run(["xdotool"] + list(a), capture_output=True)
    time.sleep(0.1)


def db_query(path, sql):
    c = sqlite3.connect(path)
    try:
        return c.execute(sql).fetchall()
    finally:
        c.close()


_step = ""

def step(name):
    global _step; _step = name
    print("  %s..." % name, end="", flush=True)

def ok(d=""):
    print(" OK" + (" (%s)" % d if d else ""))


def run():
    tmpdir = tempfile.mkdtemp(prefix="gnomint-gui-")
    db = os.path.join(tmpdir, "test.gnomint")

    proc = subprocess.Popen([GNOMINT, db],
        env={**os.environ, "LC_ALL": "C"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        step("App startup")
        main_wid = xdo_find("gnoMint")
        xdo("windowactivate", "--sync", main_wid)
        time.sleep(1.0)
        ok()

        step("Create CA")
        activate_action("win.add-ca")
        ca_wid = xdo_find("New CA")
        xdo("windowactivate", "--sync", ca_wid)
        xdo("windowfocus", "--sync", ca_wid)
        xdo("windowraise", ca_wid)
        time.sleep(1.0)

        # Click on widgets at absolute screen coordinates.
        # openbox places window content at y=44 (title bar + border).
        # Window is 700x600, so content spans y=44..644.
        _x11("""
click(240, 300); time.sleep(0.2)    # CN entry (~250px into content)
type_text('Test Root CA'); time.sleep(0.3)
click(196, 615); time.sleep(1.0)    # Next button (near bottom of content)
click(196, 615); time.sleep(1.0)    # Next button (page 2, same position)
click(196, 615)                     # OK button (page 3, same position)
""")

        print(" keygen...", end="", flush=True)
        time.sleep(15)
        print(" dismiss...", end="", flush=True)

        # Dismiss extra windows
        for _ in range(15):
            r = subprocess.run(["xdotool", "search", "--pid", str(proc.pid)],
                               capture_output=True, text=True)
            extras = [w for w in r.stdout.strip().split("\n")
                      if w and w != main_wid]
            if not extras:
                break
            for w in extras:
                xdo("windowactivate", w)
                _x11("send_key('Return')")
                time.sleep(0.3)
            time.sleep(0.5)

        rows = db_query(db, "SELECT subject FROM certificates WHERE is_ca=1")
        assert len(rows) >= 1, "No CA in database"
        ok("'%s'" % rows[0][0])

        step("Create CSR")
        xdo("windowactivate", "--sync", main_wid)
        activate_action("win.add-csr")
        time.sleep(1.0)
        r = subprocess.run(["xdotool", "search", "--pid", str(proc.pid)],
                           capture_output=True, text=True)
        csr_wids = [w for w in r.stdout.strip().split("\n")
                    if w and w != main_wid]
        assert csr_wids, "CSR window not found"
        xdo("windowactivate", "--sync", csr_wids[-1])
        time.sleep(0.5)

        _x11("""
# CSR page 1: Tab to Next, Space
for _ in range(8):
    send_key('Tab'); time.sleep(0.03)
send_key('space'); time.sleep(0.5)
# Page 2: Tab 6x to CN (dropdown+ST+City+O+OU+CN), type
for _ in range(6):
    send_key('Tab'); time.sleep(0.03)
type_text('Web Server Test'); time.sleep(0.3)
for _ in range(8):
    send_key('Tab'); time.sleep(0.03)
send_key('space'); time.sleep(0.5)
# Page 3: Tab 12x to OK, Space
for _ in range(12):
    send_key('Tab'); time.sleep(0.03)
send_key('space')
""")

        print(" keygen...", end="", flush=True)
        time.sleep(15)

        for _ in range(15):
            r = subprocess.run(["xdotool", "search", "--pid", str(proc.pid)],
                               capture_output=True, text=True)
            extras = [w for w in r.stdout.strip().split("\n")
                      if w and w != main_wid]
            if not extras:
                break
            for w in extras:
                xdo("windowactivate", w)
                _x11("send_key('Return')")
                time.sleep(0.3)
            time.sleep(0.5)

        csr_rows = db_query(db, "SELECT subject FROM certificate_requests")
        assert len(csr_rows) >= 1, "No CSR in database"
        ok("'%s'" % csr_rows[0][0])

        step("Final DB check")
        nc = db_query(db, "SELECT COUNT(*) FROM certificates")[0][0]
        nr = db_query(db, "SELECT COUNT(*) FROM certificate_requests")[0][0]
        ok("certs=%d CSRs=%d" % (nc, nr))

    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except: proc.kill(); proc.wait()
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    if not os.path.isfile(GNOMINT):
        if not shutil.which(GNOMINT):
            print("SKIP: %s not found" % GNOMINT, file=sys.stderr)
            return 77
    if not shutil.which("xdotool"):
        print("SKIP: xdotool not found", file=sys.stderr)
        return 77

    print("==> gnomint GUI workflow (black-box, XTest + xdotool)")
    run()
    print("PASS: GUI workflow — CA + CSR creation verified")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (TimeoutError, AssertionError) as e:
        print("\nFAIL [%s]: %s" % (_step, e), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("\nFAIL [%s]: %s" % (_step, e), file=sys.stderr)
        import traceback; traceback.print_exc()
        sys.exit(1)
