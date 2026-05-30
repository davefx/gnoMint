#!/usr/bin/env python3
"""
check_gui_workflow.py — Black-box GUI workflow test for gnomint.

Uses Xorg + xf86-video-dummy + openbox + XTest (via x11type.py)
for input, xdotool for window management, AT-SPI (in subprocess)
for GAction activation, and SQLite for result verification.

NOTE: GTK 4's X11 backend has a focus-proxy architecture that makes
programmatic keyboard focus unreliable from external tools (XTest,
xdotool, inputtest).  The automated test suite uses check_workflows
under headless Wayland instead.  This script is kept for manual
X11 smoke testing where a human can click to establish focus.

Run:  tests/run-xdummy.sh python3 tests/check_gui_workflow.py
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
                    "from x11type import type_text, send_key, click, focus_window\n%s"
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
        # Give main window focus by clicking at screen center
        _x11("focus_window(640, 600)")
        time.sleep(1.0)
        ok()

        step("Create CA")
        # Open CA window via AT-SPI GAction (no coordinates needed)
        activate_action("win.add-ca")
        ca_wid = xdo_find("New CA")
        # Give the new CA window focus by clicking at screen center
        _x11("focus_window(640, 600)")
        time.sleep(0.5)

        # Click on the CN entry to focus it, type, then Tab+Space to Next.
        # CA window geometry retrieved dynamically.
        _x11("""
import subprocess
r = subprocess.run(['xdotool','search','--name','New CA'],
                   capture_output=True, text=True)
wid = r.stdout.strip().split(chr(10))[0]
r2 = subprocess.run(['xdotool','getwindowgeometry','--shell',wid],
                     capture_output=True, text=True)
g = {}
for ln in r2.stdout.strip().split(chr(10)):
    if '=' in ln: k,v=ln.split('='); g[k]=int(v)
# Tab to CN: country(1) + ST(1) + City(1) + O(1) + OU(1) + CN(1) = 6
for _ in range(6):
    send_key('Tab'); time.sleep(0.05)
type_text('Test Root CA'); time.sleep(0.3)
# Tab from CN to Next: email(1) + _Add(1) + _Edit(1) + _Remove(1) + Help(1) + Cancel(1) + Next(1) = 7
for _ in range(7):
    send_key('Tab'); time.sleep(0.05)
send_key('space'); time.sleep(1.0)
# Page 2: radio(4) + spin(1) + months(1) + Help(1) + Cancel(1) + Prev(1) + Next(1) = 10
for _ in range(10):
    send_key('Tab'); time.sleep(0.05)
send_key('space'); time.sleep(1.0)
# Page 3: CRL(1) + Help(1) + Cancel(1) + Prev(1) + OK(1) = 5
for _ in range(5):
    send_key('Tab'); time.sleep(0.05)
send_key('space')
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
import subprocess
r = subprocess.run(['xdotool','search','--pid','%d'],
                   capture_output=True, text=True)
wids = [w for w in r.stdout.strip().split(chr(10)) if w and w != '%s']
if wids:
    r2 = subprocess.run(['xdotool','getwindowgeometry','--shell',wids[-1]],
                         capture_output=True, text=True)
    g = {}
    for ln in r2.stdout.strip().split(chr(10)):
        if '=' in ln: k,v=ln.split('='); g[k]=int(v)
    focus_window(g.get('X',100) + g.get('WIDTH',400)//2,
                 g.get('Y',100) + g.get('HEIGHT',400)//2)
    time.sleep(0.3)
# CSR page 1: Tab to Next (8 stops)
for _ in range(8):
    send_key('Tab'); time.sleep(0.03)
send_key('Return'); time.sleep(0.5)
# Page 2: Tab to CN (6 stops)
for _ in range(6):
    send_key('Tab'); time.sleep(0.03)
type_text('Web Server Test'); time.sleep(0.3)
for _ in range(8):
    send_key('Tab'); time.sleep(0.03)
send_key('Return'); time.sleep(0.5)
# Page 3: Tab to OK (12 stops)
for _ in range(12):
    send_key('Tab'); time.sleep(0.03)
send_key('Return')
""" % (proc.pid, main_wid))

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
