"""
gui_harness.py — Headless GUI test harness for gnomint.

Drives gnomint via AT-SPI under a headless Wayland compositor (weston).
No keyboard/mouse injection needed — all interaction goes through
AT-SPI's action, selection, and editable-text interfaces.

Requires: run-gui-test.sh environment (WAYLAND_DISPLAY set,
          GDK_BACKEND=wayland, AT-SPI bus running).
"""

import gi
gi.require_version("Atspi", "2.0")
from gi.repository import Atspi

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))


class GnoMintHarness:
    """Launch gnomint and drive it via AT-SPI."""

    GNOMINT = os.environ.get("GNOMINT_BIN",
        os.path.join(_HERE, "..", "src", "gnomint"))
    GNOMINT_CLI = os.path.join(_HERE, "..", "src", "gnomint-cli")
    FIXTURE_DB = os.environ.get("FIXTURE_DB",
        os.path.join(_HERE, "..", "certs", "example-ca.gnomint"))

    def __init__(self, db_path=None, use_fixture=False):
        self.tmpdir = tempfile.mkdtemp(prefix="gnomint-gui-")
        if db_path:
            self.db = db_path
        elif use_fixture:
            self.db = os.path.join(self.tmpdir, "fixture.gnomint")
            shutil.copy2(self.FIXTURE_DB, self.db)
        else:
            self.db = os.path.join(self.tmpdir, "test.gnomint")

        self.proc = None
        self._app = None

    def start(self):
        env = {**os.environ, "LC_ALL": "C"}
        self.proc = subprocess.Popen(
            [self.GNOMINT, self.db], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._wait_for_app(timeout=15)
        return self

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
                self.proc.wait()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ── AT-SPI: app and window discovery ──

    def _wait_for_app(self, timeout=15):
        """Poll AT-SPI until gnomint appears."""
        Atspi.init()
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._app = self._find_app()
            if self._app:
                return
            time.sleep(0.5)
        raise RuntimeError("gnomint not found via AT-SPI after %ds" % timeout)

    def _find_app(self):
        d = Atspi.get_desktop(0)
        for i in range(d.get_child_count()):
            a = d.get_child_at_index(i)
            if a and a.get_name() == "gnomint":
                return a
        return None

    def get_frame(self):
        return self._app.get_child_at_index(0) if self._app else None

    def find_window(self, name_substr):
        if not self._app:
            return None
        for i in range(self._app.get_child_count()):
            w = self._app.get_child_at_index(i)
            if w and name_substr in (w.get_name() or ""):
                return w
        return None

    def wait_for_window(self, name_substr, timeout=20):
        """Poll until a window matching name_substr appears."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            w = self.find_window(name_substr)
            if w:
                return w
            time.sleep(0.5)
        return None

    def window_count(self):
        return self._app.get_child_count() if self._app else 0

    # ── AT-SPI: actions ──

    def activate_action(self, action_name):
        frame = self.get_frame()
        if not frame:
            return False
        ai = frame.get_action_iface()
        if not ai:
            return False
        for j in range(ai.get_n_actions()):
            if ai.get_action_name(j) == action_name:
                try:
                    ai.do_action(j)
                except Exception:
                    pass
                time.sleep(2)
                return True
        return False

    # ── AT-SPI: buttons ──

    def find_button(self, root, label):
        """Find the first visible+sensitive button with the given label."""
        return self._find_button_impl(root, label, 0)

    def _find_button_impl(self, obj, label, depth):
        if depth > 12:
            return None
        try:
            if obj.get_role_name() in ("button", "push button") and \
               obj.get_name() == label:
                ss = obj.get_state_set()
                if ss and ss.contains(Atspi.StateType.SHOWING) and \
                   ss.contains(Atspi.StateType.SENSITIVE):
                    return obj
            for i in range(obj.get_child_count()):
                c = obj.get_child_at_index(i)
                if c:
                    r = self._find_button_impl(c, label, depth + 1)
                    if r:
                        return r
        except Exception:
            pass
        return None

    def click_button(self, root, label):
        btn = self.find_button(root, label)
        if btn:
            ai = btn.get_action_iface()
            if ai and ai.get_n_actions() > 0:
                ai.do_action(0)
                time.sleep(0.5)
                return True
        return False

    # ── AT-SPI: widget search ──

    def find_widget_by_name(self, root, name_substr, depth=0):
        """Find any showing widget whose name contains name_substr."""
        if depth > 12:
            return None
        try:
            n = root.get_name() or ""
            ss = root.get_state_set()
            showing = ss.contains(Atspi.StateType.SHOWING) if ss else False
            if showing and name_substr in n:
                return root
            for i in range(root.get_child_count()):
                c = root.get_child_at_index(i)
                if c:
                    r = self.find_widget_by_name(c, name_substr, depth + 1)
                    if r:
                        return r
        except Exception:
            pass
        return None

    def click_widget_by_name(self, root, name_substr):
        w = self.find_widget_by_name(root, name_substr)
        if w:
            ai = w.get_action_iface()
            if ai and ai.get_n_actions() > 0:
                ai.do_action(0)
                time.sleep(0.5)
                return True
        return False

    # ── AT-SPI: text and editable fields ──

    def find_editable_texts(self, root):
        results = []
        self._collect_editable(root, results, 0)
        return results

    def _collect_editable(self, obj, results, depth):
        if depth > 12:
            return
        try:
            eti = obj.get_editable_text_iface()
            if eti:
                ss = obj.get_state_set()
                if ss and ss.contains(Atspi.StateType.SHOWING):
                    results.append(obj)
            for i in range(obj.get_child_count()):
                c = obj.get_child_at_index(i)
                if c:
                    self._collect_editable(c, results, depth + 1)
        except Exception:
            pass

    def set_entry_text(self, entry, text):
        eti = entry.get_editable_text_iface()
        if eti:
            eti.insert_text(0, text, len(text))
            time.sleep(0.2)

    # ── AT-SPI: tree view selection ──

    def select_row(self, index):
        frame = self.get_frame()
        lst = self._find_role(frame, "list")
        if not lst:
            return None
        si = lst.get_selection_iface()
        if not si:
            return None
        if index < 0 or index >= lst.get_child_count():
            return None
        si.select_child(index)
        time.sleep(0.3)
        row = lst.get_child_at_index(index)
        return row.get_name() if row else None

    def select_row_by_name(self, name_substr):
        frame = self.get_frame()
        lst = self._find_role(frame, "list")
        if not lst:
            return None
        si = lst.get_selection_iface()
        if not si:
            return None
        for i in range(lst.get_child_count()):
            row = lst.get_child_at_index(i)
            if row and name_substr in (row.get_name() or ""):
                si.select_child(i)
                time.sleep(0.3)
                return row.get_name()
        return None

    def row_count(self):
        frame = self.get_frame()
        lst = self._find_role(frame, "list")
        return lst.get_child_count() if lst else 0

    # ── AT-SPI: SAN editor ──

    def add_san(self, win, san_type_index, san_value):
        """Add a SAN via the SAN editor dialog."""
        clicked = self.click_button(win, "_Add") or \
                  self.click_button(win, "Add")
        if not clicked:
            return False
        time.sleep(1)

        san_dlg = self.find_window("Subject Alternative Name")
        if not san_dlg:
            san_dlg = self.find_window("SAN")
        if not san_dlg:
            return False

        entries = self.find_editable_texts(san_dlg)
        if entries:
            self.set_entry_text(entries[0], san_value)

        self.click_button(san_dlg, "OK") or self.click_button(san_dlg, "_OK")
        time.sleep(0.5)
        return True

    # ── Wizard navigation ──

    def wizard_next(self, win):
        """Click the Next button on the current wizard page."""
        self.click_button(win, "Next")
        time.sleep(1)

    def wizard_ok(self, win):
        """Click the OK button on the current wizard page."""
        self.click_button(win, "OK")
        time.sleep(1)

    # ── CLI helpers ──

    def cli(self, command, timeout=10):
        """Run a gnomint-cli command against this harness's database."""
        result = subprocess.run(
            [self.GNOMINT_CLI, self.db],
            input=command + "\n", capture_output=True, text=True,
            timeout=timeout)
        return result.stdout, result.stderr, result.returncode

    # ── DB helpers ──

    def db_query(self, sql):
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()

    def db_scalar(self, sql):
        rows = self.db_query(sql)
        return rows[0][0] if rows else None

    # ── Private ──

    def _find_role(self, obj, role, depth=0):
        if depth > 12 or not obj:
            return None
        try:
            if obj.get_role_name() == role:
                return obj
            for i in range(obj.get_child_count()):
                c = obj.get_child_at_index(i)
                if c:
                    r = self._find_role(c, role, depth + 1)
                    if r:
                        return r
        except Exception:
            pass
        return None
