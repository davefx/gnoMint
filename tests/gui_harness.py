"""
gui_harness.py — Headless GUI test harness for gnomint under Xorg+dummy.

Combines AT-SPI (widget introspection + GAction activation + button clicks)
with the Xorg inputtest driver (keyboard navigation + text input) to drive
gnomint end-to-end without needing GDK surface focus for every operation.

Requires: run-xdummy.sh environment (INPUTTEST_KBD_SOCK set),
          patched GTK 4 via LD_PRELOAD for keyboard activation.
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from inputtest_client import (InputTestClient, send_key, type_text,
                               KEY_LEFTALT, KEY_LEFTSHIFT)


class GnoMintHarness:
    """Launch gnomint and drive it via AT-SPI + inputtest keyboard."""

    GNOMINT = os.environ.get("GNOMINT_BIN", "src/gnomint")
    GTK_PRELOAD = os.environ.get(
        "GTK_PRELOAD", "/tmp/gtk4-build/gtk/libgtk-4.so.1.2200.2")
    FIXTURE_DB = os.environ.get(
        "FIXTURE_DB",
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", "certs", "example-ca.gnomint"))

    def __init__(self, db_path=None, use_fixture=False, kbd=None):
        self.tmpdir = tempfile.mkdtemp(prefix="gnomint-gui-")
        if db_path:
            self.db = db_path
        elif use_fixture:
            self.db = os.path.join(self.tmpdir, "fixture.gnomint")
            shutil.copy2(self.FIXTURE_DB, self.db)
        else:
            self.db = os.path.join(self.tmpdir, "test.gnomint")

        self._owns_kbd = kbd is None
        self.kbd = kbd or InputTestClient(os.environ["INPUTTEST_KBD_SOCK"])
        self.proc = None
        self._portal_proc = None
        self._app = None
        self.export_path = os.path.join(self.tmpdir, "export.pem")
        self.import_path = None

    def start(self, mock_portal=True):
        env = {**os.environ, "LC_ALL": "C"}
        if os.path.isfile(self.GTK_PRELOAD):
            env["LD_PRELOAD"] = self.GTK_PRELOAD
        if mock_portal:
            env["GTK_USE_PORTAL"] = "1"

        if mock_portal:
            portal_env = {**os.environ,
                          "MOCK_PORTAL_SAVE": self.export_path}
            if self.import_path:
                portal_env["MOCK_PORTAL_OPEN"] = self.import_path
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "mock_portal.py")
            self._portal_proc = subprocess.Popen(
                [sys.executable, script], env=portal_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)

        self.proc = subprocess.Popen(
            [self.GNOMINT, self.db], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(4)
        Atspi.init()
        time.sleep(0.5)
        self._app = self._find_app()
        if not self._app:
            raise RuntimeError("gnomint not found via AT-SPI")
        return self

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
                self.proc.wait()
        if self._portal_proc:
            self._portal_proc.terminate()
            try:
                self._portal_proc.wait(timeout=3)
            except Exception:
                self._portal_proc.kill()
                self._portal_proc.wait()
        if self._owns_kbd:
            self.kbd.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ── AT-SPI helpers ──

    def _find_app(self):
        d = Atspi.get_desktop(0)
        for i in range(d.get_child_count()):
            a = d.get_child_at_index(i)
            if a and a.get_name() == "gnomint":
                return a
        return None

    def get_frame(self):
        return self._app.get_child_at_index(0) if self._app else None

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
                time.sleep(1.5)
                return True
        return False

    def find_window(self, name_substr):
        if not self._app:
            return None
        for i in range(self._app.get_child_count()):
            w = self._app.get_child_at_index(i)
            if w and name_substr in (w.get_name() or ""):
                return w
        return None

    def find_button(self, root, label):
        return self._find_by_role_name(root, ("button", "push button"), label)

    def click_button(self, root, label):
        btn = self.find_button(root, label)
        if btn:
            ai = btn.get_action_iface()
            if ai and ai.get_n_actions() > 0:
                ai.do_action(0)
                time.sleep(0.5)
                return True
        return False

    def find_editable_texts(self, root):
        results = []
        self._collect_editable(root, results, 0)
        return results

    def set_entry_text(self, entry, text):
        eti = entry.get_editable_text_iface()
        if eti:
            eti.insert_text(0, text, len(text))
            time.sleep(0.2)

    def find_focused(self, root=None):
        if root is None:
            root = self._app
        if not root:
            return None
        return self._find_with_state(root, Atspi.StateType.FOCUSED, 0)

    def window_count(self):
        if not self._app:
            return 0
        return self._app.get_child_count()

    # ── Keyboard helpers ──

    def tab(self, n=1):
        for _ in range(n):
            send_key(self.kbd, "Tab")
            time.sleep(0.08)
        self.kbd.sync()

    def alt_key(self, key_name):
        from inputtest_client import _NAME_TO_KEYCODE, _CHAR_TO_KEYCODE
        if key_name in _NAME_TO_KEYCODE:
            kc = _NAME_TO_KEYCODE[key_name]
        elif len(key_name) == 1 and key_name.lower() in _CHAR_TO_KEYCODE:
            kc = _CHAR_TO_KEYCODE[key_name.lower()]
        else:
            raise ValueError("Unknown key: " + key_name)
        need_shift = key_name != key_name.lower()
        if need_shift:
            self.kbd.key_event(KEY_LEFTSHIFT, press=True)
            time.sleep(0.02)
        self.kbd.key_event(KEY_LEFTALT, press=True)
        time.sleep(0.03)
        self.kbd.key_event(kc, press=True)
        time.sleep(0.03)
        self.kbd.key_event(kc, press=False)
        time.sleep(0.03)
        self.kbd.key_event(KEY_LEFTALT, press=False)
        if need_shift:
            time.sleep(0.02)
            self.kbd.key_event(KEY_LEFTSHIFT, press=False)
        self.kbd.sync()
        time.sleep(0.5)

    def type(self, text):
        type_text(self.kbd, text)
        self.kbd.sync()
        time.sleep(0.3)

    def press_return(self):
        send_key(self.kbd, "Return")
        self.kbd.sync()
        time.sleep(0.5)

    def press_escape(self):
        send_key(self.kbd, "Escape")
        self.kbd.sync()
        time.sleep(0.5)

    def add_san(self, win, san_type_index, san_value):
        """Add a Subject Alternative Name entry via the SAN editor dialog.

        Clicks the _Add button in the wizard window, waits for the SAN editor
        dialog, sets the value via AT-SPI EditableText, and clicks OK.

        Args:
            win: The wizard window containing the _Add button.
            san_type_index: Index for the SAN type dropdown (0=DNS, 1=IP,
                            2=Email, 3=URI). Currently only default (0) is
                            used since GtkDropDown is hard to drive via AT-SPI.
            san_value: The SAN value string to enter.
        """
        # Click the _Add button inside the wizard window
        clicked = self.click_button(win, "_Add") or self.click_button(win, "Add")
        if not clicked:
            return False
        time.sleep(1)

        # Find the SAN editor dialog (separate window)
        san_dlg = self.find_window("Subject Alternative Name")
        if not san_dlg:
            san_dlg = self.find_window("SAN")
        if not san_dlg:
            return False

        # Find the editable text entry in the dialog and set the value
        entries = self.find_editable_texts(san_dlg)
        if entries:
            self.set_entry_text(entries[0], san_value)
            time.sleep(0.2)

        # Click OK in the SAN editor dialog
        self.click_button(san_dlg, "OK") or self.click_button(san_dlg, "_OK")
        time.sleep(0.5)
        return True

    def wizard_next(self, win):
        """Advance a wizard page: try Alt+N mnemonic, fall back to AT-SPI."""
        self.alt_key("n")
        time.sleep(1)
        # If the mnemonic didn't work (unpatched GTK 4), click via AT-SPI
        self.click_button(win, "Next") or self.click_button(win, "_Next")
        time.sleep(0.5)

    def wizard_ok(self, win):
        """Commit a wizard: try Alt+O mnemonic, fall back to AT-SPI."""
        self.alt_key("o")
        time.sleep(1)
        self.click_button(win, "OK") or self.click_button(win, "_OK")
        time.sleep(0.5)

    def wait_for_window(self, name_substr, timeout=20):
        """Wait for a new window to appear, without dismissing it.

        Returns the window accessible, or None on timeout.  This lets
        the GTK event loop run naturally — if the app is hung (e.g. a
        blocking g_main_context_iteration), the window never appears
        and the test times out.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            w = self.find_window(name_substr)
            if w:
                return w
            time.sleep(0.5)
        return None

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

    def _find_by_role_name(self, obj, roles, name, depth=0):
        if depth > 12:
            return None
        try:
            if obj.get_role_name() in roles and obj.get_name() == name:
                return obj
            for i in range(obj.get_child_count()):
                c = obj.get_child_at_index(i)
                if c:
                    r = self._find_by_role_name(c, roles, name, depth + 1)
                    if r:
                        return r
        except Exception:
            pass
        return None

    def _find_with_state(self, obj, state, depth):
        if depth > 12:
            return None
        try:
            ss = obj.get_state_set()
            if ss and ss.contains(state):
                return obj
            for i in range(obj.get_child_count()):
                c = obj.get_child_at_index(i)
                if c:
                    r = self._find_with_state(c, state, depth + 1)
                    if r:
                        return r
        except Exception:
            pass
        return None

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
