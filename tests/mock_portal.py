#!/usr/bin/env python3
"""
mock_portal.py — Mock xdg-desktop-portal FileChooser for headless testing.

Implements the org.freedesktop.portal.FileChooser D-Bus interface.
When OpenFile/SaveFile/SaveFiles is called, immediately responds with
a preconfigured file path instead of showing a dialog.

Usage:
    Set MOCK_PORTAL_OPEN=/path/to/file for OpenFile responses.
    Set MOCK_PORTAL_SAVE=/path/to/file for SaveFile responses.
    Run this before launching the application under test.
"""

import os
import sys
import signal
import threading

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

_request_counter = 0


class MockFileChooser(dbus.service.Object):
    IFACE = "org.freedesktop.portal.FileChooser"

    def __init__(self, bus, open_path=None, save_path=None):
        self._bus = bus
        self._open_path = open_path or "/dev/null"
        self._save_path = save_path or "/tmp/gnomint-mock-export.pem"
        super().__init__(bus, "/org/freedesktop/portal/desktop")

    def _next_request_path(self, sender):
        global _request_counter
        _request_counter += 1
        token = "gnomint%d" % _request_counter
        sender_part = sender.replace(".", "_").replace(":", "")
        return "/org/freedesktop/portal/desktop/request/%s/%s" % (
            sender_part, token)

    def _respond(self, request_path, uri):
        """Emit Response signal on the request object after a short delay."""
        def _emit():
            req = MockRequest(self._bus, request_path, uri)
            req.emit_response()
            return False
        GLib.timeout_add(100, _emit)

    @dbus.service.method(IFACE, in_signature="ssa{sv}", out_signature="o",
                         sender_keyword="sender")
    def OpenFile(self, parent_window, title, options, sender=None):
        path = self._next_request_path(sender)
        uri = "file://" + os.path.abspath(self._open_path)
        sys.stderr.write("mock-portal: OpenFile '%s' → %s\n" % (title, uri))
        self._respond(path, uri)
        return path

    @dbus.service.method(IFACE, in_signature="ssa{sv}", out_signature="o",
                         sender_keyword="sender")
    def SaveFile(self, parent_window, title, options, sender=None):
        path = self._next_request_path(sender)
        uri = "file://" + os.path.abspath(self._save_path)
        sys.stderr.write("mock-portal: SaveFile '%s' → %s\n" % (title, uri))
        self._respond(path, uri)
        return path

    @dbus.service.method(IFACE, in_signature="ssa{sv}", out_signature="o",
                         sender_keyword="sender")
    def SaveFiles(self, parent_window, title, options, sender=None):
        return self.SaveFile(parent_window, title, options, sender=sender)

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature="ss",
                         out_signature="v")
    def Get(self, interface, prop):
        if prop == "version":
            return dbus.UInt32(4)
        raise dbus.exceptions.DBusException("No such property")

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature="s",
                         out_signature="a{sv}")
    def GetAll(self, interface):
        return {"version": dbus.UInt32(4)}


class MockRequest(dbus.service.Object):
    IFACE = "org.freedesktop.portal.Request"

    def __init__(self, bus, path, uri):
        self._uri = uri
        super().__init__(bus, path)

    @dbus.service.signal(IFACE, signature="ua{sv}")
    def Response(self, response, results):
        pass

    @dbus.service.method(IFACE, in_signature="", out_signature="")
    def Close(self):
        pass

    def emit_response(self):
        self.Response(
            dbus.UInt32(0),
            {"uris": dbus.Array([self._uri], signature="s")})


def run(open_path=None, save_path=None):
    bus = dbus.SessionBus()
    name = dbus.service.BusName("org.freedesktop.portal.Desktop", bus,
                                replace_existing=True, allow_replacement=True,
                                do_not_queue=True)
    MockFileChooser(bus,
                    open_path=open_path or os.environ.get("MOCK_PORTAL_OPEN"),
                    save_path=save_path or os.environ.get("MOCK_PORTAL_SAVE"))

    loop = GLib.MainLoop()
    signal.signal(signal.SIGTERM, lambda *_: loop.quit())
    signal.signal(signal.SIGINT, lambda *_: loop.quit())
    sys.stderr.write("mock-portal: running (open=%s save=%s)\n" % (
        open_path or os.environ.get("MOCK_PORTAL_OPEN", "(default)"),
        save_path or os.environ.get("MOCK_PORTAL_SAVE", "(default)")))
    loop.run()


if __name__ == "__main__":
    run()
