#!/usr/bin/env python3
"""
testwm.py — Minimal WM for headless GTK 4 GUI testing.

Handles only what GTK 4 needs: sends WM_TAKE_FOCUS on MapNotify
without calling XSetInputFocus directly, so GTK 4's focus proxy
gets the FocusIn event it expects.

Run in the background before launching the app under test.
"""

import ctypes
import ctypes.util
import signal
import struct
import sys

x11 = ctypes.cdll.LoadLibrary(ctypes.util.find_library("X11") or "libX11.so.6")

XEvent = ctypes.c_char * 192

x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XInternAtom.restype = ctypes.c_ulong
x11.XDefaultRootWindow.restype = ctypes.c_ulong
x11.XNextEvent.argtypes = [ctypes.c_void_p, ctypes.c_char * 192]

SubstructureRedirectMask = 1 << 20
SubstructureNotifyMask = 1 << 19
MapRequest = 20
MapNotify = 19
ConfigureRequest = 23
UnmapNotify = 18


def run():
    dpy = x11.XOpenDisplay(None)
    if not dpy:
        print("testwm: cannot open display", file=sys.stderr)
        sys.exit(1)

    root = x11.XDefaultRootWindow(dpy)
    WM_PROTOCOLS = x11.XInternAtom(dpy, b"WM_PROTOCOLS", False)
    WM_TAKE_FOCUS = x11.XInternAtom(dpy, b"WM_TAKE_FOCUS", False)
    NET_ACTIVE = x11.XInternAtom(dpy, b"_NET_ACTIVE_WINDOW", False)
    NET_SUPPORTING = x11.XInternAtom(dpy, b"_NET_SUPPORTING_WM_CHECK", False)
    NET_WM_NAME = x11.XInternAtom(dpy, b"_NET_WM_NAME", False)
    UTF8 = x11.XInternAtom(dpy, b"UTF8_STRING", False)

    x11.XSelectInput(dpy, root,
                     SubstructureRedirectMask | SubstructureNotifyMask)

    wmwin = x11.XCreateSimpleWindow(dpy, root, 0, 0, 1, 1, 0, 0, 0)
    name = b"testwm"
    x11.XChangeProperty(dpy, wmwin, NET_WM_NAME, UTF8, 8, 0, name, len(name))
    x11.XChangeProperty(dpy, root, NET_SUPPORTING,
                        33, 32, 0, ctypes.byref(ctypes.c_ulong(wmwin)), 1)
    x11.XChangeProperty(dpy, wmwin, NET_SUPPORTING,
                        33, 32, 0, ctypes.byref(ctypes.c_ulong(wmwin)), 1)

    x11.XFlush(dpy)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    screen_w = x11.XDisplayWidth(dpy, 0)
    screen_h = x11.XDisplayHeight(dpy, 0)

    def send_take_focus(window):
        # XClientMessageEvent layout on x86-64:
        #   0: int type (4) + 4 pad
        #   8: ulong serial (8)
        #  16: int send_event (4) + 4 pad
        #  24: Display* display (8)
        #  32: Window window (8)
        #  40: Atom message_type (8)
        #  48: int format (4) + 4 pad
        #  56: long data[0] (8)
        #  64: long data[1] (8)
        data = bytearray(192)
        struct.pack_into("=i", data, 0, 33)             # type = ClientMessage
        struct.pack_into("=i", data, 16, 1)              # send_event = True
        struct.pack_into("=Q", data, 32, window)         # window
        struct.pack_into("=Q", data, 40, WM_PROTOCOLS)   # message_type
        struct.pack_into("=i", data, 48, 32)             # format = 32
        struct.pack_into("=q", data, 56, WM_TAKE_FOCUS)  # data.l[0]
        struct.pack_into("=q", data, 64, 0)              # data.l[1] = CurrentTime
        cm = (ctypes.c_char * 192)(*data)
        x11.XSendEvent(dpy, window, False, 0, cm)
        x11.XChangeProperty(dpy, root, NET_ACTIVE,
                            33, 32, 0,
                            ctypes.byref(ctypes.c_ulong(window)), 1)
        x11.XFlush(dpy)

    evt = XEvent()
    while True:
        x11.XNextEvent(dpy, evt)
        raw = bytes(evt)
        etype = struct.unpack_from("=i", raw, 0)[0]

        if etype == MapRequest:
            # XMapRequestEvent: window at offset 40
            window = struct.unpack_from("=Q", raw, 40)[0]
            sys.stderr.write(f"testwm: MapRequest 0x{window:x}\n")
            sys.stderr.flush()
            x11.XMapWindow(dpy, window)
            x11.XFlush(dpy)
            send_take_focus(window)

        elif etype == MapNotify:
            # XMapNotifyEvent: window at offset 40
            window = struct.unpack_from("=Q", raw, 40)[0]
            if window != wmwin and window != root:
                sys.stderr.write(f"testwm: MapNotify 0x{window:x}\n")
                sys.stderr.flush()
                send_take_focus(window)

        elif etype == ConfigureRequest:
            # XConfigureRequestEvent: window at offset 32
            window = struct.unpack_from("=Q", raw, 32)[0]
            x11.XFlush(dpy)


if __name__ == "__main__":
    run()
