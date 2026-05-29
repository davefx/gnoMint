"""
x11type.py — Send keyboard events to the X display via XTest extension.

xdotool's type/key commands use the old core protocol path which GTK 4
ignores. This module uses XTestFakeKeyEvent directly via ctypes, which
goes through the full X server input pipeline and is received by GTK 4.
"""

import ctypes
import ctypes.util
import time

_x11 = ctypes.cdll.LoadLibrary(ctypes.util.find_library("X11") or "libX11.so.6")
_xtst = ctypes.cdll.LoadLibrary(ctypes.util.find_library("Xtst") or "libXtst.so.6")

_dpy = None

# Common keysym → keycode mapping (populated lazily)
_keycode_cache = {}


def _display():
    global _dpy
    if _dpy is None:
        _dpy = _x11.XOpenDisplay(None)
        if not _dpy:
            raise RuntimeError("Cannot open X display")
    return _dpy


def _keysym_to_keycode(keysym):
    dpy = _display()
    if keysym not in _keycode_cache:
        kc = _x11.XKeysymToKeycode(dpy, keysym)
        _keycode_cache[keysym] = kc
    return _keycode_cache[keysym]


def _char_to_keysym(ch):
    """Convert a character to an X11 keysym."""
    # For ASCII printable, keysym == ord(ch) for most characters
    o = ord(ch)
    if 0x20 <= o <= 0x7e:
        return o
    # For common special chars
    return o


def _needs_shift(ch):
    return ch.isupper() or ch in '~!@#$%^&*()_+{}|:"<>?'


# Well-known keysyms
_KEYSYMS = {
    "Return": 0xff0d, "Tab": 0xff09, "Escape": 0xff1b,
    "BackSpace": 0xff08, "Delete": 0xffff, "space": 0x0020,
    "Shift_L": 0xffe1, "Control_L": 0xffe3, "Alt_L": 0xffe9,
    "Home": 0xff50, "End": 0xff57, "Left": 0xff51, "Right": 0xff53,
    "Up": 0xff52, "Down": 0xff54,
    "a": 0x61,
}


def press_key(keysym):
    dpy = _display()
    kc = _keysym_to_keycode(keysym)
    if kc:
        _xtst.XTestFakeKeyEvent(dpy, kc, True, 0)
        _x11.XFlush(dpy)


def release_key(keysym):
    dpy = _display()
    kc = _keysym_to_keycode(keysym)
    if kc:
        _xtst.XTestFakeKeyEvent(dpy, kc, False, 0)
        _x11.XFlush(dpy)


def tap_key(keysym, delay=0.02):
    press_key(keysym)
    time.sleep(delay)
    release_key(keysym)
    time.sleep(delay)


def type_text(text, delay=0.02):
    """Type a string character by character via XTest."""
    shift_sym = _KEYSYMS["Shift_L"]
    for ch in text:
        sym = _char_to_keysym(ch)
        if _needs_shift(ch):
            # For uppercase: send Shift+lowercase keysym
            if ch.isupper():
                sym = _char_to_keysym(ch.lower())
            press_key(shift_sym)
            time.sleep(0.01)
            tap_key(sym, delay)
            release_key(shift_sym)
            time.sleep(0.01)
        else:
            tap_key(sym, delay)


def send_key(name):
    """Send a named key (Tab, Return, Escape, etc.)."""
    if name in _KEYSYMS:
        tap_key(_KEYSYMS[name])
    elif len(name) == 1:
        type_text(name)
    elif "+" in name:
        parts = name.split("+")
        modifier_map = {"ctrl": "Control_L", "alt": "Alt_L", "shift": "Shift_L"}
        mods = [modifier_map[p.lower()] for p in parts[:-1] if p.lower() in modifier_map]
        key_part = parts[-1]
        key_sym = _char_to_keysym(key_part) if len(key_part) == 1 else _KEYSYMS.get(key_part, 0)
        for m in mods:
            press_key(_KEYSYMS[m])
            time.sleep(0.01)
        tap_key(key_sym)
        for m in reversed(mods):
            release_key(_KEYSYMS[m])
            time.sleep(0.01)
    else:
        raise ValueError("Unknown key: %s" % name)


def click(x, y, button=1):
    """Move mouse and click at (x, y).

    Uses XWarpPointer for the move (real pointer warp) + XTest for the
    button events.  GTK 4 accepts XTest button events only when the
    pointer position was set via XWarpPointer, not XTestFakeMotionEvent.
    """
    dpy = _display()
    root = _x11.XDefaultRootWindow(dpy)
    _x11.XWarpPointer(dpy, 0, root, 0, 0, 0, 0, x, y)
    _x11.XFlush(dpy)
    time.sleep(0.05)
    _xtst.XTestFakeButtonEvent(dpy, button, True, 0)
    _x11.XFlush(dpy)
    time.sleep(0.05)
    _xtst.XTestFakeButtonEvent(dpy, button, False, 0)
    _x11.XFlush(dpy)
    time.sleep(0.1)


def focus_window(x, y):
    """Give a GTK 4 window real X focus by warp+click at (x, y).

    After this, XTest keyboard events (Tab, Enter, typing) will be
    received by GTK 4. Without this initial real click, GTK 4 on X11
    ignores XTest key events.
    """
    click(x, y)
