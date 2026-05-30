"""
inputtest_client.py — Client for the Xorg inputtest driver socket protocol.

Sends keyboard and pointer events through the inputtest driver's Unix
socket. Events injected this way go through the full Xorg input pipeline
and appear as genuine XI2 events, which GTK 4 processes correctly.

Protocol reference: xf86-input-inputtest-protocol.h from xserver source.
"""

import os
import socket
import struct
import time

# Protocol version
_PROTOCOL_MAJOR = 1
_PROTOCOL_MINOR = 1

# Event types (client → driver)
_EVENT_CLIENT_VERSION = 0
_EVENT_WAIT_FOR_SYNC = 1
_EVENT_MOTION = 2
_EVENT_BUTTON = 4
_EVENT_KEY = 5

# XF86IT_MAX_VALUATORS = 64.  The C struct xf86ITValuatorData has
# padding between mask[8] and double valuators[64] for alignment:
#   uint32_t has_unaccelerated (4) + uint8_t mask[8] (8) + pad(4)
#   + double valuators[64] (512) + double unaccelerated[64] (512) = 1040
_MAX_VALUATORS = 64
_VALUATOR_MASK_BYTES = (_MAX_VALUATORS + 7) // 8  # 8
_VALUATOR_DATA_SIZE = 1040  # sizeof(xf86ITValuatorData) on x86-64

# Response types (driver → client)
_RESPONSE_SERVER_VERSION = 0
_RESPONSE_SYNC_FINISHED = 1


class InputTestClient:
    def __init__(self, socket_path, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(socket_path):
                break
            time.sleep(0.1)

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(timeout)
        self._sock.connect(socket_path)
        self._handshake()

    def _send(self, data):
        self._sock.sendall(data)

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("inputtest socket closed")
            buf += chunk
        return buf

    def _handshake(self):
        # xf86ITEventClientVersion: header(8) + major(2) + minor(2) = 12
        msg = struct.pack("=IiHH", 12, _EVENT_CLIENT_VERSION,
                          _PROTOCOL_MAJOR, _PROTOCOL_MINOR)
        self._send(msg)

        # xf86ITResponseServerVersion: header(8) + major(2) + minor(2) = 12
        resp = self._recv(12)
        length, rtype, major, minor = struct.unpack("=IiHH", resp)
        if rtype != _RESPONSE_SERVER_VERSION:
            raise RuntimeError("unexpected response type %d" % rtype)
        if major < _PROTOCOL_MAJOR:
            raise RuntimeError("server protocol %d.%d < required %d.%d"
                               % (major, minor, _PROTOCOL_MAJOR,
                                  _PROTOCOL_MINOR))

    def key_event(self, keycode, press=True):
        """Send a key press or release. keycode is an X11 keycode (evdev + 8)."""
        # xf86ITEventKey: header(8) + key_code(4) + is_press(4) = 16
        msg = struct.pack("=IiiI", 16, _EVENT_KEY, keycode,
                          1 if press else 0)
        self._send(msg)

    def key_tap(self, keycode, delay=0.02):
        """Press and release a key."""
        self.key_event(keycode, press=True)
        time.sleep(delay)
        self.key_event(keycode, press=False)
        time.sleep(delay)

    def sync(self):
        """Wait for the server to process all pending events."""
        msg = struct.pack("=Ii", 8, _EVENT_WAIT_FOR_SYNC)
        self._send(msg)
        resp = self._recv(8)
        length, rtype = struct.unpack("=Ii", resp)
        if rtype != _RESPONSE_SYNC_FINISHED:
            raise RuntimeError("expected sync response, got %d" % rtype)

    @staticmethod
    def _build_valuator_data(vals=None):
        """Build an xf86ITValuatorData blob (1040 bytes, matching C layout).

        C layout on x86-64:
          uint32_t has_unaccelerated  (4)
          uint8_t  mask[8]            (8)
          <4 bytes padding>           (4)  — align double to 8
          double   valuators[64]      (512)
          double   unaccelerated[64]  (512)
          Total: 1040
        """
        has_unaccel = 0
        mask = bytearray(_VALUATOR_MASK_BYTES)
        valuators = bytearray(_MAX_VALUATORS * 8)
        if vals:
            for idx, val in vals.items():
                mask[idx // 8] |= (1 << (idx % 8))
                struct.pack_into("=d", valuators, idx * 8, float(val))
        pad4 = b"\x00" * 4
        return (struct.pack("=I", has_unaccel) + bytes(mask) + pad4 +
                bytes(valuators) + bytearray(_MAX_VALUATORS * 8))

    def motion(self, x, y, absolute=True):
        """Send a pointer motion event (xf86ITEventMotion, 1056 bytes)."""
        vdata = self._build_valuator_data({0: x, 1: y})
        # header(8) + is_absolute(4) + pad(4) + valuator_data(1040) = 1056
        length = 8 + 4 + 4 + len(vdata)
        header = struct.pack("=Ii", length, _EVENT_MOTION)
        body = struct.pack("=I", 1 if absolute else 0)
        pad4 = b"\x00" * 4
        self._send(header + body + pad4 + vdata)

    def button(self, btn, press, absolute=False):
        """Send a pointer button event (xf86ITEventButton, 1064 bytes)."""
        vdata = self._build_valuator_data()
        # header(8) + is_absolute(4) + button(4) + is_press(4)
        # + pad(4) + valuator_data(1040) = 1064
        length = 8 + 4 + 4 + 4 + 4 + len(vdata)
        header = struct.pack("=Ii", length, _EVENT_BUTTON)
        body = struct.pack("=iiI", 1 if absolute else 0, btn,
                           1 if press else 0)
        pad4 = b"\x00" * 4
        self._send(header + body + pad4 + vdata)

    def click(self, x, y, btn=1):
        """Move pointer and click at (x, y)."""
        self.motion(x, y, absolute=True)
        time.sleep(0.05)
        self.button(btn, press=True, absolute=True)
        time.sleep(0.05)
        self.button(btn, press=False, absolute=True)
        time.sleep(0.1)

    def close(self):
        self._sock.close()


# X11 keycodes = Linux evdev keycodes + 8.  The inputtest driver's
# xf86PostKeyboardEvent expects X11 keycodes.
_EVDEV_OFFSET = 8

KEY_ESC = 1 + _EVDEV_OFFSET
KEY_1 = 2 + _EVDEV_OFFSET
KEY_2 = 3 + _EVDEV_OFFSET
KEY_3 = 4 + _EVDEV_OFFSET
KEY_4 = 5 + _EVDEV_OFFSET
KEY_5 = 6 + _EVDEV_OFFSET
KEY_6 = 7 + _EVDEV_OFFSET
KEY_7 = 8 + _EVDEV_OFFSET
KEY_8 = 9 + _EVDEV_OFFSET
KEY_9 = 10 + _EVDEV_OFFSET
KEY_0 = 11 + _EVDEV_OFFSET
KEY_MINUS = 12 + _EVDEV_OFFSET
KEY_EQUAL = 13 + _EVDEV_OFFSET
KEY_BACKSPACE = 14 + _EVDEV_OFFSET
KEY_TAB = 15 + _EVDEV_OFFSET
KEY_Q = 16 + _EVDEV_OFFSET
KEY_W = 17 + _EVDEV_OFFSET
KEY_E = 18 + _EVDEV_OFFSET
KEY_R = 19 + _EVDEV_OFFSET
KEY_T = 20 + _EVDEV_OFFSET
KEY_Y = 21 + _EVDEV_OFFSET
KEY_U = 22 + _EVDEV_OFFSET
KEY_I = 23 + _EVDEV_OFFSET
KEY_O = 24 + _EVDEV_OFFSET
KEY_P = 25 + _EVDEV_OFFSET
KEY_LEFTBRACE = 26 + _EVDEV_OFFSET
KEY_RIGHTBRACE = 27 + _EVDEV_OFFSET
KEY_ENTER = 28 + _EVDEV_OFFSET
KEY_LEFTCTRL = 29 + _EVDEV_OFFSET
KEY_A = 30 + _EVDEV_OFFSET
KEY_S = 31 + _EVDEV_OFFSET
KEY_D = 32 + _EVDEV_OFFSET
KEY_F = 33 + _EVDEV_OFFSET
KEY_G = 34 + _EVDEV_OFFSET
KEY_H = 35 + _EVDEV_OFFSET
KEY_J = 36 + _EVDEV_OFFSET
KEY_K = 37 + _EVDEV_OFFSET
KEY_L = 38 + _EVDEV_OFFSET
KEY_SEMICOLON = 39 + _EVDEV_OFFSET
KEY_APOSTROPHE = 40 + _EVDEV_OFFSET
KEY_GRAVE = 41 + _EVDEV_OFFSET
KEY_LEFTSHIFT = 42 + _EVDEV_OFFSET
KEY_BACKSLASH = 43 + _EVDEV_OFFSET
KEY_Z = 44 + _EVDEV_OFFSET
KEY_X = 45 + _EVDEV_OFFSET
KEY_C = 46 + _EVDEV_OFFSET
KEY_V = 47 + _EVDEV_OFFSET
KEY_B = 48 + _EVDEV_OFFSET
KEY_N = 49 + _EVDEV_OFFSET
KEY_M = 50 + _EVDEV_OFFSET
KEY_COMMA = 51 + _EVDEV_OFFSET
KEY_DOT = 52 + _EVDEV_OFFSET
KEY_SLASH = 53 + _EVDEV_OFFSET
KEY_RIGHTSHIFT = 54 + _EVDEV_OFFSET
KEY_LEFTALT = 56 + _EVDEV_OFFSET
KEY_SPACE = 57 + _EVDEV_OFFSET
KEY_CAPSLOCK = 58 + _EVDEV_OFFSET
KEY_F1 = 59 + _EVDEV_OFFSET
KEY_F6 = 64 + _EVDEV_OFFSET
KEY_F10 = 68 + _EVDEV_OFFSET
KEY_UP = 103 + _EVDEV_OFFSET
KEY_LEFT = 105 + _EVDEV_OFFSET
KEY_RIGHT = 106 + _EVDEV_OFFSET
KEY_DOWN = 108 + _EVDEV_OFFSET
KEY_HOME = 102 + _EVDEV_OFFSET
KEY_END = 107 + _EVDEV_OFFSET
KEY_DELETE = 111 + _EVDEV_OFFSET

_CHAR_TO_KEYCODE = {
    'a': KEY_A, 'b': KEY_B, 'c': KEY_C, 'd': KEY_D, 'e': KEY_E,
    'f': KEY_F, 'g': KEY_G, 'h': KEY_H, 'i': KEY_I, 'j': KEY_J,
    'k': KEY_K, 'l': KEY_L, 'm': KEY_M, 'n': KEY_N, 'o': KEY_O,
    'p': KEY_P, 'q': KEY_Q, 'r': KEY_R, 's': KEY_S, 't': KEY_T,
    'u': KEY_U, 'v': KEY_V, 'w': KEY_W, 'x': KEY_X, 'y': KEY_Y,
    'z': KEY_Z,
    '1': KEY_1, '2': KEY_2, '3': KEY_3, '4': KEY_4, '5': KEY_5,
    '6': KEY_6, '7': KEY_7, '8': KEY_8, '9': KEY_9, '0': KEY_0,
    ' ': KEY_SPACE, '-': KEY_MINUS, '=': KEY_EQUAL,
    '[': KEY_LEFTBRACE, ']': KEY_RIGHTBRACE, '\\': KEY_BACKSLASH,
    ';': KEY_SEMICOLON, "'": KEY_APOSTROPHE, '`': KEY_GRAVE,
    ',': KEY_COMMA, '.': KEY_DOT, '/': KEY_SLASH,
}

_SHIFTED_CHARS = {
    'A': 'a', 'B': 'b', 'C': 'c', 'D': 'd', 'E': 'e',
    'F': 'f', 'G': 'g', 'H': 'h', 'I': 'i', 'J': 'j',
    'K': 'k', 'L': 'l', 'M': 'm', 'N': 'n', 'O': 'o',
    'P': 'p', 'Q': 'q', 'R': 'r', 'S': 's', 'T': 't',
    'U': 'u', 'V': 'v', 'W': 'w', 'X': 'x', 'Y': 'y',
    'Z': 'z',
}

_NAME_TO_KEYCODE = {
    'Tab': KEY_TAB, 'Return': KEY_ENTER, 'Enter': KEY_ENTER,
    'space': KEY_SPACE, 'Escape': KEY_ESC, 'BackSpace': KEY_BACKSPACE,
    'Delete': KEY_DELETE, 'Up': KEY_UP, 'Down': KEY_DOWN,
    'Left': KEY_LEFT, 'Right': KEY_RIGHT, 'Home': KEY_HOME,
    'End': KEY_END, 'F1': KEY_F1, 'F6': KEY_F6, 'F10': KEY_F10,
    'Shift_L': KEY_LEFTSHIFT, 'Control_L': KEY_LEFTCTRL,
    'Alt_L': KEY_LEFTALT,
}


def type_text(client, text, delay=0.02):
    """Type a string character by character through the inputtest driver."""
    for ch in text:
        if ch in _SHIFTED_CHARS:
            client.key_event(KEY_LEFTSHIFT, press=True)
            time.sleep(0.01)
            client.key_tap(_CHAR_TO_KEYCODE[_SHIFTED_CHARS[ch]], delay)
            client.key_event(KEY_LEFTSHIFT, press=False)
            time.sleep(0.01)
        elif ch in _CHAR_TO_KEYCODE:
            client.key_tap(_CHAR_TO_KEYCODE[ch], delay)
        else:
            pass


def send_key(client, name, delay=0.03):
    """Send a named key (Tab, Return, space, etc.)."""
    if name in _NAME_TO_KEYCODE:
        client.key_tap(_NAME_TO_KEYCODE[name], delay)
    elif len(name) == 1 and name in _CHAR_TO_KEYCODE:
        client.key_tap(_CHAR_TO_KEYCODE[name], delay)
    else:
        raise ValueError("Unknown key: %s" % name)
