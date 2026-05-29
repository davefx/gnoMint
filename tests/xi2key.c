/*
 * xi2key — Send keyboard events through XInput2 via the XTest extension.
 *
 * Regular XTestFakeKeyEvent sends events through the core protocol
 * (deviceid=0) which GTK 4 ignores for navigation keys. This tool
 * uses xcb_test_fake_input with the master keyboard's device ID,
 * causing the X server to deliver XI2 key events that GTK 4 processes.
 *
 * Usage:
 *   xi2key Tab            # Press and release Tab
 *   xi2key space          # Press and release Space
 *   xi2key Return         # Press and release Return
 *   xi2key Escape         # Press and release Escape
 *   xi2key type hello     # Type "hello" character by character
 *   xi2key press Tab      # Press Tab (no release)
 *   xi2key release Tab    # Release Tab
 *
 * Build:
 *   gcc -o xi2key xi2key.c $(pkg-config --cflags --libs xcb xcb-xtest xcb-xinput)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xcb/xcb.h>
#include <xcb/xtest.h>
#include <xcb/xinput.h>
#include <X11/Xlib.h>
#include <X11/Xlib-xcb.h>
#include <X11/keysym.h>

/* XCB event types for XTest fake_input */
#define KEY_PRESS   2
#define KEY_RELEASE 3

static Display *xdpy;
static xcb_connection_t *conn;
static uint8_t master_kbd_id;

static void init(void) {
    xdpy = XOpenDisplay(NULL);
    if (!xdpy) {
        fprintf(stderr, "xi2key: cannot open display\n");
        exit(1);
    }
    conn = XGetXCBConnection(xdpy);

    /* Find master keyboard device ID.
     * We query XI2 devices and look for the master keyboard. */
    xcb_input_xi_query_device_cookie_t cookie =
        xcb_input_xi_query_device(conn, XCB_INPUT_DEVICE_ALL);
    xcb_input_xi_query_device_reply_t *reply =
        xcb_input_xi_query_device_reply(conn, cookie, NULL);

    if (reply) {
        xcb_input_xi_device_info_iterator_t iter =
            xcb_input_xi_query_device_infos_iterator(reply);
        while (iter.rem) {
            xcb_input_xi_device_info_t *info = iter.data;
            if (info->type == XCB_INPUT_DEVICE_TYPE_MASTER_KEYBOARD) {
                master_kbd_id = info->deviceid;
                break;
            }
            xcb_input_xi_device_info_next(&iter);
        }
        free(reply);
    }

    if (master_kbd_id == 0) {
        master_kbd_id = 3;
    }
    if (getenv("XI2KEY_VERBOSE"))
        fprintf(stderr, "xi2key: master keyboard device ID = %d\n", master_kbd_id);
}

static void send_key(uint8_t keycode, int press) {
    xcb_test_fake_input(conn,
        press ? KEY_PRESS : KEY_RELEASE,
        keycode,
        XCB_CURRENT_TIME,
        XCB_WINDOW_NONE,  /* root window */
        0, 0,             /* x, y (unused for keys) */
        master_kbd_id);   /* THIS IS THE KEY: device ID */
    xcb_flush(conn);
}

static void tap_key(uint8_t keycode) {
    send_key(keycode, 1);
    usleep(20000);
    send_key(keycode, 0);
    usleep(20000);
}

static KeyCode sym_to_code(KeySym sym) {
    return XKeysymToKeycode(xdpy, sym);
}

/* Map key names to keysyms */
static KeySym name_to_sym(const char *name) {
    if (!strcmp(name, "Tab")) return XK_Tab;
    if (!strcmp(name, "Return") || !strcmp(name, "Enter")) return XK_Return;
    if (!strcmp(name, "space")) return XK_space;
    if (!strcmp(name, "Escape")) return XK_Escape;
    if (!strcmp(name, "BackSpace")) return XK_BackSpace;
    if (!strcmp(name, "Delete")) return XK_Delete;
    if (!strcmp(name, "Up")) return XK_Up;
    if (!strcmp(name, "Down")) return XK_Down;
    if (!strcmp(name, "Left")) return XK_Left;
    if (!strcmp(name, "Right")) return XK_Right;
    if (!strcmp(name, "Home")) return XK_Home;
    if (!strcmp(name, "End")) return XK_End;
    if (!strcmp(name, "Shift_L")) return XK_Shift_L;
    if (!strcmp(name, "Control_L")) return XK_Control_L;
    if (!strcmp(name, "Alt_L")) return XK_Alt_L;
    if (!strcmp(name, "F1")) return XK_F1;
    if (!strcmp(name, "F6")) return XK_F6;
    if (!strcmp(name, "F10")) return XK_F10;
    /* Single character */
    if (strlen(name) == 1) return (KeySym) name[0];
    /* Try XStringToKeysym */
    KeySym s = XStringToKeysym(name);
    if (s != NoSymbol) return s;
    fprintf(stderr, "xi2key: unknown key '%s'\n", name);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: xi2key <keyname> | type <text> | press <key> | release <key>\n");
        return 1;
    }

    init();

    if (!strcmp(argv[1], "type") && argc > 2) {
        /* Type a string character by character */
        const char *text = argv[2];
        KeyCode shift_kc = sym_to_code(XK_Shift_L);
        for (int i = 0; text[i]; i++) {
            char ch = text[i];
            int need_shift = (ch >= 'A' && ch <= 'Z') ||
                             strchr("~!@#$%^&*()_+{}|:\"<>?", ch);
            KeySym sym;
            if (need_shift && ch >= 'A' && ch <= 'Z')
                sym = (KeySym) (ch - 'A' + 'a');
            else
                sym = (KeySym) ch;
            KeyCode kc = sym_to_code(sym);
            if (!kc) continue;
            if (need_shift) send_key(shift_kc, 1);
            tap_key(kc);
            if (need_shift) send_key(shift_kc, 0);
            usleep(10000);
        }
    } else if (!strcmp(argv[1], "press") && argc > 2) {
        KeySym sym = name_to_sym(argv[2]);
        send_key(sym_to_code(sym), 1);
    } else if (!strcmp(argv[1], "release") && argc > 2) {
        KeySym sym = name_to_sym(argv[2]);
        send_key(sym_to_code(sym), 0);
    } else {
        /* Single key tap */
        KeySym sym = name_to_sym(argv[1]);
        tap_key(sym_to_code(sym));
    }

    XCloseDisplay(xdpy);
    return 0;
}
