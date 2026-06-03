#!/bin/sh
# run-xdummy.sh — run a GUI test under Xorg + xf86-video-dummy + inputtest.
#
# Uses the dummy video driver for output and the inputtest driver for
# keyboard/pointer input. The inputtest driver creates proper XI2 slave
# devices that accept events through Unix sockets, providing the real
# input pipeline that GTK 4 requires for keyboard navigation.
#
# Exports INPUTTEST_KBD_SOCK and INPUTTEST_PTR_SOCK so the test
# binary can inject events through the inputtest protocol.
#
# Requires: xserver-xorg-core (provides both dummy and inputtest
#           drivers), dbus-x11, openbox (optional).

set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Use the real Xorg binary, bypassing Xorg.wrap's console-user check.
if [ -x /usr/lib/xorg/Xorg ]; then
    XORG_BIN=/usr/lib/xorg/Xorg
elif [ -x /usr/libexec/Xorg ]; then
    XORG_BIN=/usr/libexec/Xorg
else
    XORG_BIN=Xorg
fi

XDISPLAY=:$(( ($$ % 100) + 50 ))
DISPLAY_NUM="${XDISPLAY#:}"
rm -f "/tmp/.X${DISPLAY_NUM}-lock" 2>/dev/null || true

XORG_LOG="/tmp/Xorg-gnomint-test-$$.log"

# Per-run socket paths for the inputtest driver.
INPUTTEST_KBD_SOCK="/tmp/gnomint-test-kbd-$$.sock"
INPUTTEST_PTR_SOCK="/tmp/gnomint-test-ptr-$$.sock"
export INPUTTEST_KBD_SOCK INPUTTEST_PTR_SOCK

# Generate a per-run xorg.conf with unique socket paths.
XORG_CONF="/tmp/xorg-dummy-$$.conf"
sed \
    -e "s|/tmp/gnomint-test-kbd.sock|$INPUTTEST_KBD_SOCK|" \
    -e "s|/tmp/gnomint-test-ptr.sock|$INPUTTEST_PTR_SOCK|" \
    "$SCRIPT_DIR/xorg-dummy.conf" > "$XORG_CONF"

rm -f "$INPUTTEST_KBD_SOCK" "$INPUTTEST_PTR_SOCK" 2>/dev/null || true

"$XORG_BIN" "$XDISPLAY" \
    -noreset \
    -nolisten tcp \
    -config "$XORG_CONF" \
    -logfile "$XORG_LOG" \
    >/dev/null 2>&1 &
XORG_PID=$!

cleanup() {
    rc=$?
    kill "$XORG_PID" 2>/dev/null || true
    wait "$XORG_PID" 2>/dev/null || true
    if [ "$rc" != 0 ] && [ -f "$XORG_LOG" ]; then
        echo "--- Xorg log ---" >&2
        tail -40 "$XORG_LOG" >&2
        echo "--- end Xorg log ---" >&2
    fi
    rm -f "$XORG_LOG" "$XORG_CONF"
    rm -f "$INPUTTEST_KBD_SOCK" "$INPUTTEST_PTR_SOCK" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT INT TERM

i=0
while [ $i -lt 50 ]; do
    DISPLAY="$XDISPLAY" xdpyinfo >/dev/null 2>&1 && break
    sleep 0.1
    i=$((i + 1))
done

if ! DISPLAY="$XDISPLAY" xdpyinfo >/dev/null 2>&1; then
    echo "run-xdummy.sh: Xorg never became ready on $XDISPLAY" >&2
    if [ -f "$XORG_LOG" ]; then
        echo "--- Xorg log ---" >&2
        tail -40 "$XORG_LOG" >&2
        echo "--- end Xorg log ---" >&2
    fi
    exit 1
fi

export DISPLAY="$XDISPLAY"
export GDK_BACKEND=x11
export GTK_A11Y=atspi

eval $(dbus-launch --sh-syntax)
if command -v openbox >/dev/null 2>&1; then
    openbox --config-file "$SCRIPT_DIR/openbox-rc.xml" >/dev/null 2>&1 &
    TESTWM_PID=$!
else
    python3 "$SCRIPT_DIR/testwm.py" &
    TESTWM_PID=$!
fi
sleep 1
/usr/libexec/at-spi-bus-launcher --launch-immediately >/dev/null 2>&1 &
sleep 1

"$@"
rc=$?

kill "$TESTWM_PID" 2>/dev/null || true
kill "$DBUS_SESSION_BUS_PID" 2>/dev/null || true
exit "$rc"
