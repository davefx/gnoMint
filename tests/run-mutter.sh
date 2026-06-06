#!/bin/sh
# run-mutter.sh — run a GUI test under mutter headless Wayland.
#
# Uses mutter as a headless Wayland compositor. AT-SPI button
# activation works correctly on mutter (no X11 focus proxy issues),
# making this the preferred runner for the full GUI test suite.
#
# Requires: mutter, dbus-x11, at-spi2-core.

set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

if ! command -v mutter >/dev/null 2>&1; then
    echo "run-mutter.sh: mutter not found" >&2
    exit 77
fi

# Each run gets its own Wayland display name.
WAYLAND_DISPLAY="gnomint-test-$$"
export WAYLAND_DISPLAY
export GDK_BACKEND=wayland
export GTK_A11Y=atspi

MUTTER_LOG="/tmp/mutter-gnomint-test-$$.log"

mutter --headless \
    --virtual-monitor 1280x1024 \
    --wayland \
    --no-x11 \
    --wayland-display="$WAYLAND_DISPLAY" \
    > "$MUTTER_LOG" 2>&1 &
MUTTER_PID=$!

cleanup() {
    rc=$?
    kill "$MUTTER_PID" 2>/dev/null || true
    wait "$MUTTER_PID" 2>/dev/null || true
    if [ "$rc" != 0 ] && [ -f "$MUTTER_LOG" ]; then
        echo "--- mutter log ---" >&2
        tail -20 "$MUTTER_LOG" >&2
        echo "--- end mutter log ---" >&2
    fi
    rm -f "$MUTTER_LOG"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# Wait for mutter's Wayland socket.
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
i=0
while [ $i -lt 50 ] && [ ! -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]; do
    sleep 0.1
    i=$((i + 1))
done
if [ ! -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]; then
    echo "run-mutter.sh: mutter socket never appeared" >&2
    exit 1
fi

# Extra settle time for mutter to fully initialize.
sleep 1

eval $(dbus-launch --sh-syntax)
/usr/libexec/at-spi-bus-launcher --launch-immediately >/dev/null 2>&1 &
sleep 1

"$@"
rc=$?

kill "$DBUS_SESSION_BUS_PID" 2>/dev/null || true
exit "$rc"
