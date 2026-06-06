#!/bin/sh
# run-mutter.sh — run a GUI test under mutter headless Wayland.
#
# Fully isolated: private XDG_RUNTIME_DIR, private Wayland display,
# private D-Bus session. No connection to the host's compositor,
# display server, or accessibility bus. The test cannot capture
# the user's keyboard or mouse.
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

# ── Fully isolate from the host session ──
unset DISPLAY 2>/dev/null || true
unset WAYLAND_DISPLAY 2>/dev/null || true
unset DBUS_SESSION_BUS_ADDRESS 2>/dev/null || true
unset AT_SPI_BUS_ADDRESS 2>/dev/null || true

# Private XDG_RUNTIME_DIR so mutter's socket, D-Bus, and AT-SPI
# are completely separate from the host session.
TEST_RUNTIME="$(mktemp -d -t gnomint-test-runtime.XXXXXX)"
chmod 700 "$TEST_RUNTIME"
export XDG_RUNTIME_DIR="$TEST_RUNTIME"

WAYLAND_DISPLAY="wayland-0"
export WAYLAND_DISPLAY
export GDK_BACKEND=wayland
export GTK_A11Y=atspi

MUTTER_LOG="$TEST_RUNTIME/mutter.log"

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
    rm -rf "$TEST_RUNTIME"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# Wait for mutter's Wayland socket.
i=0
while [ $i -lt 50 ] && [ ! -S "$TEST_RUNTIME/$WAYLAND_DISPLAY" ]; do
    sleep 0.1
    i=$((i + 1))
done
if [ ! -S "$TEST_RUNTIME/$WAYLAND_DISPLAY" ]; then
    echo "run-mutter.sh: mutter socket never appeared" >&2
    exit 1
fi

sleep 1

# Private D-Bus session.
eval $(dbus-launch --sh-syntax)
/usr/libexec/at-spi-bus-launcher --launch-immediately >/dev/null 2>&1 &
sleep 1

"$@"
rc=$?

kill "$DBUS_SESSION_BUS_PID" 2>/dev/null || true
exit "$rc"
