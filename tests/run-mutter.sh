#!/bin/sh
# run-mutter.sh — run a GUI test under a headless Wayland compositor.
#
# Uses weston with the headless backend (no GPU, no display output).
# Fully isolated: private XDG_RUNTIME_DIR, private D-Bus session,
# private AT-SPI bus. Cannot capture the user's keyboard or mouse.
#
# Requires: weston, dbus-x11, at-spi2-core.

set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

if ! command -v weston >/dev/null 2>&1; then
    echo "run-mutter.sh: weston not found" >&2
    exit 77
fi

# ── Fully isolate from the host session ──
unset DISPLAY 2>/dev/null || true
unset WAYLAND_DISPLAY 2>/dev/null || true
unset DBUS_SESSION_BUS_ADDRESS 2>/dev/null || true
unset AT_SPI_BUS_ADDRESS 2>/dev/null || true

# Private runtime dir — compositor socket, D-Bus, AT-SPI all live here.
TEST_RUNTIME="$(mktemp -d -t gnomint-test-runtime.XXXXXX)"
chmod 700 "$TEST_RUNTIME"
export XDG_RUNTIME_DIR="$TEST_RUNTIME"

WAYLAND_DISPLAY="wayland-test"
export WAYLAND_DISPLAY
export GDK_BACKEND=wayland
export GTK_A11Y=atspi

WESTON_LOG="$TEST_RUNTIME/weston.log"

weston \
    --backend=headless-backend.so \
    --socket="$WAYLAND_DISPLAY" \
    --idle-time=0 \
    > "$WESTON_LOG" 2>&1 &
COMPOSITOR_PID=$!

cleanup() {
    rc=$?
    kill "$COMPOSITOR_PID" 2>/dev/null || true
    wait "$COMPOSITOR_PID" 2>/dev/null || true
    if [ "$rc" != 0 ] && [ -f "$WESTON_LOG" ]; then
        echo "--- weston log ---" >&2
        tail -20 "$WESTON_LOG" >&2
        echo "--- end weston log ---" >&2
    fi
    rm -rf "$TEST_RUNTIME"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# Wait for the Wayland socket.
i=0
while [ $i -lt 50 ] && [ ! -S "$TEST_RUNTIME/$WAYLAND_DISPLAY" ]; do
    sleep 0.1
    i=$((i + 1))
done
if [ ! -S "$TEST_RUNTIME/$WAYLAND_DISPLAY" ]; then
    echo "run-mutter.sh: compositor socket never appeared" >&2
    exit 1
fi

sleep 1

# Private D-Bus session + AT-SPI bus.
eval $(dbus-launch --sh-syntax)
/usr/libexec/at-spi-bus-launcher --launch-immediately >/dev/null 2>&1 &
sleep 1

"$@"
rc=$?

kill "$DBUS_SESSION_BUS_PID" 2>/dev/null || true
exit "$rc"
