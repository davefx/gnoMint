#!/bin/sh
# run-mutter.sh — run a GUI test under a fully isolated headless Wayland
# compositor with its own D-Bus and AT-SPI bus.
#
# Fully isolated: private XDG_RUNTIME_DIR, private D-Bus, private AT-SPI.
# Uses weston --backend=headless-backend.so — no GPU, no display output,
# no input capture. Cannot interact with the host desktop.
#
# All child processes (weston, dbus-daemon, at-spi-bus-launcher,
# at-spi2-registryd, gnomint) are killed on exit via process group.
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
unset GNOME_SETUP_DISPLAY 2>/dev/null || true

# Private runtime dir.
TEST_RUNTIME="$(mktemp -d -t gnomint-test-runtime.XXXXXX)"
chmod 700 "$TEST_RUNTIME"
export XDG_RUNTIME_DIR="$TEST_RUNTIME"

WAYLAND_DISPLAY="wayland-test"
export WAYLAND_DISPLAY
export GDK_BACKEND=wayland
export GTK_A11Y=atspi

WESTON_LOG="$TEST_RUNTIME/weston.log"
PIDS_FILE="$TEST_RUNTIME/pids"
: > "$PIDS_FILE"

weston \
    --backend=headless-backend.so \
    --socket="$WAYLAND_DISPLAY" \
    --idle-time=0 \
    > "$WESTON_LOG" 2>&1 &
echo $! >> "$PIDS_FILE"

cleanup() {
    rc=$?
    # Kill every process we started.
    while read pid; do
        kill "$pid" 2>/dev/null || true
    done < "$PIDS_FILE"
    # Also kill any at-spi processes in our private runtime dir.
    pgrep -f "$TEST_RUNTIME" 2>/dev/null | while read pid; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
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

# Private D-Bus session.
eval $(dbus-launch --sh-syntax)
export DBUS_SESSION_BUS_ADDRESS
echo "$DBUS_SESSION_BUS_PID" >> "$PIDS_FILE"

# Private AT-SPI bus.
/usr/libexec/at-spi-bus-launcher --launch-immediately >/dev/null 2>&1 &
echo $! >> "$PIDS_FILE"
sleep 1

"$@"
rc=$?
exit "$rc"
