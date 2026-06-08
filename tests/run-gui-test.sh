#!/bin/sh
# run-gui-test.sh — run a GUI test under a fully isolated headless
# Wayland compositor with its own D-Bus and AT-SPI bus.
#
# Uses weston --backend=headless-backend.so — no GPU, no display
# output, no input capture. Private XDG_RUNTIME_DIR ensures nothing
# touches the host desktop.
#
# Requires: weston, dbus-x11, at-spi2-core.

set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

if ! command -v weston >/dev/null 2>&1; then
    echo "run-gui-test.sh: weston not found" >&2
    exit 77
fi

# ── Isolate from the host session ──
unset DISPLAY 2>/dev/null || true
unset WAYLAND_DISPLAY 2>/dev/null || true
unset DBUS_SESSION_BUS_ADDRESS 2>/dev/null || true
unset AT_SPI_BUS_ADDRESS 2>/dev/null || true
unset GNOME_SETUP_DISPLAY 2>/dev/null || true

TEST_RUNTIME="$(mktemp -d -t gnomint-test-runtime.XXXXXX)"
chmod 700 "$TEST_RUNTIME"
export XDG_RUNTIME_DIR="$TEST_RUNTIME"
export WAYLAND_DISPLAY="wayland-test"
export GDK_BACKEND=wayland
export GSK_RENDERER=cairo
export GTK_A11Y=atspi

PIDS=""

add_pid() { PIDS="$PIDS $1"; }

cleanup() {
    rc=$?
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    # D-Bus services (gvfs, portal) may have FUSE-mounted inside the
    # runtime dir. Unmount before removing.
    fusermount -uz "$TEST_RUNTIME/gvfs" 2>/dev/null || true
    fusermount -uz "$TEST_RUNTIME/doc" 2>/dev/null || true
    rm -rf "$TEST_RUNTIME" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ── Start headless compositor ──
weston \
    --backend=headless-backend.so \
    --socket="$WAYLAND_DISPLAY" \
    --idle-time=0 \
    > "$TEST_RUNTIME/weston.log" 2>&1 &
add_pid $!

# Wait for compositor socket.
i=0
while [ $i -lt 50 ] && [ ! -S "$TEST_RUNTIME/$WAYLAND_DISPLAY" ]; do
    sleep 0.1
    i=$((i + 1))
done
if [ ! -S "$TEST_RUNTIME/$WAYLAND_DISPLAY" ]; then
    echo "run-gui-test.sh: weston socket never appeared" >&2
    cat "$TEST_RUNTIME/weston.log" >&2
    exit 1
fi

# ── Private D-Bus + AT-SPI ──
eval $(dbus-launch --sh-syntax)
export DBUS_SESSION_BUS_ADDRESS
add_pid "$DBUS_SESSION_BUS_PID"

/usr/libexec/at-spi-bus-launcher --launch-immediately >/dev/null 2>&1 &
add_pid $!
sleep 1

"$@"
rc=$?
exit "$rc"
