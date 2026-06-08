#!/bin/sh
# run-headless.sh — run a GTK test binary under a headless Wayland compositor.
#
# Used as automake's check_workflows_LOG_COMPILER. Spawns weston with the
# headless backend on a unique socket, exports GDK_BACKEND=wayland +
# WAYLAND_DISPLAY pointing at that socket, runs the supplied binary, and
# tears weston down regardless of test outcome. The test's exit code is
# propagated.
#
# Wayland is gnomint's primary user environment, so the workflow regression
# tests exercise GTK's Wayland backend rather than X11.

set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 <test-binary> [args...]" >&2
    exit 2
fi

# weston needs an XDG_RUNTIME_DIR with 0700 perms to put its socket in.
if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
    XDG_RUNTIME_DIR="$(mktemp -d -t gnomint-test-runtime.XXXXXX)"
    export XDG_RUNTIME_DIR
    chmod 700 "$XDG_RUNTIME_DIR"
    CLEAN_RUNTIME_DIR=1
else
    CLEAN_RUNTIME_DIR=0
fi

WAYLAND_DISPLAY="gnomint-test-$$"
export WAYLAND_DISPLAY
export GDK_BACKEND=wayland
export GSK_RENDERER=cairo

WESTON_LOG="$XDG_RUNTIME_DIR/weston-$$.log"

# Start weston in headless mode. --shell=desktop-shell.so is the default;
# --idle-time=0 prevents weston from quitting under inactivity (it is
# headless so there are no input events at all).
weston \
    --backend=headless-backend.so \
    --socket="$WAYLAND_DISPLAY" \
    --idle-time=0 \
    > "$WESTON_LOG" 2>&1 &
WESTON_PID=$!

cleanup() {
    rc=$?
    if kill -0 "$WESTON_PID" 2>/dev/null; then
        kill "$WESTON_PID" 2>/dev/null || true
        wait "$WESTON_PID" 2>/dev/null || true
    fi
    if [ "$CLEAN_RUNTIME_DIR" = 1 ]; then
        rm -rf "$XDG_RUNTIME_DIR"
    fi
    # Surface weston's own log on test failure to help diagnose.
    if [ "$rc" != 0 ] && [ -f "$WESTON_LOG" ]; then
        echo "--- weston log ---" >&2
        cat "$WESTON_LOG" >&2
        echo "--- end weston log ---" >&2
    fi
    rm -f "$WESTON_LOG"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# Wait for weston's socket to appear (it's async). The lock file is created
# alongside the socket once weston is ready to accept connections.
i=0
while [ $i -lt 50 ] && [ ! -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]; do
    sleep 0.1
    i=$((i + 1))
done
if [ ! -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]; then
    echo "run-headless.sh: weston socket never appeared at " \
         "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" >&2
    exit 1
fi

# Hand off to the actual test binary. Its exit code becomes ours.
"$@"
