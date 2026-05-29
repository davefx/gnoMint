#!/bin/sh
# run-xvfb.sh — run a GUI test under Xvfb with AT-SPI accessibility.

set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

XDISPLAY=:$(( ($$ % 100) + 50 ))
rm -f "/tmp/.X${XDISPLAY#:}-lock" 2>/dev/null || true

Xvfb "$XDISPLAY" -screen 0 1280x1024x24 -ac >/dev/null 2>&1 &
XVFB_PID=$!

cleanup() {
    rc=$?
    kill "$XVFB_PID" 2>/dev/null || true
    wait "$XVFB_PID" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT INT TERM

i=0
while [ $i -lt 50 ]; do
    DISPLAY="$XDISPLAY" xdpyinfo >/dev/null 2>&1 && break
    sleep 0.1
    i=$((i + 1))
done

export DISPLAY="$XDISPLAY"
export GDK_BACKEND=x11
export GTK_A11Y=atspi

# Start a session bus, window manager, AT-SPI launcher, then hand off.
eval $(dbus-launch --sh-syntax)
if command -v openbox >/dev/null 2>&1; then
    openbox >/dev/null 2>&1 &
    sleep 0.5
fi
/usr/libexec/at-spi-bus-launcher --launch-immediately >/dev/null 2>&1 &
sleep 1

"$@"
rc=$?

kill "$DBUS_SESSION_BUS_PID" 2>/dev/null || true
exit "$rc"
