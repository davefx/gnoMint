#!/bin/bash

# Post-create script for gnoMint development environment
# This script runs after the devcontainer is created

set -e

echo "==================================="
echo "gnoMint Development Environment"
echo "==================================="
echo ""

# Display installed versions
echo "Checking installed dependencies..."
echo ""

echo "GCC version:"
gcc --version | head -n 1

echo ""
echo "GTK+ version:"
pkg-config --modversion gtk+-3.0

echo ""
echo "GLib version:"
pkg-config --modversion glib-2.0

echo ""
echo "GnuTLS version:"
pkg-config --modversion gnutls

echo ""
echo "SQLite version:"
pkg-config --modversion sqlite3

echo ""
echo "libgcrypt version:"
libgcrypt-config --version

echo ""
echo "==================================="
echo "Environment ready for development!"
echo "==================================="
echo ""
echo "To build gnoMint, run:"
echo "  ./autogen.sh"
echo "  ./configure"
echo "  make"
echo ""
