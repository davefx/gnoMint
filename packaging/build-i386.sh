#!/bin/sh
# build-i386.sh — build and test gnoMint as a 32-bit (i386) binary on an
# amd64 host, WITHOUT a chroot or container.
#
# This uses the host toolchain in multilib mode (gcc -m32) plus the Debian/
# Ubuntu i386 multiarch -dev packages, so the build links against the SAME
# 32-bit-time_t system libraries (GnuTLS, GLib, SQLite, ...) that the i386
# distribution ships. That is exactly the configuration that exposed the
# _TIME_BITS=64 ABI mismatch reported in issue #86, which makes this the right
# environment to regression-test that fix.
#
# Usage:
#   ./packaging/build-i386.sh            # configure + build + make check
#   ./packaging/build-i386.sh deps       # only install the i386 -dev packages
#
# The build tree is created at build-i386/ (git-ignored) and is reusable: rerun
# this script after edits and it reconfigures/rebuilds in place.

set -e

SRCDIR=$(cd "$(dirname "$0")/.." && pwd)
BUILDDIR="$SRCDIR/build-i386"

# i386 -dev packages needed to satisfy configure.ac. libgpg-error-dev:i386 is
# pulled in as a dependency of libgcrypt20-dev:i386 and provides the i386
# gpg-error.pc that gpgrt-config (the libgcrypt detector) needs.
I386_PKGS="libgnutls28-dev:i386 libsqlite3-dev:i386 libglib2.0-dev:i386 \
libgtk-4-dev:i386 libgcrypt20-dev:i386 libreadline-dev:i386"

install_deps() {
    sudo dpkg --add-architecture i386
    sudo apt-get update
    # shellcheck disable=SC2086
    sudo apt-get install -y --no-install-recommends $I386_PKGS
}

if [ "$1" = "deps" ]; then
    install_deps
    exit 0
fi

# Environment that makes the autotools build target i386:
#   CC="gcc -m32"        compile/link 32-bit objects; also drives gpgrt-config's
#                        libdir search (-print-search-dirs) to the i386 tree.
#   PKG_CONFIG_LIBDIR    resolve .pc files from the i386 multiarch dir ONLY, so
#                        no amd64 .pc files leak into the flags.
# build==host (no --host), so the resulting i386 ELF runs natively on the amd64
# kernel and `make check` executes the test binaries directly.
export CC="gcc -m32"
export PKG_CONFIG_LIBDIR="/usr/lib/i386-linux-gnu/pkgconfig:/usr/share/pkgconfig"

mkdir -p "$BUILDDIR"
cd "$BUILDDIR"
"$SRCDIR/configure" --enable-debug
make -j"$(nproc)"
make check
