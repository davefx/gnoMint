#!/bin/sh
# collect-files.sh - Assemble a relocatable directory tree for the
# Windows MSI installer.  Run inside the MSYS2/MinGW64 shell after
# `make install DESTDIR=$STAGING`.
#
# Usage: ./packaging/windows/collect-files.sh <staging-dir>
#
# The resulting tree must be self-contained: when an end user without
# MSYS2 runs bin\gnomint.exe, every DLL the program loads — directly,
# through the GDK-Pixbuf loaders, or through the GIO modules — has to be
# present under the staging tree.  Missing a single transitive DLL makes
# the program fail to start at all (issue #91), so the harvesting below
# follows the *whole* dependency graph, not just the executables.

set -eu

STAGING=${1:?Usage: collect-files.sh <staging-dir>}
PREFIX=${MINGW_PREFIX:-/mingw64}

mkdir -p "$STAGING/bin" \
         "$STAGING/lib/gdk-pixbuf-2.0/2.10.0/loaders" \
         "$STAGING/lib/gio/modules" \
         "$STAGING/share/glib-2.0/schemas" \
         "$STAGING/share/icons" \
         "$STAGING/etc/gtk-4.0"

# ── DLL harvester ──────────────────────────────────────────────────
# Bundle every MinGW DLL that $1 depends on (recursively) into bin/.
#
# We key on the DLL *name* rather than the path ntldd prints: ntldd
# builds vary in whether they emit Unix (/mingw64/bin/foo.dll) or Windows
# (C:\msys64\mingw64\bin\foo.dll) paths, and the previous path-regex
# silently matched neither on some runners — bundling zero DLLs.  A
# dependency is "ours" iff a file by that name exists in $PREFIX/bin;
# anything else (kernel32.dll, …) is a system DLL we must NOT ship.
harvest_dlls() {
    [ -f "$1" ] || return 0
    ntldd -R "$1" 2>/dev/null | tr -d '\r' | awk '{print $1}' \
    | while IFS= read -r name; do
        case "$name" in
            *.dll|*.DLL) ;;
            *) continue ;;
        esac
        if [ -f "$PREFIX/bin/$name" ]; then
            cp -n "$PREFIX/bin/$name" "$STAGING/bin/" 2>/dev/null || true
        fi
    done
}

# ── 1. Executables ─────────────────────────────────────────────────
# gnomint is linked with -export-dynamic, which puts libtool into
# "wrapper" mode: src/gnomint.exe is then a tiny launcher (it imports
# only KERNEL32/msvcrt and re-execs a hardcoded build path), while the
# REAL PE — the one that actually imports libgtk-4, libgnutls, … — lives
# in src/.libs/.  Shipping the wrapper gave an installer whose exe had no
# GTK imports, harvested no DLLs, and could not run on any other machine
# (issue #91).  Always prefer the real binary from .libs when present.
for prog in gnomint gnomint-cli; do
    if [ -f "src/.libs/$prog.exe" ]; then
        cp "src/.libs/$prog.exe" "$STAGING/bin/$prog.exe"
    else
        cp "src/$prog.exe" "$STAGING/bin/$prog.exe"
    fi
done

# ── 2. GDK-Pixbuf loaders ─────────────────────────────────────────
# Copy the loaders first so their own DLL dependencies (libjpeg, libpng,
# libtiff, …) are picked up by the harvest pass below.
cp "$PREFIX/lib/gdk-pixbuf-2.0/2.10.0/loaders/"*.dll \
   "$STAGING/lib/gdk-pixbuf-2.0/2.10.0/loaders/"
GDK_PIXBUF_MODULEDIR="$STAGING/lib/gdk-pixbuf-2.0/2.10.0/loaders" \
    gdk-pixbuf-query-loaders \
    > "$STAGING/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache"

# ── 3. GIO modules (TLS backend, etc.) ────────────────────────────
# gnoMint links GnuTLS directly, but GIO modules are cheap to ship and
# keep any g_tls_* / GVfs paths working.  Skip silently if none exist.
if [ -d "$PREFIX/lib/gio/modules" ]; then
    cp -n "$PREFIX/lib/gio/modules/"*.dll \
       "$STAGING/lib/gio/modules/" 2>/dev/null || true
fi

# ── 4. Harvest MinGW runtime DLLs (executables + plugins) ─────────
# ntldd -R only follows the static import table, so the GDK-Pixbuf
# loaders and GIO modules — which are dlopen()ed at runtime — must be
# scanned individually or their dependencies go missing.
harvest_dlls "$STAGING/bin/gnomint.exe"
harvest_dlls "$STAGING/bin/gnomint-cli.exe"
for plugin in "$STAGING/lib/gdk-pixbuf-2.0/2.10.0/loaders/"*.dll \
              "$STAGING/lib/gio/modules/"*.dll; do
    [ -f "$plugin" ] && harvest_dlls "$plugin"
done

# ── 5. Icons (Adwaita + hicolor) ──────────────────────────────────
cp -r "$PREFIX/share/icons/Adwaita" "$STAGING/share/icons/"
cp -r "$PREFIX/share/icons/hicolor" "$STAGING/share/icons/"

# ── 6. GLib schemas (system + app) ────────────────────────────────
cp "$PREFIX/share/glib-2.0/schemas/"*.xml \
   "$STAGING/share/glib-2.0/schemas/" 2>/dev/null || true
cp gconf/org.gnome.gnomint.gschema.xml \
   "$STAGING/share/glib-2.0/schemas/"
glib-compile-schemas "$STAGING/share/glib-2.0/schemas/"

# ── 7. App data files (.ui, icons, locale) ─────────────────────────
mkdir -p "$STAGING/share/gnomint"
cp gui/*.ui gui/*.png "$STAGING/share/gnomint/"

if [ -d po ]; then
    for mo in po/*.gmo; do
        [ -f "$mo" ] || continue
        lang=$(basename "$mo" .gmo)
        mkdir -p "$STAGING/share/locale/$lang/LC_MESSAGES"
        cp "$mo" "$STAGING/share/locale/$lang/LC_MESSAGES/gnomint.mo"
    done
fi

# ── 8. GTK settings ───────────────────────────────────────────────
cat > "$STAGING/etc/gtk-4.0/settings.ini" <<'EOF'
[Settings]
gtk-theme-name=Windows10
EOF

# ── 9. Sanity check ───────────────────────────────────────────────
# A complete GTK 4 bundle pulls in dozens of DLLs.  If we ended up with
# only a handful, the harvest above silently failed (the exact class of
# bug behind issue #91), so fail loudly here rather than ship a broken
# installer.
dll_count=$(ls "$STAGING/bin/"*.dll 2>/dev/null | wc -l)
echo "Staging tree ready at $STAGING"
echo "  Executables: $(ls "$STAGING/bin/"*.exe | wc -l)"
echo "  DLLs:        $dll_count"
echo "  UI files:    $(ls "$STAGING/share/gnomint/"*.ui 2>/dev/null | wc -l)"

if [ "$dll_count" -lt 20 ]; then
    echo "ERROR: only $dll_count DLLs bundled — dependency harvesting failed." >&2
    echo "       A working GTK 4 bundle needs dozens; refusing to build a" >&2
    echo "       broken installer (see issue #91)." >&2
    exit 1
fi
