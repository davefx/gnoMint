#!/bin/sh
# collect-files.sh - Assemble a relocatable directory tree for the
# Windows MSI installer.  Run inside the MSYS2/MinGW64 shell after
# `make install DESTDIR=$STAGING`.
#
# Usage: ./packaging/windows/collect-files.sh <staging-dir>

set -eu

STAGING=${1:?Usage: collect-files.sh <staging-dir>}
PREFIX=${MINGW_PREFIX:-/mingw64}

mkdir -p "$STAGING/bin" \
         "$STAGING/lib/gdk-pixbuf-2.0/2.10.0/loaders" \
         "$STAGING/share/glib-2.0/schemas" \
         "$STAGING/share/icons" \
         "$STAGING/etc/gtk-4.0"

# ── 1. Executables ─────────────────────────────────────────────────
cp src/gnomint.exe src/gnomint-cli.exe "$STAGING/bin/"

# ── 2. MinGW runtime DLLs (ntldd recursive) ───────────────────────
for exe in "$STAGING/bin/"*.exe; do
    ntldd -R "$exe" 2>/dev/null \
    | grep -io '[a-z]:\\.*mingw64\\[^ ]*\.dll' \
    | sort -u \
    | while IFS= read -r dll; do
        unix_path=$(cygpath -u "$dll")
        cp -n "$unix_path" "$STAGING/bin/" 2>/dev/null || true
    done
done

# ── 3. GDK-Pixbuf loaders ─────────────────────────────────────────
cp "$PREFIX/lib/gdk-pixbuf-2.0/2.10.0/loaders/"*.dll \
   "$STAGING/lib/gdk-pixbuf-2.0/2.10.0/loaders/"
GDK_PIXBUF_MODULEDIR="$STAGING/lib/gdk-pixbuf-2.0/2.10.0/loaders" \
    gdk-pixbuf-query-loaders \
    > "$STAGING/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache"

# ── 4. Icons (Adwaita + hicolor) ──────────────────────────────────
cp -r "$PREFIX/share/icons/Adwaita" "$STAGING/share/icons/"
cp -r "$PREFIX/share/icons/hicolor" "$STAGING/share/icons/"

# ── 5. GLib schemas (system + app) ────────────────────────────────
cp "$PREFIX/share/glib-2.0/schemas/"*.xml \
   "$STAGING/share/glib-2.0/schemas/" 2>/dev/null || true
cp gconf/org.gnome.gnomint.gschema.xml \
   "$STAGING/share/glib-2.0/schemas/"
glib-compile-schemas "$STAGING/share/glib-2.0/schemas/"

# ── 6. App data files (.ui, icons, locale) ─────────────────────────
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

# ── 7. GTK settings ───────────────────────────────────────────────
cat > "$STAGING/etc/gtk-4.0/settings.ini" <<'EOF'
[Settings]
gtk-theme-name=Windows10
EOF

echo "Staging tree ready at $STAGING"
echo "  Executables: $(ls "$STAGING/bin/"*.exe | wc -l)"
echo "  DLLs:        $(ls "$STAGING/bin/"*.dll 2>/dev/null | wc -l)"
echo "  UI files:    $(ls "$STAGING/share/gnomint/"*.ui 2>/dev/null | wc -l)"
