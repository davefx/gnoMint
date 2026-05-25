---
layout: default
title: Install
permalink: /install/
---

# Installing gnoMint

## From distribution packages

gnoMint has historically shipped in Debian and Ubuntu. The packaged
version may lag the upstream release; check
[packages.debian.org](https://packages.debian.org/search?keywords=gnomint)
or your distribution's equivalent.

```bash
# Debian / Ubuntu
sudo apt install gnomint

# Fedora (when available)
sudo dnf install gnomint
```

For the latest release (1.5.0 "Belt and Braces" and newer), you'll
likely want to install via Flatpak or build from source.

---

## Flatpak

The easiest way to run the latest gnoMint on any Linux distribution:

```bash
# Build and install from the repo manifest
flatpak-builder --install --user build-flatpak \
    net.sourceforge.gnomint.yml

# Run
flatpak run net.sourceforge.gnomint
```

The Flatpak bundles GnuTLS, libgcrypt, and all other dependencies
inside the sandbox. It uses the GNOME 48 runtime for GTK 4.

---

## Building from source

### Dependencies

gnoMint links against:

- **GTK 4** (≥ 4.6)
- **GLib / GIO** (≥ 2.66)
- **GnuTLS** (≥ 2.0; ≥ 2.7.4 for advanced features)
- **libgcrypt**
- **SQLite 3**
- **GNU readline** (for `gnomint-cli`)

Build-time tools:

- **autoconf / automake / libtool**
- **intltool**
- **pkg-config**

On Debian/Ubuntu the full set installs with:

```bash
sudo apt install \
    build-essential autoconf automake libtool intltool pkg-config \
    libgtk-4-dev libglib2.0-dev libgnutls28-dev libgcrypt20-dev \
    libsqlite3-dev libreadline-dev
```

The same package list is used by gnoMint's CI workflow, so it stays in
sync with what upstream tests against.

### Configure, build, install

From a git checkout:

```bash
./autogen.sh        # only after a fresh clone
./configure         # add --enable-debug for -g -O0
make
sudo make install
```

From a release tarball, skip `autogen.sh` and start at `./configure`.

The build produces two binaries:

- `gnomint`     — the GTK 4 desktop application
- `gnomint-cli` — the readline command-line interface

Both are installed into `$prefix/bin` (default `/usr/local/bin`). UI
files, icons, and translations go to `$prefix/share/gnomint/`,
`$prefix/share/icons/`, and `$prefix/share/locale/` respectively.

### Running tests

```bash
make check
```

The suite runs Y2K38 unit tests, a static `.ui` consistency checker, a
Wayland-backed workflow regression test (started by
`tests/run-headless.sh` via weston), and CLI smoke tests. See the
[features page]({{ site.baseurl }}/features#test-suite) for what's
covered.

---

## First run

On first launch gnoMint creates an empty database at
`$XDG_DATA_HOME/gnomint/default.gnomint` (typically
`~/.local/share/gnomint/default.gnomint`). Existing databases at the
legacy `~/.gnomint/default.gnomint` location are migrated automatically.

From there, see the [user manual]({{ site.baseurl }}/manual) for the
first-CA walkthrough.

---

## Reporting build failures

If `./configure` or `make` fails, please file a bug at
[github.com/davefx/gnoMint/issues](https://github.com/davefx/gnoMint/issues)
including:

- distribution + version (`lsb_release -a` or contents of `/etc/os-release`)
- output of `pkg-config --modversion gtk4 gnutls glib-2.0 sqlite3`
- the failing line from `./configure` (or `config.log` if it bailed out)
- the gnoMint version (release tarball name or `git describe`)
