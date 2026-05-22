# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

gnoMint is a GTK+ 3 graphical (and readline-driven CLI) Certification Authority manager written in C. It uses GnuTLS for crypto, libgcrypt for low-level primitives, and SQLite 3 as the on-disk format for CA databases (`*.gnomint` files). Builds produce two binaries from a shared source tree: `gnomint` (GTK GUI) and `gnomint-cli` (readline CLI).

Upstream repo: https://github.com/davefx/gnoMint. The legacy gnomint.sourceforge.net site is gone; its content has been archived into docs/ in the repo.

## Build

The build uses GNU Autotools. From the repo root:

```bash
./autogen.sh        # only after a fresh clone / when configure.ac changes
./configure         # add --enable-debug for -g -O0; --enable-debug-signal for signal tracing
make                # builds both src/gnomint and src/gnomint-cli
sudo make install
```

After `./configure` exists you can usually re-run only `make` between edits — `make` will re-invoke `config.status` if needed. A devcontainer at `.devcontainer/` installs all build deps on Debian/Ubuntu; the same package list is used by `.github/workflows/copilot-setup-steps.yml` if you need to reproduce CI locally.

There is no test target in the Makefile and no `make check`. `src/test_y2k38.c` is a standalone harness that is **not** wired into the build — compile it manually if you need to run it:

```bash
gcc -D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64 src/test_y2k38.c -o /tmp/test_y2k38 && /tmp/test_y2k38
```

## Two binaries, one source tree

`src/Makefile.am` defines `bin_PROGRAMS = gnomint gnomint-cli`. The two share most `.c` files but compile separately:

- `gnomint-cli` is compiled with `-DGNOMINTCLI`. Code that should not be reached from the CLI (GTK widgets, dialogs) is guarded with `#ifndef GNOMINTCLI` / equivalent. When you touch a shared file (e.g. `ca_file.c`, `tls.c`, `import.c`, `export.c`, `new_cert.c`, `pkey_manage.c`, `crl.c`), assume **both** binaries link it and check that GTK symbols stay behind `GNOMINTCLI` guards.
- GUI-only sources (`main.c`, `new_ca_window.c`, `new_req_window.c`, `creation_process_window.c`, `certificate_properties.c`, `csr_properties.c`, `preferences-gui.c`, `preferences-window.c`, `san_manager.c`, `country_table.c`) appear only in `gnomint_SOURCES`.
- CLI-only sources (`gnomint-cli.c`, `ca-cli.c`, `ca-cli-callbacks.c`, `preferences.c`) appear only in `gnomint_cli_SOURCES`.

When adding a new source file, edit `src/Makefile.am` in both lists if it is shared, or just the appropriate list otherwise — do not edit the generated `Makefile.in`/`Makefile`.

## Architecture

Layered roughly bottom-up:

- **`uint160.{c,h}`** — 160-bit integer type used for certificate serial numbers.
- **`tls.{c,h}`** — the GnuTLS wrapper layer. All key generation, certificate/CSR/CRL parsing and emission, PKCS#8 / PKCS#12 handling, and SAN encoding lives here. `TlsCreationData`, `TlsCertCreationData`, `TlsCert`, `TlsCsr` are the data structures passed between layers. Some features compile in only when `ADVANCED_GNUTLS` is defined (gated by GnuTLS ≥ 2.7.4 at configure time).
- **`ca_file.{c,h}`** — the SQLite persistence layer. A `.gnomint` file is a SQLite 3 DB containing CAs, certs, CSRs, private keys (optionally password-encrypted), CA policy rows, and CRL state. All schema access goes through `ca_file_*` functions and the `CaFile*Columns` enums; do not write raw SQL elsewhere. `gnomint-upgrade-db` (shell script in `src/`) migrates pre-0.1.4 SQLite 2 DBs.
- **`ca_policy.{c,h}`** — per-CA policy stored via `ca_file_policy_*`.
- **`ca_creation.c`, `csr_creation.c`, `new_cert.c`, `crl.c`, `pkey_manage.c`, `import.c`, `export.c`, `san_manager.c`** — feature modules that combine `tls.*` + `ca_file.*` to implement CA bootstrap, CSR generation, signing, revocation, key management, import/export (PEM/PKCS#12), and SAN editing.
- **`ca.{c,h}`** (GUI) and **`ca-cli.{c,h}` + `ca-cli-callbacks.{c,h}`** (CLI) — the two front-end shells. `ca-cli-callbacks.c` is a command dispatch table (`CaCommand` structs with mandatory/optional arg counts) consumed by the readline loop in `ca-cli.c`.
- **`gui/*.ui`** — GtkBuilder XML loaded at runtime; widget IDs in `.ui` files are referenced by name (`gtk_builder_get_object`) from the C code, so renames must be done in both places. PNG icons used by the UI also live here.
- **`main.c` / `gnomint-cli.c`** — entry points.

## Conventions worth knowing

- **Y2K38**: `configure.ac` defines `_TIME_BITS=64` and `_FILE_OFFSET_BITS=64` so `time_t` is 64-bit even on 32-bit hosts. Certificate validity periods reach well past 2038. Don't introduce `int`/`long` truncation when handling `time_t`; the codebase explicitly supports far-future expirations.
- **Default DB location**: `gnomint-cli` stores the default CA DB at `$XDG_DATA_HOME/gnomint/default.gnomint` (typically `~/.local/share/gnomint/default.gnomint`) and migrates from the legacy `~/.gnomint/default.gnomint` on first run. The GUI uses the same convention.
- **i18n**: gettext via `intltool`; supported locales are listed as `ALL_LINGUAS` in `configure.ac`. Translations live in `po/`. New user-visible strings should be wrapped in `_()`.
- **MIME type**: registered as `application/x-gnomint` (see `mime/`); used for the GUI's recent-files filter.
- **Generated files**: `aclocal.m4`, `configure`, `Makefile.in`, `config.*`, `libtool`, `*.o`, the `gnomint` and `gnomint-cli` binaries, and `src/.deps/` are all build artifacts present in the working tree. Don't hand-edit them; rerun `./autogen.sh` / `./configure` instead. `.gitignore` already excludes most of them.

## Repository layout note

The directory `/home/davefx/proyectos/gnomint/` contains three sibling trees:

- `gnomint-git/` — **active development tree** (this one; current Git working copy). All edits go here.
- `gnomint-svn/` — historical SVN snapshots and release tarballs (0.5.4, 0.6.0). Read-only reference.
- `translations-export/`, `web/` — auxiliary content unrelated to the source build.
