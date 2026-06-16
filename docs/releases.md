---
layout: default
title: Releases
permalink: /releases/
---

# Release history

This page is a chronological summary of gnoMint releases since 2006.
The early entries are reconstructed from the original announcements on
gnomint.sourceforge.net (preserved on the
[Internet Archive](https://web.archive.org/web/2017*/gnomint.sourceforge.net));
from 1.4.0 onwards the source is the in-tree [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
file.

---

## 1.6.6 — "Tempered Anvil" (2026-06-15)

Windows polish.

Highlights:

- **No console window behind the GUI** — `gnomint.exe` is now linked with
  the Windows GUI subsystem (`-mwindows`), so launching from the Start
  menu no longer pops up a stray console. `gnomint-cli` stays a console
  program.

Database-compatible with 1.4.0 — no migration needed.

See the full [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
for the complete list.

---

## 1.6.5 — "Tempered Anvil" (2026-06-15)

Security hardening and a working Windows installer.

Highlights:

- **Cryptographically random serial numbers** — 128 bits of CSPRNG
  entropy (CA/Browser Forum BR 7.1) instead of a sequential counter;
  existing serials are unchanged.
- **Private keys encrypted with PBES2** (PBKDF2-SHA256 + AES-256-CBC)
  instead of legacy PKCS#12 3DES; backward compatible (GnuTLS
  auto-detects the scheme).
- **Passwords wiped from memory** with a non-elidable routine.
- **Minimum GTK raised to 4.12**, with `GDK_VERSION_MAX_ALLOWED` capped
  at the floor so using newer API is a compile error.
- **The Windows `.msi` installer now actually runs** ([#91](https://github.com/davefx/gnoMint/issues/91)) —
  it ships the real binaries with their full DLL closure (plus pixbuf
  loaders and GIO modules) and locates its schemas, data, and
  translations relative to the install directory.

Database-compatible with 1.4.0 — no migration needed.

See the full [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
for the complete list.

---

## 1.6.4 — "Tempered Anvil" (2026-06-12)

i386 / Year-2038 correctness.

Highlights:

- **i386 signing crash fixed** — `configure.ac` no longer forces
  `_TIME_BITS=64`, a glibc ABI switch inconsistent with the system GnuTLS
  on i386 that corrupted the stack in `gnutls_x509_crt_set_*_time()`.
  gnoMint now uses the platform's native `time_t`. ([#86](https://github.com/davefx/gnoMint/issues/86))
- **Correct post-2038 dates on every architecture** — stored as 64-bit
  and rendered with a 64-bit-safe formatter; on 32-bit-`time_t` hosts
  gnoMint warns and clamps when generating a cert and self-heals stored
  dates when a 64-bit host opens the database.
- **All date I/O is unconditionally 64-bit** (`g_ascii_strtoll` / `%lld`).
- **New 32-bit i386 multilib CI job** plus Year-2038 tests on every
  platform.

Database-compatible with 1.4.0 — no migration needed.

See the full [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
for the complete list.

---

## 1.6.3 — "Tempered Anvil" (2026-06-11)

i386 crash fix (community contribution).

Highlights:

- **Segfault on i386 fixed** — four `sqlite3_mprintf` calls in
  `ca_file.c` used `%ld` for 64-bit `time_t` values, reading only 4 bytes
  per value and corrupting the stack. Now `%lld` with explicit casts.
  (PR #85 by tzbkk, reported via Debian CI.)

Database-compatible with 1.4.0 — no migration needed.

See the full [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
for the complete list.

---

## 1.6.2 — "Tempered Anvil" (2026-06-11)

New application icon and desktop integration fix.

Highlights:

- **New application icon** — a wax-seal "CA" badge with colored ribbons,
  rendered from SVG at all sizes; the scalable SVG is installed for sharp
  rendering at any DPI.
- **Taskbar icon fixed in GNOME Shell** — the desktop file, appdata, and
  icon names now use the `org.gnome.gnomint` reverse-DNS name matching
  the `GtkApplication` ID.
- **Flatpak manifest** moved from `net.sourceforge.gnomint` to
  `org.gnome.gnomint`; removed the post-install rename hacks.

Database-compatible with 1.4.0 — no migration needed.

See the full [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
for the complete list.

---

## 1.6.1 — "Tempered Anvil" (2026-06-10)

Multi-platform CI and the first Windows installer.

Highlights:

- **Multi-platform CI** via GitHub Actions — automated builds and tests
  on Fedora, Arch Linux, macOS (Homebrew), and Windows (MSYS2/MinGW64)
  on every push and pull request.
- **Windows MSI installer** built with WiX v5, bundling both binaries
  with the MinGW runtime DLLs, GTK 4 theme and icons, GLib schemas,
  translations, and UI files, plus Start Menu shortcuts and a `.gnomint`
  file association. (Made fully functional in 1.6.5.)
- **Windows portability** — winsock2 instead of `arpa/inet.h`, GLib
  `GRegex` instead of POSIX `regex.h`, a runtime-relative
  `PACKAGE_DATA_DIR`, and a keyfile GSettings backend.

Database-compatible with 1.4.0 — no migration needed.

See the full [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
for the complete list.

---

## 1.6.0 — "Tempered Anvil" (2026-06-08)

The first fully stabilized release of the GTK 4 port. No new
user-facing features — this release is entirely bug fixes, polish,
and quality infrastructure.

Highlights:

- **EdDSA key generation hang fixed** — blocking main-loop call inside
  a timer callback caused deadlock.
- **CSR wizard crash and broken commit button** — wrong widget IDs in
  the code vs. the `.ui` file.
- **Country selector search now works** — `GtkDropDown` needed an
  explicit expression for search matching.
- **All dialogs modal on Wayland** — `transient_for` set everywhere.
- **Tab reaches wizard buttons** — capture-phase key handler works
  around `GtkNotebook` focus wrapping.
- **View toggles persist** — Show CSR/Revoked/Expired saved via GSettings.
- **Spanish translations complete** — 862/862 strings.
- **16 automated tests** via `make check`, all under headless Wayland
  with full process isolation. GitHub Actions CI on every push/PR.
- **`AC_CONFIG_HEADERS([config.h])`** — `make` now detects define
  changes (version bumps, etc.) automatically.

Database-compatible with 1.4.0 — no migration needed.

See the full [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
for the complete list.

---

## 1.5.0 — "Belt and Braces" (2026-05-24)

Six weeks after Lazarus. Closes the running-a-CA-over-years loop
(warning → filter → renew → diff) and brings `gnomint-cli` to full
parity with the GUI. Every state-mutating CLI command is now covered
by an automated test.

Highlights:

- **ECDSA / Ed25519 key support** ([#49](https://github.com/davefx/gnoMint/issues/49))
  in both wizards and the CLI prompts.
- **Algorithm-aware key-size selector** — spinbutton for RSA/DSA,
  curve dropdown for ECDSA, hidden for Ed25519.
- **Certificate renewal** ([#50](https://github.com/davefx/gnoMint/issues/50)):
  right-click → *Renew with fresh key*. CLI: `renewcert <id>`.
- **Search / filter box** ([#53](https://github.com/davefx/gnoMint/issues/53))
  above the tree view; Ctrl+F focuses it. CLI: `search <pattern>`.
- **Side-by-side certificate diff** ([#55](https://github.com/davefx/gnoMint/issues/55)):
  right-click → *Compare with PEM file…*. CLI: `diff <id|path> <id|path>`.
- **Startup expiry banner** ([#56](https://github.com/davefx/gnoMint/issues/56))
  with a *Show them* action that filters the tree to the expiring
  certs. CLI: stderr notice on `ca_open`.
- **Editable SAN list when signing a CSR** ([#40](https://github.com/davefx/gnoMint/issues/40)):
  the sign-CSR dialog now embeds the full SAN editor.
- **GitHub Pages site** under `docs/` — landing, features, install,
  manual, tutorial, release history, all with current GTK 3
  screenshots.
- **Full user manual** ([#57](https://github.com/davefx/gnoMint/issues/57))
  covering every workflow, the CLI, and a troubleshooting section.
- **CLI parity**: `renewcert`, `exportchain`, `revokemany`,
  `deletemany`, `search`, `diff` all available from `gnomint-cli`.
- **Comprehensive test coverage**: 5 suites → 14 suites, all green.
  pty-driven Python script for the getpass-using commands
  (`extractcertpkey`, `extractcsrpkey`, `changepassword`).

Bug fixes:

- ECDSA prompt no longer asserts in `addca`/`addcsr`.
- `gnomint-cli importfile` no longer segfaults.
- Copyright updated to 2006-2026; dead sourceforge URLs replaced.

Database-compatible with 1.4.0 — no migration needed.

---

## 1.4.0 — "Lazarus" (2026-05-19)

After a decade-long hiatus since 1.3.0, gnoMint returns. This release
accumulates ten years of patches from the Debian downstream community,
modernises the build, and adds a test suite to keep regressions out.

Highlights:

- Subject Alternative Name (SAN) support throughout the workflow
- Year 2038 (Y2K38) safe handling of certificate dates
- XDG Base Directory Specification compliance for the default DB
- AppData file for software-center integration
- New `make check` test suite (Y2K38, .ui consistency, Wayland
  workflows, CLI smoke)
- ECDSA (P-256/P-384/P-521) and Ed25519 key support
- Certificate wizards for web-server and email certs
- Amber per-row highlighting for soon-to-expire certs (cascade-aware:
  a leaf under an expiring CA goes amber too)
- "Show expired" toggle in the View menu
- Bulk revoke and bulk delete-CSR actions
- Full certificate chain export (leaf → root PEM bundle)

See the full [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
for the complete list and the corresponding GitHub issue numbers.

---

## 1.3.0 — "Sha Sha Dance" (2016-03-15)

> *"I'm pleased to announce version 1.3.0, also known as 'Sha Sha
> dance', of gnoMint."*

- All new certificates are signed using the **SHA-512** digest
  algorithm.
- Several compiler warnings fixed.

---

## 1.2.1 — "All you need is a giant pacifier" (2010-08-11)

Bug-fix release over 1.2.0.

---

## 1.2.0 — "How to put an elephant to sleep" (2010-08-10)

- Added support for **CRL distribution points**.
- Fixed bug in export-from-menu.
- Fixed bug in CA policy settings (both `gnomint` and `gnomint-cli`).
- Initial Windows compilation support (thanks to Jaroslav Imrich).
- Added Slovak translation; refreshed all translations from Launchpad.

---

## Git migration (2010-06-01)

> *"gnoMint is now managed using Git, the distributed Software
> Control Management tool created by Linus Torvalds."*

The project moved from SourceForge SVN to git.

---

## 1.1.0 — "Against the tide of bit-rot" (2009-11-08)

> *"I'm pleased to announce version 1.1.0 […]. This version includes
> some bug fixes and improvements over the 1.0.0 version."*

---

## 1.0.0 — "Minted gnoMint" (2009-06-03)

> *"This version is the first stable release of gnoMint."*

The first stable release, with bug fixes and improvements over the
0.9.9 release candidate.

---

## 0.9.9 (2009-03-23)

Major code clean-up plus new features.

---

## 0.9.1 (2008-12-18)

Patch release fixing a `gnomint-cli` compile issue on OpenSUSE 11.

---

## 0.9.0 — "Command-line & Conquer-line" (2008-12-16)

The big one: introduces **`gnomint-cli`**, a full readline command-line
front-end. Drives any action over a gnoMint database from standard
input — making gnoMint scriptable. Useful for cron jobs (regenerate
CRLs on a schedule) or bulk certificate issuance from an employee
roster.

---

## 0.6.0 (2008-11-10 era)

- Added the ability to import pre-existing OpenSSL-style CAs (`openssl
  ca` scripts, tinyCA, OpenVPN `easy-rsa`) into a gnoMint database.
- Added Italian and initial German translations (Launchpad).
- Many bug fixes.

Around this time gnoMint was packaged in Fedora Core and Debian (and
already in archLinux).

---

## 0.5.4 (2008-10-01)

Continuing the work-in-progress after 0.6.0; adds further features.

---

## 0.5.3 (2008-09-08)

- Initial Czech translation (thanks to Staněk Luboš).
- When exporting certificates, the full certification path is exported
  and saved (easier validation by external tools).
- Generation of PKCS#3 Diffie-Hellman parameters.

---

## 0.5.2 (2008-09-01)

- General view preferences are now persisted via GConf.
- New certificates can be exported automatically to gnome-keyring.

---

## 0.5.1 (2008-08-23)

- Recent-opened-files menu.
- Fix CSR-creation field inheritance from CA.
- Fix CA policy changes.
- Removed GUI warnings.

---

## 0.5.0 (2008-08-21)

Several interesting features (full announcement was elided on the
preserved archive page).

---

## 0.4.0 (2007-11-19)

Useful features over 0.3.2.

---

## 0.3.2 (2007-11-03)

Fixes nasty bugs, including:

- Databases created by versions prior to 0.3.1 are now correctly
  loaded and upgraded.
- Note that databases from before 0.3.1 will contain non-CA
  certificates that share internal serial number 0 — a problem if any
  of them is revoked, because the generated CRL will invalidate all of
  them.

---

## 0.3.1 (2007-11-01)

- **PKCS#12 export**, so certificates can be imported by browsers and
  mail clients.
- **Certificate revocation** plus CRL generation.
- License updated to GPL v3.

---

## 0.1.4 (2007-05-14)

- Per-CA policies (uses, purposes, validity).
- **SQLite 3** for proper UTF-8 support (a conversion script ships in
  the package for pre-0.1.4 databases).

---

## 0.1.3 (2006-11-10)

- Export uncrypted private keys (useful for unattended SSL/TLS
  servers).
- Minimum length (8 chars) for private-key export passphrase so
  OpenSSL can import the keys.

---

## 0.1.2 (2006-10-15)

Bug-fix: 0.1.1 couldn't save a CA database if the destination file and
`/tmp` were on different partitions.

---

## 0.1.1 (2006-09-17)

Bug-fix: 0.1.0 couldn't build on 64-bit due to a type-conversion error.

---

## 0.1.0 — first public release (2006-09-15)

> *"gnoMint is a tool for an easy creation and management of
> Certification Authorities. It allows a fancy visualization of all
> the pieces that conform a CA: x509 certificates, CSRs, CRLs..."*

Creation of CAs, CSRs and certificates. Export of both public and
private parts as PEM files. Known bugs and not feature-complete yet.
