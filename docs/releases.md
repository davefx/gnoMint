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
