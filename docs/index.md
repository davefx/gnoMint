---
layout: default
title: gnoMint
---

# gnoMint

**A graphical Certification Authority manager for the Linux desktop.**

gnoMint is a GTK 3 application (with a parallel `gnomint-cli` readline
front-end) that lets you bootstrap a Certificate Authority, issue and
revoke certificates, manage CSRs, publish CRLs, and import/export keys
and PKCS#12 bundles — all stored in a self-contained SQLite database
file you can carry around or back up like any other document.

- **Source:** [github.com/davefx/gnoMint](https://github.com/davefx/gnoMint)
- **Latest release:** 1.4.0 "Lazarus" (2026-05-19) — see [NEWS](https://github.com/davefx/gnoMint/blob/master/NEWS)
- **License:** GPL v3 or later

---

## At a glance

| | |
|---|---|
| **CA databases** | One `*.gnomint` SQLite file per organisation; full hierarchical CAs |
| **Key algorithms** | RSA, DSA, ECDSA (P-256/P-384/P-521), Ed25519 |
| **Standards** | X.509, PKCS#8, PKCS#10 CSRs, PKCS#12 bundles, X.509 CRLs |
| **Extensions** | Subject Alternative Names (SAN), Extended Key Usage, Basic Constraints |
| **Interfaces** | GTK 3 desktop GUI and `gnomint-cli` readline shell |
| **Workflows** | New CA, sign CSR, revoke, renew, bulk-revoke, full-chain export |
| **Lifetime safety** | 64-bit `time_t` everywhere — Y2K38-safe certificates |

---

## Why gnoMint?

- **It's a desktop app**, not a script. Discoverable workflows, a real
  tree view of your hierarchy, and a property dialog for every cert.
- **One file per CA database**. Nothing leaks into your home directory;
  back up a single SQLite file and you have everything.
- **Wizards** for the most common cases — web-server certs and email
  certs — so you don't have to remember which extensions to flip.
- **Two front-ends, one source tree.** Use the GUI on your laptop and
  the CLI in your CI pipeline; they read the same database.

---

## Quick links

- [Features overview]({{ site.baseurl }}/features) — what gnoMint can do
- [Install guide]({{ site.baseurl }}/install) — packages and building from source
- [User manual]({{ site.baseurl }}/manual) — task-oriented walkthrough
- [Report a bug](https://github.com/davefx/gnoMint/issues) on GitHub
- [Send a patch](https://github.com/davefx/gnoMint/pulls) — pull requests welcome
