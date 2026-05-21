---
layout: default
title: Manual
permalink: /manual/
---

# gnoMint user manual

This is a task-oriented walkthrough. It assumes you have gnoMint
installed — if not, see the [install guide]({{ site.baseurl }}/install)
first.

The manual is divided into:

1. [Concepts](#concepts) — the model gnoMint operates on
2. [Bootstrapping your first CA](#bootstrapping-your-first-ca)
3. [Issuing certificates](#issuing-certificates)
4. [Wizards: web-server and email certs](#wizards-web-server-and-email-certs)
5. [Importing a CSR and signing it](#importing-a-csr-and-signing-it)
6. [Renewing, revoking, and CRLs](#renewing-revoking-and-crls)
7. [Exporting](#exporting)
8. [Bulk operations](#bulk-operations)
9. [Expiry warnings](#expiry-warnings)
10. [Using the CLI](#using-the-cli)
11. [Preferences](#preferences)

---

## Concepts

A **CA database** is a single SQLite file (extension `.gnomint`) that
holds:

- one or more **certificate authorities** (a root CA, optionally with
  intermediate CAs underneath),
- the **certificates** each CA has signed,
- the **CSRs** (certificate signing requests) you've imported and not
  yet signed,
- **private keys** (optionally PKCS#8-encrypted with a passphrase),
- **CRL state** (which certs are revoked, with timestamps and reasons),
- **per-CA policy** (default key length, expiration period).

You can have as many CA databases as you like — one per organisation
is typical. The default file lives at
`~/.local/share/gnomint/default.gnomint`; use **File → Open** or
**File → New** to switch to another.

### Hierarchy

Every certificate is rooted in a self-signed CA. Intermediates are
chained by signing one CA's certificate with another CA's key. The
**tree view** in the main window reflects this structure: drill into a
CA to see what it has signed.

---

## Bootstrapping your first CA

1. **File → New** (or Ctrl-N). Pick a path for your `.gnomint` database.
2. The "New CA" dialog opens. Fill in the subject fields:
   - **CN (Common Name)**: a human-readable name (e.g. "Example Org
     Root CA"). This is what shows up in tools that display issuer
     names.
   - **OU / O / L / ST / C**: optional organisational metadata.
   - **emailAddress**: optional; goes into the subject DN.
3. Pick a **key algorithm**:
   - **RSA** with 4096 bits is the safe default for a long-lived root.
   - **ECDSA P-384** is shorter, faster, and widely supported.
   - **Ed25519** is the smallest and fastest, but a few legacy clients
     don't speak it yet.
4. Choose a **validity period**. For a root CA, 20+ years is normal —
   gnoMint is Y2K38-safe, so dates past 2038 are fine.
5. Optionally edit the **SAN list** (not common for root CAs, but
   useful for self-signed leaves).
6. Click **OK**. Key generation runs in a worker thread; you'll see a
   progress dialog. When it finishes, your new root CA appears in the
   tree.

### Encrypting the database

If your database holds production keys, encrypt it at creation time.
gnoMint asks for an optional passphrase when you create a CA; if you
set one, private keys are stored PKCS#8-encrypted with PKCS#12 3DES.
You can also add/change/remove the passphrase later from **File →
Database password**.

---

## Issuing certificates

With a CA selected, **Certificates → Add new certificate** opens the
issuance dialog. Fill in:

- **Subject** (CN/OU/O/L/ST/C/email)
- **SAN** entries (DNS names, IP addresses, email, URI)
- **Key usage** flags (digitalSignature, keyEncipherment, …)
- **Extended key usage** (serverAuth, clientAuth, codeSigning, …)
- **Validity period** (months, defaults to the per-CA policy)
- **Key algorithm and length**

Click **OK** and gnoMint generates a fresh keypair, signs the resulting
certificate with the CA's key, and writes both into the database.

---

## Wizards: web-server and email certs

For the two most common cases gnoMint offers **wizards** that hide all
the key-usage / EKU fiddling.

### Web-server wizard

**Certificates → Add web-server certificate**:

1. Pick the CA that should sign it.
2. Enter the **hostname** (used both as CN and as a DNS SAN).
3. Optionally enter extra SANs (e.g. `www.example.com`).
4. Click **Issue**.

The wizard sets `keyUsage = digitalSignature, keyEncipherment` and
`extendedKeyUsage = serverAuth`, plus the SAN, and signs.

### Email wizard

**Certificates → Add email certificate**:

1. Pick the signing CA.
2. Enter the **email address** (used both as CN and as an `email`
   SAN).
3. Click **Issue**.

Key usage and EKU are set for S/MIME (signing + key encipherment, plus
`emailProtection` EKU).

---

## Importing a CSR and signing it

If a colleague hands you a CSR (`.csr` or `.pem` PKCS#10), import it:

1. **CSRs → Import CSR…**, pick the file.
2. The CSR appears under "Imported CSRs" in the tree.
3. Right-click it and choose **Sign**.
4. Pick the signing CA, choose validity, optionally tweak the SAN,
   click **OK**.

The issued certificate is filed under the CA you picked.

---

## Renewing, revoking, and CRLs

### Renewing

> *Note: certificate renewal is an in-progress feature for the next
> release; see [issue #50](https://github.com/davefx/gnoMint/issues/50).
> Until then, re-issue manually by signing a new cert with the same
> subject and SAN.*

### Revoking

Right-click any issued certificate and choose **Revoke**. Confirm the
dialog; the cert is marked revoked, and its serial number is added to
the CA's CRL state with a revocation timestamp and reason.

### Publishing a CRL

**Certificates → Export CRL** writes the current CRL for the selected
CA in PEM or DER form. Re-export whenever you revoke something new.

---

## Exporting

### Single certificate

Right-click a certificate and choose **Export certificate**. Picks of:

- PEM (text, `-----BEGIN CERTIFICATE-----`)
- DER (binary)
- PKCS#12 (with the private key, passphrase-protected)

### Private key

Right-click and choose **Extract private key**. The key is exported
PKCS#8 PEM, optionally re-wrapped with a fresh passphrase.

### Full certificate chain

Right-click a leaf certificate and choose **Export full certificate
chain**. You get a single PEM bundle in web-server order — leaf first,
intermediates next, root last — ready to drop into Apache, nginx,
HAProxy, or any other server that expects a `fullchain.pem`. Issue
[#52](https://github.com/davefx/gnoMint/issues/52).

---

## Bulk operations

Hold **Ctrl** to add individual rows to the selection, or **Shift** to
select a range. With multiple rows selected:

- **Certificates → Revoke selected** revokes every cert in the
  selection.
- **CSRs → Delete selected** deletes every CSR in the selection.

Mixed selections (certs + CSRs) are fine — the action that doesn't
apply to a given row silently skips it. Bulk-revoke records the same
revocation reason and timestamp for every entry, so they all appear
together in the CRL. Issue
[#54](https://github.com/davefx/gnoMint/issues/54).

---

## Expiry warnings

### Per-row colouring

Rows in the tree view are coloured by their effective expiration:

- **Amber** — expires within the warning window (default 30 days)
- **Red** — already expired
- **Grey** — expired *and* "show expired" is on, so you can see history
  without misreading it

Expiry is cascade-computed: a leaf certificate is effectively expired
at the earliest of its own `notAfter` and every ancestor CA's
`notAfter`. So a 10-year leaf issued under a CA that expires in two
months will turn amber along with the CA. Issue
[#51](https://github.com/davefx/gnoMint/issues/51).

### Hide expired

**View → Show expired certificates** toggles whether expired entries
(and their entire subtree, in the case of an expired CA) appear in the
list. The setting is persisted in GSettings.

---

## Using the CLI

Everything above is also available from `gnomint-cli`, a readline shell
with tab completion. Common commands:

```bash
gnomint-cli                                # default DB
gnomint-cli ~/some-other.gnomint           # explicit DB

gnomint> help                              # list commands
gnomint> showcas                           # list CAs
gnomint> showcerts                         # list issued certs
gnomint> showcsrs                          # list pending CSRs

gnomint> addca                             # interactive new CA
gnomint> addservercert                     # web-server cert wizard
gnomint> addemailcert                      # email cert wizard
gnomint> sign <csr-id>                     # sign an imported CSR
gnomint> revokecert <id>                   # revoke a cert
gnomint> exportcert <id> <path.pem>
gnomint> exportchain <id> <path.pem>
gnomint> exportcrl <ca-id> <path.pem>
```

Same database; the GUI and CLI can be opened against the same file at
different times (don't open it from both simultaneously — SQLite locking
will reject the second writer).

---

## Preferences

**Edit → Preferences** controls:

- **Default key length** for new RSA/DSA keys.
- **Default validity period** (months) for new certificates.
- **Expire-warning days** — how many days before a cert's effective
  expiration it turns amber. Default 30.
- **Show expired** — same as the View-menu toggle, persisted.

All preferences live in GSettings under the
`org.gnome.gnomint` schema, so `gsettings` works too:

```bash
gsettings list-keys org.gnome.gnomint
gsettings set org.gnome.gnomint expire-warning-days 60
```
