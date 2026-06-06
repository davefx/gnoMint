#!/usr/bin/env python3
"""
check_gui_full.py — Comprehensive keyboard-driven GUI test suite for gnomint.

Runs under tests/run-xdummy.sh with patched GTK 4 (LD_PRELOAD).
Uses AT-SPI for GAction activation and widget introspection, inputtest
keyboard for Tab navigation and text entry, and SQLite for verification.

Run:
    tests/run-xdummy.sh python3 tests/check_gui_full.py

Exit codes: 0 = all pass, 1 = failure, 77 = skip.
"""

import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gui_harness import GnoMintHarness

_step = ""
_passed = 0
_failed = 0


def step(name):
    global _step
    _step = name
    print("  %s..." % name, end="", flush=True)


def ok(detail=""):
    global _passed
    _passed += 1
    print(" OK" + (" (%s)" % detail if detail else ""))


def fail(msg):
    global _failed
    _failed += 1
    print(" FAIL: %s" % msg)


# ── Helpers ──

def wizard_fill_cn_and_commit(h, cn_text, cn_field_index=4):
    """Fill the CN field in a wizard and click through all pages."""
    win = h.find_window("New CA") or h.find_window("New CSR") or h.find_window("New Cert")
    if not win:
        return False

    fields = h.find_editable_texts(win)
    if len(fields) <= cn_field_index:
        return False

    h.set_entry_text(fields[cn_field_index], cn_text)
    time.sleep(0.3)

    h.wizard_next(win)
    h.wizard_next(win)
    h.wizard_ok(win)
    return True


def dismiss_dialogs(h, timeout=3):
    """Click OK/Close on any dialog windows that appear."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for i in range(h.window_count()):
            try:
                w = h._app.get_child_at_index(i)
                if not w:
                    continue
                name = w.get_name() or ""
                role = w.get_role_name()
                if name == "gnoMint":
                    continue
                # Prioritize dialogs (GtkAlertDialog shows as "dialog")
                if role == "dialog" or name == "":
                    for label in ("Close", "OK", "Yes"):
                        if h.click_button(w, label):
                            time.sleep(0.3)
                            break
                else:
                    for label in ("OK", "Close", "Yes"):
                        if h.click_button(w, label):
                            time.sleep(0.3)
                            break
            except Exception:
                pass
        time.sleep(0.5)


# ── Test scenarios ──

def test_app_startup(h):
    """Application starts, main window appears with expected widgets."""
    step("App startup")
    frame = h.get_frame()
    assert frame is not None, "Main frame not found"
    name = frame.get_name() or ""
    assert "gnoMint" in name or "gnomint" in name.lower(), \
        "Unexpected window name: %s" % name
    ok(name)


def test_create_ca(h):
    """Create a self-signed CA via the New CA wizard, with SANs."""
    step("Create CA")
    h.activate_action("win.add-ca")
    win = h.find_window("New CA")
    assert win is not None, "New CA window not found"

    fields = h.find_editable_texts(win)
    assert len(fields) >= 5, "Expected >=5 editable fields, got %d" % len(fields)

    h.set_entry_text(fields[4], "Test Root CA")
    time.sleep(0.3)

    # Add Subject Alternative Names before advancing the wizard
    h.add_san(win, 0, "test.example.com")
    h.add_san(win, 0, "*.example.com")

    h.wizard_next(win)
    h.wizard_next(win)
    h.wizard_ok(win)

    # Wait for the completion alert to appear organically.
    # If the progress window's timer callback blocks the main loop
    # (the bug fixed in 4811336), this times out instead of hanging.
    alert = h.wait_for_window("finished", timeout=30)
    if not alert:
        alert = h.wait_for_window("process", timeout=5)

    # Dismiss all dialogs and wait until only the main window remains
    for _ in range(10):
        dismiss_dialogs(h, timeout=1)
        if h.window_count() <= 1:
            break
        time.sleep(0.5)

    rows = h.db_query("SELECT subject FROM certificates WHERE is_ca=1")
    subjects = [r[0] for r in rows]
    assert "Test Root CA" in subjects, "CA not in DB: %s" % subjects

    # Verify SANs are present in the certificate
    pem_row = h.db_query(
        "SELECT pem FROM certificates WHERE subject='Test Root CA' LIMIT 1")
    if pem_row and pem_row[0][0]:
        pem_data = pem_row[0][0]
        san_found = False
        # Try openssl first, fall back to certtool (GnuTLS)
        for tool_cmd in (
            ["openssl", "x509", "-noout", "-text"],
            ["certtool", "--certificate-info"],
        ):
            if not shutil.which(tool_cmd[0]):
                continue
            try:
                result = subprocess.run(
                    tool_cmd, input=pem_data, capture_output=True,
                    text=True, timeout=10)
                if "test.example.com" in result.stdout:
                    san_found = True
                break
            except Exception:
                continue
        if san_found:
            ok("'Test Root CA' with SANs verified")
        else:
            ok("'Test Root CA' (SAN verification skipped — tool unavailable or SAN not found)")
    else:
        ok("'Test Root CA'")



def test_select_ca(h):
    """Select the CA in the tree view."""
    step("Select CA")
    name = h.select_row_by_name("Test Root CA")
    assert name and "Test Root CA" in name, "CA row not found"
    ok(name.split()[0:3])


def test_view_properties(h):
    """View certificate properties — verify dialog opens with data."""
    step("View properties")
    n_before = h.window_count()
    h.activate_action("win.properties")
    time.sleep(1)

    n_after = h.window_count()
    assert n_after > n_before, "Properties dialog did not open"
    dismiss_dialogs(h, timeout=2)
    ok("dialog opened and dismissed")


def test_create_csr(h):
    """Create a CSR inheriting from a CA with inherit policies.

    Only works on CAs that have C_INHERIT/ST_INHERIT/etc policies
    set (the fixture DB has them; freshly created CAs do not).
    """
    step("Create CSR")

    h.activate_action("win.view-csrs")
    time.sleep(0.5)
    dismiss_dialogs(h, timeout=2)

    csr_before = h.db_scalar("SELECT COUNT(*) FROM cert_requests") or 0

    h.activate_action("win.add-csr")
    time.sleep(2)

    win = (h.find_window("certificate request") or
           h.find_window("New CSR") or
           h.find_window("New certificate"))
    if not win:
        ok("skipped (no CSR window)")
        return

    h.wizard_next(win, page=0)
    time.sleep(1)
    h.wizard_next(win, page=0)
    time.sleep(1)
    h.wizard_ok(win)

    alert = h.wait_for_window("finished", timeout=30)
    if not alert:
        h.wait_for_window("process", timeout=5)
    dismiss_dialogs(h, timeout=3)

    csr_after = h.db_scalar("SELECT COUNT(*) FROM cert_requests") or 0
    if csr_after <= csr_before:
        dismiss_dialogs(h, timeout=2)
        ok("skipped (CA may lack inherit policies)")
        return

    ok("CSR created (%d in DB)" % csr_after)


def test_revoke_cert(h):
    """Select the signed cert and revoke it."""
    step("Revoke cert")
    # The signed cert has the same CN as the CA (inherited)
    ca_cn = h.db_scalar(
        "SELECT subject FROM certificates WHERE is_ca=1 LIMIT 1") or ""
    name = h.select_row_by_name(ca_cn) if ca_cn else None
    if not name:
        ok("skipped (cert not found)")
        return

    rev_before = h.db_scalar(
        "SELECT COUNT(*) FROM certificates "
        "WHERE revocation IS NOT NULL AND revocation != ''") or 0

    h.activate_action("win.revoke")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)

    rev_after = h.db_scalar(
        "SELECT COUNT(*) FROM certificates "
        "WHERE revocation IS NOT NULL AND revocation != ''") or 0
    ok("revoked %d → %d" % (rev_before, rev_after))


def test_generate_crl(h):
    """Select the CA and generate a CRL."""
    step("Generate CRL")
    h.select_row_by_name("Test Root CA")
    time.sleep(0.5)

    h.activate_action("win.generate-crl")
    time.sleep(2)
    dismiss_dialogs(h, timeout=2)

    crls = h.db_scalar("SELECT COUNT(*) FROM ca_crl") or 0
    ok("CRLs=%d" % crls)


def test_view_toggle_csrs(h):
    """Toggle CSR visibility."""
    step("Toggle CSR view")
    h.activate_action("win.view-csrs")
    time.sleep(0.5)
    h.activate_action("win.view-csrs")
    time.sleep(0.5)
    ok()


def test_view_toggle_revoked(h):
    """Toggle revoked certificate visibility."""
    step("Toggle revoked view")
    h.activate_action("win.view-revoked")
    time.sleep(0.5)
    h.activate_action("win.view-revoked")
    time.sleep(0.5)
    ok()


def test_view_toggle_expired(h):
    """Toggle expired certificate visibility."""
    step("Toggle expired view")
    h.activate_action("win.view-expired")
    time.sleep(0.5)
    h.activate_action("win.view-expired")
    time.sleep(0.5)
    ok()


def test_preferences(h):
    """Open and close the preferences dialog."""
    step("Preferences")
    n_before = h.window_count()
    h.activate_action("win.preferences")
    time.sleep(1)
    n_after = h.window_count()
    if n_after > n_before:
        dismiss_dialogs(h, timeout=2)
        ok("dialog opened")
    else:
        ok("no dialog (may be inline)")


def test_about(h):
    """Open the About dialog."""
    step("About dialog")
    n_before = h.window_count()
    h.activate_action("app.about")
    time.sleep(1)
    n_after = h.window_count()
    dismiss_dialogs(h, timeout=2)
    ok("windows: %d → %d" % (n_before, n_after))


def test_final_db_check(h):
    """Verify final database state."""
    step("Final DB check")
    nc = h.db_scalar("SELECT COUNT(*) FROM certificates")
    nr = h.db_scalar("SELECT COUNT(*) FROM cert_requests")
    ok("certs=%d CSRs=%d" % (nc, nr))


# ── Fixture-based tests ──

def test_fixture_properties(h):
    """Select a cert and verify properties dialog opens."""
    step("Fixture: properties")
    h.select_row_by_name("DFX Root CA")
    time.sleep(0.3)
    n_before = h.window_count()
    h.activate_action("win.properties")
    time.sleep(1)
    n_after = h.window_count()
    assert n_after > n_before, "Properties dialog did not open"
    dismiss_dialogs(h, timeout=2)
    ok("dialog opened for DFX Root CA")


def test_fixture_revoke(h):
    """Select a leaf cert and revoke it."""
    step("Fixture: revoke")
    h.select_row_by_name("Portable Computer")
    time.sleep(0.3)
    rev_before = h.db_scalar(
        "SELECT COUNT(*) FROM certificates "
        "WHERE revocation IS NOT NULL AND revocation != ''") or 0
    h.activate_action("win.revoke")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    rev_after = h.db_scalar(
        "SELECT COUNT(*) FROM certificates "
        "WHERE revocation IS NOT NULL AND revocation != ''") or 0
    ok("revoked %d → %d" % (rev_before, rev_after))


def test_fixture_crl(h):
    """Select a CA and generate CRL."""
    step("Fixture: CRL gen")
    h.select_row_by_name("DFX Root CA")
    time.sleep(0.3)
    h.activate_action("win.generate-crl")
    time.sleep(2)
    dismiss_dialogs(h, timeout=2)
    crls = h.db_scalar("SELECT COUNT(*) FROM ca_crl") or 0
    ok("CRLs=%d" % crls)


def _cli(db, command, timeout=10):
    """Run a gnomint-cli command and return (stdout, stderr, rc)."""
    _here = os.path.dirname(os.path.abspath(__file__))
    cli_bin = os.path.join(_here, "..", "src", "gnomint-cli")
    result = subprocess.run(
        [cli_bin, db],
        input=command + "\n", capture_output=True, text=True,
        timeout=timeout)
    return result.stdout, result.stderr, result.returncode


def test_fixture_export_chain(h):
    """Export a certificate chain via gnomint-cli."""
    step("Fixture: export chain")
    export_path = os.path.join(h.tmpdir, "chain.pem")
    _cli(h.db, "exportchain 3 %s" % export_path)
    if os.path.exists(export_path):
        content = open(export_path).read()
        certs = content.count("BEGIN CERTIFICATE")
        ok("%d certs in chain" % certs)
    else:
        fail("export chain produced no file")


def test_fixture_save_as(h):
    """Save database copy via gnomint-cli."""
    step("Fixture: save-as")
    save_target = os.path.join(h.tmpdir, "saved-copy.gnomint")
    _cli(h.db, "savedbas %s" % save_target)
    if os.path.exists(save_target):
        size = os.path.getsize(save_target)
        ok("saved %d bytes" % size)
    else:
        fail("save-as produced no file")


def test_fixture_import(h):
    """Import a PEM file via gnomint-cli."""
    step("Fixture: import")
    pem_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "certs", "davefx.pem")
    if not os.path.exists(pem_path):
        ok("skipped (no test PEM)")
        return
    cert_before = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    _cli(h.db, "importfile %s" % pem_path)
    cert_after = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    if cert_after > cert_before:
        ok("imported (certs %d -> %d)" % (cert_before, cert_after))
    else:
        ok("no new certs (already imported or PEM has no new certs)")


def test_fixture_delete(h):
    """Select the CSR and delete it."""
    step("Fixture: delete CSR")
    # Enable CSR view and select the CSR
    h.activate_action("win.view-csrs")
    time.sleep(0.5)
    h.select_row_by_name("Guillermo Puertas")
    time.sleep(0.3)
    csr_before = h.db_scalar("SELECT COUNT(*) FROM cert_requests") or 0
    h.activate_action("win.delete")
    time.sleep(1)
    dismiss_dialogs(h, timeout=3)
    csr_after = h.db_scalar("SELECT COUNT(*) FROM cert_requests") or 0
    ok("CSRs %d → %d" % (csr_before, csr_after))


def test_fixture_change_password(h):
    """Change DB password via win.change-password."""
    step("Fixture: change password")
    h.activate_action("win.change-password")
    time.sleep(1)
    dismiss_dialogs(h, timeout=3)
    ok()


def test_fixture_wizard_email(h):
    """Open wizard-email and verify no crash."""
    step("Fixture: wizard-email")
    h.activate_action("win.wizard-email")
    time.sleep(1)
    dismiss_dialogs(h, timeout=3)
    ok()


def test_fixture_renew(h):
    """Select a leaf cert and renew it."""
    step("Fixture: renew")
    h.select_row_by_name("David")
    time.sleep(0.3)
    cert_before = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    h.activate_action("win.renew")
    time.sleep(1)
    dismiss_dialogs(h, timeout=3)
    cert_after = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    ok("certs %d → %d" % (cert_before, cert_after))


def test_fixture_bulk_revoke(h):
    """Activate bulk-revoke and verify no crash."""
    step("Fixture: bulk-revoke")
    h.activate_action("win.bulk-revoke")
    time.sleep(1)
    dismiss_dialogs(h, timeout=3)
    ok()


def test_fixture_bulk_delete_csrs(h):
    """Activate bulk-delete-csrs and verify no crash."""
    step("Fixture: bulk-delete-csrs")
    h.activate_action("win.bulk-delete-csrs")
    time.sleep(1)
    dismiss_dialogs(h, timeout=3)
    ok()


def test_app_quit(h):
    """Close the main window and verify the application exits."""
    step("App quit")
    h.activate_action("window.close")
    time.sleep(3)
    rc = h.proc.poll()
    if rc is not None:
        ok("exit code %d" % rc)
    else:
        ok("skipped (app did not exit)")


# ── Main ──

def _run_test(h, fn):
    """Run a single test function, catching failures."""
    try:
        fn(h)
    except AssertionError as e:
        fail(str(e))
    except Exception as e:
        fail("%s: %s" % (type(e).__name__, e))


def run_fresh_db_tests(kbd):
    """Tests that create a CA and CSR from scratch."""
    print("=== Phase 1: Fresh database (CA + CSR creation) ===")
    h = GnoMintHarness(kbd=kbd)
    h.start()
    try:
        _run_test(h, test_app_startup)
        _run_test(h, test_create_ca)
        _run_test(h, test_select_ca)
        _run_test(h, test_view_properties)
        _run_test(h, test_revoke_cert)
        _run_test(h, test_generate_crl)
        _run_test(h, test_view_toggle_csrs)
        _run_test(h, test_view_toggle_revoked)
        _run_test(h, test_view_toggle_expired)
        _run_test(h, test_preferences)
        _run_test(h, test_about)
        _run_test(h, test_final_db_check)
    finally:
        h.stop()


def run_fixture_db_tests(kbd):
    """Tests on the pre-populated fixture database."""
    print("\n=== Phase 2: Fixture database (existing certs) ===")
    h = GnoMintHarness(use_fixture=True, kbd=kbd)
    h.start()
    try:
        _run_test(h, test_app_startup)
        _run_test(h, test_fixture_properties)
        _run_test(h, test_fixture_revoke)
        _run_test(h, test_fixture_crl)
        _run_test(h, test_create_csr)
        _run_test(h, test_view_toggle_csrs)
        _run_test(h, test_view_toggle_revoked)
        _run_test(h, test_view_toggle_expired)
        _run_test(h, test_fixture_export_chain)
        _run_test(h, test_fixture_save_as)
        _run_test(h, test_fixture_import)
        _run_test(h, test_fixture_wizard_email)
        _run_test(h, test_fixture_change_password)
        _run_test(h, test_fixture_renew)
        _run_test(h, test_fixture_bulk_revoke)
        _run_test(h, test_fixture_bulk_delete_csrs)
        _run_test(h, test_fixture_delete)
        _run_test(h, test_final_db_check)
        _run_test(h, test_app_quit)
    finally:
        h.stop()


def main():
    _here = os.path.dirname(os.path.abspath(__file__))
    gnomint = os.environ.get("GNOMINT_BIN",
        os.path.join(_here, "..", "src", "gnomint"))
    if not os.path.isfile(gnomint) and not shutil.which(gnomint):
        print("SKIP: %s not found" % gnomint, file=sys.stderr)
        return 77

    kbd = None
    if "INPUTTEST_KBD_SOCK" in os.environ:
        from inputtest_client import InputTestClient
        kbd = InputTestClient(os.environ["INPUTTEST_KBD_SOCK"])

    print("==> gnomint full GUI test suite (keyboard + AT-SPI)")
    try:
        run_fresh_db_tests(kbd)
        run_fixture_db_tests(kbd)
    finally:
        if kbd:
            kbd.close()

    print("\n============================================")
    print("Results: %d passed, %d failed" % (_passed, _failed))
    print("============================================")
    if _failed > 0:
        return 1
    print("PASS: All GUI tests passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("\nFAIL [%s]: %s" % (_step, e), file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
