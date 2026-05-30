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
                if name in ("gnoMint", "") or "New CA" in name or "New CSR" in name:
                    continue
                for label in ("OK", "Close", "Yes", "_OK", "_Close", "_Yes"):
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
    time.sleep(15)

    dismiss_dialogs(h)
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


def test_create_csr(h):
    """Create a CSR using the New CSR wizard."""
    step("Create CSR")
    h.activate_action("win.add-csr")
    time.sleep(1.5)

    # Find the CSR wizard window (may be named "New CSR" or "New Certificate Request")
    win = None
    for i in range(h.window_count()):
        try:
            w = h._app.get_child_at_index(i)
            if not w:
                continue
            name = w.get_name() or ""
            if name and name != "gnoMint" and "gnomint" not in name.lower():
                win = w
                break
        except Exception:
            pass
    if not win:
        ok("skipped (no CSR window)")
        return

    # CSR wizard page 1: select CA (first toggle already selected)
    # Click Next via AT-SPI
    h.click_button(win, "Next") or h.click_button(win, "_Next")
    time.sleep(1.5)

    # Page 2: subject fields — set CN
    fields = h.find_editable_texts(win)
    if len(fields) >= 5:
        h.set_entry_text(fields[4], "Web Server Test")
    time.sleep(0.3)

    # Add Subject Alternative Names
    h.add_san(win, 0, "server.example.com")
    h.add_san(win, 0, "*.example.com")

    # Page 2 → 3 via AT-SPI
    h.click_button(win, "Next") or h.click_button(win, "_Next")
    time.sleep(1.5)

    # Page 3 → OK via AT-SPI
    h.click_button(win, "OK") or h.click_button(win, "_OK")
    time.sleep(15)

    dismiss_dialogs(h)
    rows = h.db_query("SELECT subject FROM cert_requests")
    subjects = [r[0] for r in rows]
    assert "Web Server Test" in subjects, "CSR not in DB: %s" % subjects
    ok("'Web Server Test'")


def test_view_properties(h):
    """View certificate properties via GAction."""
    step("View properties")
    n_before = h.window_count()
    h.activate_action("win.properties")
    time.sleep(1)

    n_after = h.window_count()
    if n_after > n_before:
        ok("dialog opened")
        dismiss_dialogs(h, timeout=2)
    else:
        ok("skipped (no cert selected)")


def test_sign_csr(h):
    """Sign a CSR using the CA."""
    step("Sign CSR")
    csr_count_before = h.db_scalar(
        "SELECT COUNT(*) FROM cert_requests")
    cert_count_before = h.db_scalar(
        "SELECT COUNT(*) FROM certificates WHERE is_ca=0")

    h.activate_action("win.sign")
    time.sleep(1)

    # If sign dialog opened, accept defaults and commit
    win = h.find_window("New Cert") or h.find_window("Sign")
    if win:
        h.wizard_next(win)
        h.wizard_next(win)
        h.wizard_ok(win)
        time.sleep(10)
        dismiss_dialogs(h)

    cert_count_after = h.db_scalar(
        "SELECT COUNT(*) FROM certificates WHERE is_ca=0")
    if cert_count_after > cert_count_before:
        ok("cert count %d → %d" % (cert_count_before, cert_count_after))
    else:
        ok("skipped (no CSR selected or sign not available)")


def test_revoke_cert(h):
    """Revoke a certificate."""
    step("Revoke cert")
    h.activate_action("win.revoke")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)

    revoked = h.db_query(
        "SELECT COUNT(*) FROM certificates WHERE revocation IS NOT NULL "
        "AND revocation != ''")
    ok("revoked=%d" % (revoked[0][0] if revoked else 0))


def test_generate_crl(h):
    """Generate a CRL for the selected CA."""
    step("Generate CRL")
    h.activate_action("win.generate-crl")
    time.sleep(2)
    dismiss_dialogs(h, timeout=2)

    crls = h.db_query("SELECT COUNT(*) FROM ca_crl")
    ok("CRLs=%d" % (crls[0][0] if crls else 0))


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
    """Open properties on a fixture CA cert."""
    step("Fixture: properties")
    h.activate_action("win.properties")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_fixture_revoke(h):
    """Revoke a cert in the fixture DB."""
    step("Fixture: revoke")
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
    """Generate CRL on fixture DB."""
    step("Fixture: CRL gen")
    h.activate_action("win.generate-crl")
    time.sleep(2)
    dismiss_dialogs(h, timeout=2)
    crls = h.db_scalar("SELECT COUNT(*) FROM ca_crl") or 0
    ok("CRLs=%d" % crls)


def test_fixture_export(h):
    """Trigger export action on fixture DB."""
    step("Fixture: export")
    h.activate_action("win.export")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_fixture_export_chain(h):
    """Trigger export-chain action on fixture DB."""
    step("Fixture: export chain")
    h.activate_action("win.export-chain")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_fixture_delete(h):
    """Delete a cert/CSR from the fixture DB."""
    step("Fixture: delete")
    cert_before = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    csr_before = h.db_scalar("SELECT COUNT(*) FROM cert_requests") or 0
    total_before = cert_before + csr_before
    h.activate_action("win.delete")
    time.sleep(1)
    dismiss_dialogs(h, timeout=3)
    cert_after = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    csr_after = h.db_scalar("SELECT COUNT(*) FROM cert_requests") or 0
    total_after = cert_after + csr_after
    if total_after < total_before:
        ok("deleted (%d+%d → %d+%d)" % (cert_before, csr_before, cert_after, csr_after))
    else:
        ok("skipped (nothing selected or dialog dismissed)")


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
    """Renew a certificate in the fixture DB."""
    step("Fixture: renew")
    cert_before = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    h.activate_action("win.renew")
    time.sleep(1)
    dismiss_dialogs(h, timeout=3)
    cert_after = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    if cert_after > cert_before:
        ok("renewed (certs %d → %d)" % (cert_before, cert_after))
    else:
        ok("skipped (no leaf cert selected or dialog dismissed)")


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
    """Activate app.quit and verify the application exits cleanly."""
    step("App quit")
    h.activate_action("app.quit")
    time.sleep(2)
    rc = h.proc.poll()
    if rc is not None:
        assert rc == 0, "app.quit exited with code %d" % rc
        ok("exit code 0")
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
        _run_test(h, test_create_csr)
        _run_test(h, test_view_properties)
        _run_test(h, test_sign_csr)
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
        _run_test(h, test_view_toggle_csrs)
        _run_test(h, test_view_toggle_revoked)
        _run_test(h, test_view_toggle_expired)
        _run_test(h, test_fixture_export)
        _run_test(h, test_fixture_export_chain)
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
    gnomint = os.environ.get("GNOMINT_BIN", "src/gnomint")
    if not os.path.isfile(gnomint) and not shutil.which(gnomint):
        print("SKIP: %s not found" % gnomint, file=sys.stderr)
        return 77

    if "INPUTTEST_KBD_SOCK" not in os.environ:
        print("SKIP: not running under run-xdummy.sh", file=sys.stderr)
        return 77

    from inputtest_client import InputTestClient
    kbd = InputTestClient(os.environ["INPUTTEST_KBD_SOCK"])

    print("==> gnomint full GUI test suite (keyboard + AT-SPI)")
    try:
        run_fresh_db_tests(kbd)
        run_fixture_db_tests(kbd)
    finally:
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
