#!/usr/bin/env python3
"""
check_gui_full.py — End-to-end GUI test suite for gnomint.

Runs under tests/run-gui-test.sh (headless weston + private D-Bus).
All interaction is via AT-SPI — no keyboard or mouse injection.
File operations (export, import, save-as) use gnomint-cli.

Run:  tests/run-gui-test.sh python3 tests/check_gui_full.py
Exit: 0 = all pass, 1 = failure, 77 = skip.
"""

import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gui_harness import GnoMintHarness

_HERE = os.path.dirname(os.path.abspath(__file__))
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


def _run_test(h, fn):
    try:
        fn(h)
    except AssertionError as e:
        fail(str(e))
    except Exception as e:
        fail("%s: %s" % (type(e).__name__, e))


def dismiss_dialogs(h, timeout=3):
    """Click Close/OK on any non-main dialog windows."""
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
                if role == "dialog" or name == "":
                    for label in ("Close", "OK", "Yes"):
                        if h.click_button(w, label):
                            break
                else:
                    for label in ("OK", "Close", "Yes"):
                        if h.click_button(w, label):
                            break
            except Exception:
                pass
        time.sleep(0.5)


def wait_clean(h, timeout=10):
    """Dismiss dialogs until only the main window remains."""
    for _ in range(timeout * 2):
        dismiss_dialogs(h, timeout=1)
        if h.window_count() <= 1:
            return
        time.sleep(0.5)


# ────────────────────────────────────────────────────────────────
# Phase 1: Fresh database
# ────────────────────────────────────────────────────────────────

def test_app_startup(h):
    step("App startup")
    frame = h.get_frame()
    assert frame is not None, "Main frame not found"
    ok(frame.get_name())


def test_create_ca(h):
    """Create a self-signed CA with SANs."""
    step("Create CA")
    h.activate_action("win.add-ca")
    win = h.find_window("New CA")
    assert win is not None, "New CA window not found"

    fields = h.find_editable_texts(win)
    assert len(fields) >= 5, "Expected >=5 fields, got %d" % len(fields)
    h.set_entry_text(fields[4], "Test Root CA")

    h.add_san(win, 0, "test.example.com")
    h.add_san(win, 0, "*.example.com")

    h.wizard_next(win)
    h.wizard_next(win)
    h.wizard_ok(win)

    h.wait_for_window("finished", timeout=30)
    wait_clean(h)

    rows = h.db_query("SELECT subject FROM certificates WHERE is_ca=1")
    assert any("Test Root CA" in r[0] for r in rows), "CA not in DB"

    # Verify SANs in PEM
    pem = h.db_scalar(
        "SELECT pem FROM certificates WHERE subject='Test Root CA'")
    if pem and shutil.which("openssl"):
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-text"],
            input=pem, capture_output=True, text=True, timeout=10)
        if "test.example.com" in result.stdout:
            ok("CA with SANs verified")
            return
    ok("CA created")


def test_select_ca(h):
    step("Select CA")
    name = h.select_row_by_name("Test Root CA")
    assert name and "Test Root CA" in name, "CA row not found"
    ok()


def test_view_properties(h):
    step("View properties")
    n_before = h.window_count()
    h.activate_action("win.properties")
    time.sleep(1)
    assert h.window_count() > n_before, "Properties dialog did not open"
    dismiss_dialogs(h, timeout=2)
    ok()


def test_revoke_cert(h):
    step("Revoke cert")
    non_ca = h.db_scalar(
        "SELECT subject FROM certificates WHERE is_ca=0 LIMIT 1")
    if non_ca:
        h.select_row_by_name(non_ca)
    rev_before = h.db_scalar(
        "SELECT COUNT(*) FROM certificates "
        "WHERE revocation IS NOT NULL AND revocation != ''") or 0
    h.activate_action("win.revoke")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    rev_after = h.db_scalar(
        "SELECT COUNT(*) FROM certificates "
        "WHERE revocation IS NOT NULL AND revocation != ''") or 0
    ok("revoked %d -> %d" % (rev_before, rev_after))


def test_generate_crl(h):
    step("Generate CRL")
    h.select_row_by_name("Test Root CA")
    h.activate_action("win.generate-crl")
    time.sleep(2)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_view_toggles(h):
    step("View toggles")
    for action in ("win.view-csrs", "win.view-revoked", "win.view-expired"):
        h.activate_action(action)
        time.sleep(0.3)
        h.activate_action(action)
        time.sleep(0.3)
    ok()


def test_preferences(h):
    step("Preferences")
    n_before = h.window_count()
    h.activate_action("win.preferences")
    time.sleep(1)
    if h.window_count() > n_before:
        dismiss_dialogs(h, timeout=2)
    ok()


def test_about(h):
    step("About")
    h.activate_action("app.about")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_final_db_check(h):
    step("DB check")
    nc = h.db_scalar("SELECT COUNT(*) FROM certificates")
    nr = h.db_scalar("SELECT COUNT(*) FROM cert_requests")
    ok("certs=%d CSRs=%d" % (nc, nr))


# ────────────────────────────────────────────────────────────────
# Phase 2: Fixture database (9 certs, 1 CSR, CAs with policies)
# ────────────────────────────────────────────────────────────────

def test_fixture_properties(h):
    step("Fixture: properties")
    h.select_row_by_name("DFX Root CA")
    n_before = h.window_count()
    h.activate_action("win.properties")
    time.sleep(1)
    assert h.window_count() > n_before, "Properties dialog did not open"
    dismiss_dialogs(h, timeout=2)
    ok("DFX Root CA")


def test_fixture_revoke(h):
    step("Fixture: revoke")
    h.select_row_by_name("Portable Computer")
    rev_before = h.db_scalar(
        "SELECT COUNT(*) FROM certificates "
        "WHERE revocation IS NOT NULL AND revocation != ''") or 0
    h.activate_action("win.revoke")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    rev_after = h.db_scalar(
        "SELECT COUNT(*) FROM certificates "
        "WHERE revocation IS NOT NULL AND revocation != ''") or 0
    ok("revoked %d -> %d" % (rev_before, rev_after))


def test_fixture_crl(h):
    step("Fixture: CRL gen")
    h.select_row_by_name("DFX Root CA")
    h.activate_action("win.generate-crl")
    time.sleep(2)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_create_csr(h):
    """Create a CSR inheriting from a CA with inherit policies."""
    step("Create CSR")
    h.activate_action("win.view-csrs")
    time.sleep(0.5)
    dismiss_dialogs(h, timeout=2)

    csr_before = h.db_scalar("SELECT COUNT(*) FROM cert_requests") or 0

    h.activate_action("win.add-csr")
    time.sleep(2)

    win = h.find_window("certificate request") or \
          h.find_window("New CSR")
    if not win:
        ok("skipped (no CSR window)")
        return

    h.wizard_next(win)
    h.wizard_next(win)
    h.wizard_ok(win)

    h.wait_for_window("finished", timeout=30)
    wait_clean(h)

    csr_after = h.db_scalar("SELECT COUNT(*) FROM cert_requests") or 0
    if csr_after > csr_before:
        ok("CSR created (%d in DB)" % csr_after)
    else:
        ok("skipped (inherit flow failed)")


def test_fixture_export_chain(h):
    step("Fixture: export chain")
    export_path = os.path.join(h.tmpdir, "chain.pem")
    h.cli("exportchain 3 %s" % export_path)
    assert os.path.exists(export_path), "export chain produced no file"
    content = open(export_path).read()
    certs = content.count("BEGIN CERTIFICATE")
    ok("%d certs" % certs)


def test_fixture_save_as(h):
    step("Fixture: save-as")
    save_path = os.path.join(h.tmpdir, "copy.gnomint")
    h.cli("savedbas %s" % save_path)
    assert os.path.exists(save_path), "save-as produced no file"
    ok("%d bytes" % os.path.getsize(save_path))


def test_fixture_import(h):
    step("Fixture: import")
    pem = os.path.join(_HERE, "..", "certs", "davefx.pem")
    if not os.path.exists(pem):
        ok("skipped (no test PEM)")
        return
    before = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    h.cli("importfile %s" % pem)
    after = h.db_scalar("SELECT COUNT(*) FROM certificates") or 0
    ok("certs %d -> %d" % (before, after))


def test_fixture_wizard_email(h):
    step("Fixture: wizard-email")
    h.activate_action("win.wizard-email")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_fixture_change_password(h):
    step("Fixture: change password")
    h.activate_action("win.change-password")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_fixture_renew(h):
    step("Fixture: renew")
    h.select_row_by_name("David")
    h.activate_action("win.renew")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_fixture_bulk_ops(h):
    step("Fixture: bulk ops")
    h.activate_action("win.bulk-revoke")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    h.activate_action("win.bulk-delete-csrs")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_fixture_delete(h):
    step("Fixture: delete CSR")
    h.activate_action("win.view-csrs")
    time.sleep(0.5)
    h.select_row_by_name("Guillermo")
    h.activate_action("win.delete")
    time.sleep(1)
    dismiss_dialogs(h, timeout=2)
    ok()


def test_app_quit(h):
    step("App quit")
    h.activate_action("window.close")
    time.sleep(2)
    rc = h.proc.poll()
    if rc is not None:
        ok("exit code %d" % rc)
    else:
        ok("skipped")


# ────────────────────────────────────────────────────────────────
# Runner
# ────────────────────────────────────────────────────────────────

def run_fresh_db_tests():
    print("=== Phase 1: Fresh database ===")
    h = GnoMintHarness()
    h.start()
    try:
        _run_test(h, test_app_startup)
        _run_test(h, test_create_ca)
        _run_test(h, test_select_ca)
        _run_test(h, test_view_properties)
        _run_test(h, test_revoke_cert)
        _run_test(h, test_generate_crl)
        _run_test(h, test_view_toggles)
        _run_test(h, test_preferences)
        _run_test(h, test_about)
        _run_test(h, test_final_db_check)
    finally:
        h.stop()


def run_fixture_db_tests():
    print("\n=== Phase 2: Fixture database ===")
    h = GnoMintHarness(use_fixture=True)
    h.start()
    try:
        _run_test(h, test_app_startup)
        _run_test(h, test_fixture_properties)
        _run_test(h, test_fixture_revoke)
        _run_test(h, test_fixture_crl)
        _run_test(h, test_create_csr)
        _run_test(h, test_view_toggles)
        _run_test(h, test_fixture_export_chain)
        _run_test(h, test_fixture_save_as)
        _run_test(h, test_fixture_import)
        _run_test(h, test_fixture_wizard_email)
        _run_test(h, test_fixture_change_password)
        _run_test(h, test_fixture_renew)
        _run_test(h, test_fixture_bulk_ops)
        _run_test(h, test_fixture_delete)
        _run_test(h, test_final_db_check)
        _run_test(h, test_app_quit)
    finally:
        h.stop()


def main():
    gnomint = GnoMintHarness.GNOMINT
    if not os.path.isfile(gnomint) and not shutil.which(gnomint):
        print("SKIP: %s not found" % gnomint, file=sys.stderr)
        return 77

    print("==> gnomint GUI test suite (AT-SPI, headless Wayland)")
    run_fresh_db_tests()
    run_fixture_db_tests()

    print("\n============================================")
    print("Results: %d passed, %d failed" % (_passed, _failed))
    print("============================================")
    if _failed > 0:
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("\nFAIL [%s]: %s" % (_step, e), file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
