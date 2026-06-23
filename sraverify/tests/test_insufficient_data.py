"""
Validation for the INSUFFICIENT_DATA / no-org-access behavior.

Verifies, without any AWS calls:
  1. requires_org_access is False for exactly the application checks and True for
     every management / audit / log-archive check (63 vs 95 in the current tree).
  2. build_insufficient_data_findings() emits a single INSUFFICIENT_DATA finding.
  3. set_org_access()/detect_org_access() honor an explicit override.

Run with: python -m pytest sraverify/tests/test_insufficient_data.py
or simply: python sraverify/tests/test_insufficient_data.py
"""
import os
import re
import glob

from sraverify.core.check import SecurityCheck, INSUFFICIENT_DATA
from sraverify.main import ALL_CHECKS


SERVICES_DIR = os.path.join(os.path.dirname(__file__), "..", "sraverify", "services")


def _expected_requires_org_access():
    """Classify every check by account_type directly from source as an independent oracle."""
    expected = {}
    for svc in sorted(os.listdir(SERVICES_DIR)):
        svc_dir = os.path.join(SERVICES_DIR, svc)
        if not os.path.isdir(svc_dir):
            continue
        base = os.path.join(svc_dir, "base.py")
        base_src = open(base).read() if os.path.exists(base) else ""
        base_m = re.search(r'account_type="([a-z-]*)"', base_src)
        base_type = base_m.group(1) if base_m else None
        for f in glob.glob(os.path.join(svc_dir, "checks", "sra_*.py")):
            src = open(f).read()
            cid = re.search(r'self\.check_id\s*=\s*"([^"]+)"', src)
            if not cid:
                continue
            ov = re.search(r'self\.account_type\s*=\s*"([a-z-]*)"', src)
            eff = ov.group(1) if ov else base_type
            expected[cid.group(1)] = (eff != "application")
    return expected


def test_requires_org_access_classification():
    expected = _expected_requires_org_access()
    mismatches = []
    for check_id, check_class in ALL_CHECKS.items():
        got = check_class().requires_org_access
        want = expected.get(check_id)
        if want is None:
            continue
        if got != want:
            mismatches.append((check_id, got, want))
    assert not mismatches, f"requires_org_access mismatches: {mismatches}"

    app = sum(1 for v in expected.values() if v is False)
    org = sum(1 for v in expected.values() if v is True)
    # Guardrail on the current tree: 63 standalone, 95 org-dependent.
    assert app == 63, f"expected 63 application checks, got {app}"
    assert org == 95, f"expected 95 org-dependent checks, got {org}"


def test_build_insufficient_data_findings():
    # Use any org-dependent check class
    check = next(c() for c in ALL_CHECKS.values() if c().requires_org_access)
    check.account_info = {"account_id": "111111111111", "account_name": "test"}
    check.findings = []
    findings = check.build_insufficient_data_findings()
    assert len(findings) == 1
    assert findings[0]["Status"] == INSUFFICIENT_DATA
    assert findings[0]["Region"] == "global"
    assert findings[0]["AccountId"] == "111111111111"


def test_org_access_override():
    SecurityCheck.set_org_access(False)
    assert SecurityCheck.detect_org_access(None) is False
    SecurityCheck.set_org_access(True)
    assert SecurityCheck.detect_org_access(None) is True
    SecurityCheck.set_org_access(None)  # reset


if __name__ == "__main__":
    test_requires_org_access_classification()
    test_build_insufficient_data_findings()
    test_org_access_override()
    print("All INSUFFICIENT_DATA validations passed.")
