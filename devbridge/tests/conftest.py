import json, os, tempfile

def pin(pub_b64):
    """Test-only pinned admin pub: separate 0700 dir, file 0444. (Production: root-owned, see README K1.)"""
    d = tempfile.mkdtemp(prefix="admin-pin-"); p = os.path.join(d, "admin.pub")
    with open(p, "w") as f: json.dump({"pub": pub_b64}, f)
    os.chmod(p, 0o444); return p

import pytest

@pytest.fixture
def relax_pin(monkeypatch):
    """M1: TEST-ONLY. Tests cannot create root-owned pins, so relax the owner check by monkeypatching the private helper _pin_owner_ok.
    There is no public keyword for this."""
    import devbridge.revoke as R; monkeypatch.setattr(R, "_pin_owner_ok", lambda st: True)

@pytest.fixture
def unlocked(monkeypatch, relax_pin):
    """M1: TEST-ONLY. Simulate a post-beta build so erase/rotate logic can be exercised."""
    from devbridge import beta; monkeypatch.setattr(beta, "BETA_BUILD", False)

# Synthetic owner name for redaction tests (configured, never a real name).
from devbridge import pii_scan as _pii
_pii.set_owner_names(["Alex Example"])
