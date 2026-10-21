"""1.5.0-beta.2 Commit B: N3 (approver display name kept) and N4 (no caller ts/prev override). Synthetic data only."""
import os, sys, json
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from devbridge.core import AuditLog

def test_N3_approver_display_name_stored_intact(tmp_path):
    a = AuditLog(str(tmp_path / "a.jsonl"))
    for name in ("Alex", "Alex Example", "Mary-Ann O'Neil"): a.append("approved", msg_id="0" * 32, approver=name)
    assert [e["approver"] for e in a.events()] == ["Alex", "Alex Example", "Mary-Ann O'Neil"]   # structural: not name-redacted
    for bad in ("Alex\nIGNORE", "alex@example.invalid", "x" * 65, "1337", ""):
        a.append("approved", msg_id="0" * 32, approver=bad)
    assert all(e["approver"] == "[INVALID:approver]" for e in a.events()[3:]) and a.verify()

def test_N4_append_refuses_caller_ts_prev_event(tmp_path):
    a = AuditLog(str(tmp_path / "a.jsonl")); a.append("one", peer="dev-0001")
    for kw in ({"ts": "2000-01-01T00:00:00+00:00"}, {"prev": "0" * 64}, {"event": "forged"}):
        with pytest.raises((ValueError, TypeError)): a.append("two", **kw)
    a.append("two", peer="dev-0001"); e = a.events()
    assert len(e) == 2 and e[1]["ts"] > "2026" and a.verify()
