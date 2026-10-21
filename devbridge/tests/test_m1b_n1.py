"""M1b + N1 regressions (security re-review). Synthetic data only."""
import json, os, random, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from devbridge.core import Identity, Allowlist, Node, Reject, AuditLog, make_envelope
from devbridge.transports import FileMailbox
import devbridge.revoke as R

# M1b
def test_M1b_no_relax_module_attribute():
    names = [n for n in vars(R) if "RELAX" in n.upper() or "TEST_ONLY" in n.upper()]
    assert not hasattr(R, "_TEST_ONLY_RELAX_PIN_OWNER") and names == []
    # no module-level bool switch ships in revoke.py at all
    assert [n for n, v in vars(R).items() if isinstance(v, bool)] == []
    # owner check is a function, not a flag; plain prod use refuses a bot-owned pin
    assert callable(R._pin_owner_ok)

# N1
def test_N1_structural_fields_not_redacted_body_redacted(tmp_path):
    al = AuditLog(str(tmp_path / "a.jsonl"))
    mid = "f1e2d3c4b5a69788f1e2d3c4b5a69788"   # 32 hex, no '0' (matched sol_wallet_like before N1)  # leakcheck: synthetic
    assert "0" not in mid and len(mid) == 32
    al.append("accepted", msg_id=mid, frm="dev-a-bot", type="info", thread=mid, echo=False,
              note="key sk-live-ABCDEFGHIJKLMNOP1234 here")
    al.append("rejected", code="schema", msg_id="not-a-hex-id; DROP", frm="x" * 200)
    e1, e2 = al.events()
    assert e1["msg_id"] == mid and e1["thread"] == mid and e1["frm"] == "dev-a-bot"
    assert "REDACTED" in e1["note"] and "ABCDEFGHIJ" not in e1["note"]
    assert e2["msg_id"] == "[INVALID:msg_id]" and e2["frm"] == "[INVALID:frm]" and al.verify()

def _noz_hex(rng): return "".join(rng.choice("123456789abcdef") for _ in range(32))  # leakcheck: synthetic
def _hex(rng): return "".join(rng.choice("0123456789abcdef") for _ in range(32))  # leakcheck: synthetic

def test_N1_replay_rebuild_from_audit_random_msg_ids(tmp_path, monkeypatch):
    import types, devbridge.core as C
    pool = []
    monkeypatch.setattr(C.uuid, "uuid4", lambda: types.SimpleNamespace(hex=pool.pop()))
    rng = random.Random(20261020)
    ids = {n: Identity.generate(n) for n in ("owner-bot", "dev-a-bot", "dev-b-bot")}
    al = Allowlist()
    al.add("owner-bot", ids["owner-bot"].pub_b64, "owner", ["dev-a-bot", "dev-b-bot"])
    for d in ("dev-a-bot", "dev-b-bot"): al.add(d, ids[d].pub_b64, d[:5], ["owner-bot"])
    mb = FileMailbox(tmp_path / "mail"); sd = str(tmp_path / "owner")
    mk = lambda: Node(ids["owner-bot"], al, mb, sd, rate_per_min=10**6, new_threads_per_min=10**6, thread_reply_budget=10**6)
    n = mk(); envs, owner = [], {}
    for i in range(300):
        frm = "dev-a-bot" if i % 2 else "dev-b-bot"
        pool.append(_noz_hex(rng) if i % 2 == 0 else _hex(rng))   # msg_id: half guaranteed no '0'
        e = make_envelope(ids[frm], "owner-bot", "info", {"i": i}, thread=(_noz_hex(rng) if i % 3 else _hex(rng)))
        envs.append(e); owner[e["thread"]] = frm; n.accept(e)
    nozero = [e for e in envs if "0" not in e["msg_id"]] + [e for e in envs if "0" not in e["thread"]]
    assert len(nozero) > 250   # plenty of ids that used to be redacted as sol_wallet_like
    os.remove(os.path.join(sd, "seen.jsonl")); os.remove(os.path.join(sd, "state.json"))
    n2 = mk()
    for e in envs: assert e["thread"] in n2.thread_owner and n2.thread_owner[e["thread"]] == owner[e["thread"]]
    for e in envs:
        with pytest.raises(Reject) as r: n2.accept(e)
        assert r.value.code == "replay"
