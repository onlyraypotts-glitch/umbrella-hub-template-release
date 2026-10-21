"""Regression tests for the security reviewer's security/QA review. Synthetic keys only."""
import hashlib, json, os, stat, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from devbridge.core import Identity, Allowlist, Node, Reject, AuditLog, make_envelope, redact
from devbridge.transports import FileMailbox

mode = lambda p: stat.S_IMODE(os.stat(p).st_mode)

@pytest.fixture
def net(tmp_path):
    ids = {n: Identity.generate(n) for n in ("owner-bot", "dev-a-bot")}
    al = Allowlist()
    al.add("owner-bot", ids["owner-bot"].pub_b64, "owner", ["dev-a-bot"]); al.add("dev-a-bot", ids["dev-a-bot"].pub_b64, "dev-a", ["owner-bot"])
    mb = FileMailbox(tmp_path / "mail")
    mk = lambda n, st=None, **kw: Node(ids[n], al, mb, str(tmp_path / (st or n)), **kw)
    return ids, al, mb, mk, tmp_path

def _drop(mb, name, content):
    p = os.path.join(mb._inbox("owner-bot"), name); open(p, "w").write(content); return p

# F1
@pytest.mark.parametrize("mut", [{"from": ["x"]}, {"sig": 5}, {"msg_id": ["x"]}, {"hops": True}, {"ts": 7}, {"body": "s"}])
def test_F1_malformed_fields_reject_not_crash(net, mut):
    ids, al, mb, mk, _ = net; e = make_envelope(ids["dev-a-bot"], "owner-bot", "info", {}); e.update(mut)
    with pytest.raises(Reject): mk("owner-bot").accept(e)
def test_F1_bad_message_does_not_stop_loop(net):
    ids, al, mb, mk, _ = net; ownr, a = mk("owner-bot"), mk("dev-a-bot")
    bad = make_envelope(ids["dev-a-bot"], "owner-bot", "info", {}); bad["from"] = ["x"]
    _drop(mb, "0" * 32 + ".json", json.dumps(bad)); _drop(mb, "1" * 32 + ".json", "[" * 5000)
    a.send("owner-bot", "info", {"t": "after"}); g, b = ownr.recv_all()
    assert len(g) == 1 and len(b) == 2
# F2
def test_F2_symlink_not_followed(net, tmp_path):
    ids, al, mb, mk, _ = net; out = tmp_path / "outside.json"; out.write_text(json.dumps({"to": "owner-bot", "leak": "x"}))
    os.symlink(out, os.path.join(mb._inbox("owner-bot"), "s.json"))
    got = list(mb.recv("owner-bot")); assert got[0]["_transport_reject"] == "not_regular_file" and "leak" not in got[0]
    assert os.path.islink(tmp_path / "mail" / "owner-bot" / "quarantine" / "s.json")  # kept, not deleted
# F3
def test_F3_oversize_rejected_before_read(net, monkeypatch):
    ids, al, mb, mk, _ = net; _drop(mb, "big.json", "A" * (2 * 1024 * 1024)); reads = []
    import builtins; real = os.read
    got = list(mb.recv("owner-bot")); assert got == [{"_transport_reject": "too_large", "file": "big.json"}]
    with pytest.raises(Reject) as r: mk("owner-bot").accept(got[0])
    assert r.value.code == "too_large"
# F4
def test_F4_corrupt_seen_tolerated_and_replay_still_blocked(net, tmp_path):
    ids, al, mb, mk, _ = net; ownr = mk("owner-bot"); e = make_envelope(ids["dev-a-bot"], "owner-bot", "info", {}); ownr.accept(e)
    open(tmp_path / "owner-bot" / "seen.jsonl", "a").write("{bad\n\x00garbage\n")
    r2 = mk("owner-bot"); assert len(r2.warnings) == 2
    with pytest.raises(Reject) as r: r2.accept(e)
    assert r.value.code == "replay" and mode(tmp_path / "owner-bot" / "seen.jsonl") == 0o600
def test_F4_seen_deleted_rebuilt_from_audit(net, tmp_path):
    ids, al, mb, mk, _ = net; e = make_envelope(ids["dev-a-bot"], "owner-bot", "info", {}); mk("owner-bot").accept(e)
    os.rename(tmp_path / "owner-bot" / "seen.jsonl", tmp_path / "seen.moved")
    with pytest.raises(Reject) as r: mk("owner-bot").accept(e)
    assert r.value.code == "replay"
# F5
def test_F5_rate_persists_across_restart(net):
    ids, al, mb, mk, _ = net; n = mk("owner-bot", rate_per_min=3)
    for i in range(3): n.accept(make_envelope(ids["dev-a-bot"], "owner-bot", "info", {"i": i}))
    with pytest.raises(Reject) as r: mk("owner-bot", rate_per_min=3).accept(make_envelope(ids["dev-a-bot"], "owner-bot", "info", {"i": 9}))
    assert r.value.code == "rate_limited"
def test_F5_echo_persists_across_restart(net):
    ids, al, mb, mk, _ = net; mk("owner-bot").accept(make_envelope(ids["dev-a-bot"], "owner-bot", "info", {"s": 1}, thread="th1"))
    assert mk("owner-bot").accept(make_envelope(ids["dev-a-bot"], "owner-bot", "info", {"s": 1}, thread="th1"))["_echo"] is True
# F8
def test_F8_new_thread_cap_and_persisted_budget(net):
    ids, al, mb, mk, _ = net; n = mk("owner-bot", new_threads_per_min=2)
    for _ in range(2): n.accept(make_envelope(ids["dev-a-bot"], "owner-bot", "info", {"x": _}))
    with pytest.raises(Reject) as r: mk("owner-bot", new_threads_per_min=2).accept(make_envelope(ids["dev-a-bot"], "owner-bot", "info", {}))
    assert r.value.code == "thread_rate"
    n2 = mk("owner-bot", "owner2", thread_reply_budget=1)
    m = n2.accept(make_envelope(ids["dev-a-bot"], "owner-bot", "info", {"q": 1}, thread="tt")); assert n2.auto_ack(m)
    m = mk("owner-bot", "owner2", thread_reply_budget=1).accept(make_envelope(ids["dev-a-bot"], "owner-bot", "info", {"q": 2}, thread="tt", hops=0))
    assert mk("owner-bot", "owner2", thread_reply_budget=1).may_auto_reply(m) is False  # hops reset to 0 does not reopen budget
# F6
def test_F6_audit_truncation_detected(tmp_path):
    a = AuditLog(str(tmp_path / "a.jsonl")); [a.append("e", i=i) for i in range(5)]
    L = open(a.path).read().splitlines(); open(a.path, "w").write("\n".join(L[:3]) + "\n"); assert a.verify() is False
def test_F6_audit_forged_chain_detected(tmp_path):
    a = AuditLog(str(tmp_path / "a.jsonl")); [a.append("e", i=i) for i in range(3)]; prev, out = "0" * 64, []
    for i in range(3):
        s = json.dumps({"event": "forged", "i": i, "prev": prev, "ts": "x"}, sort_keys=True); out.append(s); prev = hashlib.sha256(s.encode()).hexdigest()
    open(a.path, "w").write("\n".join(out) + "\n"); assert a.verify() is False
def test_F6_audit_garbage_returns_false(tmp_path):
    a = AuditLog(str(tmp_path / "a.jsonl")); a.append("e"); open(a.path, "a").write("garbage\n"); assert a.verify() is False
    a2 = AuditLog(str(tmp_path / "b.jsonl")); a2.append("e"); assert a2.verify() is True and mode(a2.head_path) == 0o600
# F7
def test_F7_perms_0600_0700(net, tmp_path):
    ids, al, mb, mk, _ = net; ownr = mk("owner-bot"); mk("dev-a-bot").send("owner-bot", "info", {}); ownr.recv_all()
    al.save(str(tmp_path / "allow.json"))
    assert mode(tmp_path / "mail") == 0o700 and mode(tmp_path / "allow.json") == 0o600
    for d, _, fs in os.walk(tmp_path):
        assert mode(d) & 0o077 == 0 or d == str(tmp_path)
        for f in fs: assert mode(os.path.join(d, f)) & 0o077 == 0, f
# F9
def test_F9_refuses_loose_private_key(tmp_path):
    p = Identity.generate("dev-a-bot").save(str(tmp_path / "k")); Identity.load(p)
    os.chmod(p, 0o640)
    with pytest.raises(PermissionError): Identity.load(p)
    os.chmod(p, 0o604)
    with pytest.raises(PermissionError): Identity.load(p)
# F10
def test_F10_redacts_dict_keys_and_split_keys():
    tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    out = json.dumps(redact({tok: 1, "k": "sk-" + "live-abc def ghi jkl"})); assert tok not in out and "abc def" not in out
# F11
def test_F11_msg_id_and_thread_validated(net):
    ids, al, mb, mk, _ = net
    with pytest.raises(ValueError): mb.send({"to": "owner-bot", "msg_id": "../../dev-b/inbox/evil"})
    with pytest.raises(ValueError): make_envelope(ids["dev-a-bot"], "owner-bot", "info", {}, thread="../x")
    e = make_envelope(ids["dev-a-bot"], "owner-bot", "info", {}); e["msg_id"] = "Z" * 32
    with pytest.raises(Reject) as r: mk("owner-bot").accept(e)
    assert r.value.code == "schema"
