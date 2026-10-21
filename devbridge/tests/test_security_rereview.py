"""Regressions for the security reviewer's re-reviews: E1-E3, K1, K2, L1, beta flag, and the cheap LATER items. Synthetic only."""
import io, json, os, stat, sys
from datetime import datetime, timedelta
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from conftest import pin
from devbridge.core import Identity, Allowlist, Node, Reject, make_envelope
from devbridge.transports import FileMailbox
from devbridge.revoke import (revoke, erase, new_seal_key, sign_erase_permit, set_hold, release_hold, sign_rotation,
                              apply_rotation, load_pinned_admin_pub)
from devbridge import cli, beta

def _open_all(q):
    if os.path.exists(q): os.chmod(q, 0o700)
    for d, ds, fs in os.walk(q):
        for x in ds + fs: os.chmod(os.path.join(d, x), 0o700)

@pytest.fixture
def S(tmp_path):
    ids = {n: Identity.generate(n) for n in ("owner-bot", "dev-a-bot", "dev-b-bot")}
    al = Allowlist()
    for n, ns, to in (("owner-bot", "owner", ["dev-a-bot", "dev-b-bot"]), ("dev-a-bot", "dev-a", ["owner-bot"]), ("dev-b-bot", "dev-b", ["owner-bot"])):
        al.add(n, ids[n].pub_b64, ns, to)
    alp = str(tmp_path / "allow.json"); al.save(alp); d = tmp_path / "dev-a-state"; d.mkdir(); (d / "x").write_text("synthetic")
    q, audit, holds = str(tmp_path / "q"), str(tmp_path / "admin.jsonl"), str(tmp_path / "holds.json")
    m = revoke("dev-a-bot", allowlist=al, allowlist_path=alp, revoked_path=str(tmp_path / "rev.json"), quarantine_root=q,
               seal_key_path=new_seal_key(str(tmp_path / "k")), paths=[str(d)], audit_path=audit, reason="t")
    P = pin(ids["owner-bot"].pub_b64); permit = sign_erase_permit(ids["owner-bot"], "dev-a-bot", m["sha256"], "owner", "yes")
    kw = dict(quarantine_root=q, audit_path=audit, reason="r", confirm=True, typed="erase dev-a-bot", permit=permit,
              admin_pin_path=P, holds_path=holds)
    yield ids, al, m, kw, tmp_path
    _open_all(os.path.join(q, "dev-a-bot"))

later = lambda d: datetime.now().astimezone() + timedelta(days=d)

# E1
@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_E1_hold_days_zero_ignored(S):
    ids, al, m, kw, tmp = S
    with pytest.raises(PermissionError, match="hold 30 days"): erase("dev-a-bot", hold_days=0, now=later(1), **kw)
# E2
@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_E2_backdated_seal_json_ignored_and_tombstone_uses_audit_time(S):
    ids, al, m, kw, tmp = S; qd = os.path.join(kw["quarantine_root"], "dev-a-bot"); os.chmod(qd, 0o700); sj = os.path.join(qd, "seal.json")
    os.chmod(sj, 0o600); j = json.load(open(sj)); j["sealed_at"] = later(-90).isoformat(timespec="seconds"); json.dump(j, open(sj, "w")); os.chmod(qd, 0o000)
    with pytest.raises(PermissionError, match="hold"): erase("dev-a-bot", now=later(1), **kw)
    erase("dev-a-bot", now=later(31), **kw)
    ev = [json.loads(l) for l in open(kw["audit_path"])]
    first = [e for e in ev if e["event"] == "sealed"][0]["ts"]; tomb = [e for e in ev if e["event"] == "erased_tombstone"][0]
    assert tomb["sealed_at"] == first != j["sealed_at"]
# E3
def test_E3_cli_refuses_piped_stdin(S, monkeypatch, capsys):
    ids, al, m, kw, tmp = S; monkeypatch.setattr(beta, "BETA_BUILD", False)
    pf = tmp / "permit.json"; pf.write_text(json.dumps(kw["permit"])); monkeypatch.setattr(sys, "stdin", io.StringIO("erase dev-a-bot\n"))
    rc = cli.main(["erase", "dev-a-bot", "--confirm", "--quarantine", kw["quarantine_root"], "--audit", kw["audit_path"], "--reason", "r",
                   "--permit", str(pf), "--admin-pin", kw["admin_pin_path"], "--hold-days", "0"])
    assert rc == 2 and "real terminal" in capsys.readouterr().err and os.path.exists(os.path.join(kw["quarantine_root"], "dev-a-bot"))
@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_E3_permit_must_be_pinned_admin_and_this_blob(S):
    ids, al, m, kw, tmp = S
    for bad in (sign_erase_permit(ids["dev-b-bot"], "dev-a-bot", m["sha256"], "owner", "yes"),     # wrong signer
                sign_erase_permit(ids["owner-bot"], "dev-a-bot", "0" * 64, "owner", "yes"),           # wrong blob
                {**kw["permit"], "peer": "dev-b-bot"}):                                          # tampered
        with pytest.raises(PermissionError, match="permit"): erase("dev-a-bot", now=later(31), **{**kw, "permit": bad})
def test_E3_permit_needs_typed_yes(S):
    ids, al, m, kw, tmp = S
    with pytest.raises(PermissionError): sign_erase_permit(ids["owner-bot"], "dev-a-bot", m["sha256"], "owner", "ok")
# K1
def test_K1_pin_must_be_readonly_and_not_bot_owned(tmp_path, monkeypatch):
    p = pin(Identity.generate("owner-bot").pub_b64)
    with pytest.raises(PermissionError, match="owned outside"): load_pinned_admin_pub(p)  # strict default: bot-owned refused
    import devbridge.revoke as R; monkeypatch.setattr(R, "_pin_owner_ok", lambda st: True)
    assert load_pinned_admin_pub(p)
    os.chmod(p, 0o644)
    with pytest.raises(PermissionError, match="read-only"): load_pinned_admin_pub(p)
def test_K1_cli_rotate_admin_key_must_match_pin(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(beta, "BETA_BUILD", False); k = tmp_path / "keys"; al = str(tmp_path / "al.json")
    import devbridge.revoke as R; monkeypatch.setattr(R, "_pin_owner_ok", lambda st: True)  # tests can't make root-owned pins
    for b in ("owner-bot", "dev-a-bot", "evil-admin"): cli.main(["keygen", "--id", b, "--out", str(k)])
    cli.main(["keygen", "--id", "dev-a-bot", "--out", str(tmp_path / "k2")])
    for b, ns, to in (("owner-bot", "owner", "dev-a-bot"), ("dev-a-bot", "dev-a", "owner-bot")):
        cli.main(["allow", "--allowlist", al, "--revoked", al + ".rev", "--pubfile", str(k / f"{b}.pub.json"), "--namespace", ns, "--may-send-to", to])
    P = pin(json.load(open(k / "owner-bot.pub.json"))["pub"])
    rc = cli.main(["rotate", "dev-a-bot", str(tmp_path / "k2" / "dev-a-bot.pub.json"), "--admin-key", str(k / "evil-admin.key"), "--allowlist", al,
                   "--rotations", str(tmp_path / "rot.json"), "--audit", str(tmp_path / "a.jsonl"), "--revoked", al + ".rev", "--admin-pin", P])
    assert rc == 2 and "does not match the pinned" in capsys.readouterr().err and json.load(open(al))["dev-a-bot"]["pub"] == json.load(open(k / "dev-a-bot.pub.json"))["pub"]
# K2
@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_K2_rotate_to_revoked_key_refused(S):
    ids, al, m, kw, tmp = S  # dev-a-bot's key is revoked in S; try to rotate dev-b to it
    rec = sign_rotation(ids["owner-bot"], "dev-b-bot", ids["dev-b-bot"].pub_b64, ids["dev-a-bot"].pub_b64)
    with pytest.raises(PermissionError, match="retired"):
        apply_rotation(rec, allowlist=al, allowlist_path=str(tmp / "allow.json"), rotations_path=str(tmp / "rot.json"),
                       audit_path=kw["audit_path"], admin_pin_path=kw["admin_pin_path"])
@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_K2_rotated_key_retired_forever(S):
    ids, al, m, kw, tmp = S; new = Identity("dev-b-bot", Identity.generate("dev-b-bot").priv); old = ids["dev-b-bot"].pub_b64
    rec = sign_rotation(ids["owner-bot"], "dev-b-bot", old, new.pub_b64)
    apply_rotation(rec, allowlist=al, allowlist_path=str(tmp / "allow.json"), rotations_path=str(tmp / "rot.json"),
                   audit_path=kw["audit_path"], admin_pin_path=kw["admin_pin_path"])
    back = sign_rotation(ids["owner-bot"], "dev-b-bot", new.pub_b64, old)  # rotate back to the old key
    with pytest.raises(PermissionError, match="retired"):
        apply_rotation(back, allowlist=al, allowlist_path=str(tmp / "allow.json"), rotations_path=str(tmp / "rot.json"),
                       audit_path=kw["audit_path"], admin_pin_path=kw["admin_pin_path"])
    with pytest.raises(ValueError, match="retired"): al.add("dev-c-bot", old, "dev-c", ["owner-bot"])
def test_K2_receive_rejects_retired_key_even_if_restored(S):
    ids, al, m, kw, tmp = S; al2 = Allowlist(dict(al.peers), dict(al.revoked), {ids["dev-b-bot"].pub_b64: {"peer": "dev-b-bot", "revoked_at": "x"}})
    ownr = Node(ids["owner-bot"], al2, FileMailbox(tmp / "mb"), str(tmp / "rs"))
    with pytest.raises(Reject) as r: ownr.accept(make_envelope(ids["dev-b-bot"], "owner-bot", "info", {}))
    assert r.value.code == "key_retired"
# L1
@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_L1_missing_holds_file_after_hold_fails_closed(S):
    ids, al, m, kw, tmp = S; set_hold("dev-b-bot", holds_path=kw["holds_path"], audit_path=kw["audit_path"], reason="other dev")
    os.rename(kw["holds_path"], str(tmp / "holds.moved"))
    with pytest.raises(PermissionError, match="legal hold"): erase("dev-a-bot", now=later(31), **kw)
    os.remove(kw["holds_path"] + ".ever")  # even without the sentinel, the audit shows a hold
    with pytest.raises(PermissionError, match="legal hold"): erase("dev-a-bot", now=later(31), **kw)
@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_L1_corrupt_holds_fails_closed_and_release_refused(S):
    ids, al, m, kw, tmp = S; open(kw["holds_path"], "w").write("{corrupt")
    with pytest.raises(PermissionError, match="legal hold"): erase("dev-a-bot", now=later(31), **kw)
    with pytest.raises(PermissionError): release_hold("dev-a-bot", holds_path=kw["holds_path"], audit_path=kw["audit_path"])
# beta flag
def test_beta_build_disables_erase_and_rotate(capsys):
    assert beta.BETA_BUILD is True
    assert cli.main(["erase", "x-bot", "--quarantine", "q", "--audit", "a", "--reason", "r", "--permit", "p", "--confirm"]) == 3
    assert cli.main(["rotate", "x-bot", "n.json", "--admin-key", "k", "--allowlist", "a", "--rotations", "r", "--audit", "a", "--revoked", "v"]) == 3
    assert capsys.readouterr().err.count("BETA-DISABLED:") == 2
# cheap LATER items
def test_node_refuses_start_on_broken_audit(tmp_path):
    i = Identity.generate("owner-bot"); n = Node(i, Allowlist(), FileMailbox(tmp_path / "m"), str(tmp_path / "s")); n.audit.append("x")
    open(n.audit.path, "a").write("garbage\n")
    with pytest.raises(RuntimeError, match="fail closed"): Node(i, Allowlist(), FileMailbox(tmp_path / "m"), str(tmp_path / "s"))
def test_rate_rebuilt_from_audit_when_state_deleted(S):
    ids, al, m, kw, tmp = S; mk = lambda: Node(ids["owner-bot"], al, FileMailbox(tmp / "mb"), str(tmp / "rr"), rate_per_min=3)
    n = mk()
    for i in range(3): n.accept(make_envelope(ids["dev-b-bot"], "owner-bot", "info", {"i": i}))
    os.rename(tmp / "rr" / "state.json", tmp / "state.moved")
    with pytest.raises(Reject) as r: mk().accept(make_envelope(ids["dev-b-bot"], "owner-bot", "info", {"i": 9}))
    assert r.value.code == "rate_limited"
def test_cli_requires_existing_revoked_list(tmp_path):
    k = tmp_path / "k"; cli.main(["keygen", "--id", "dev-a-bot", "--out", str(k)]); al = str(tmp_path / "al.json")
    cli.main(["allow", "--allowlist", al, "--revoked", al + ".rev", "--pubfile", str(k / "dev-a-bot.pub.json"), "--namespace", "d", "--may-send-to", "owner-bot"])
    os.rename(al + ".rev", al + ".moved")
    assert cli.main(["send", "--key", str(k / "dev-a-bot.key"), "--allowlist", al, "--revoked", al + ".rev", "--mailbox", str(tmp_path / "m"),
                     "--state", str(tmp_path / "s"), "--to", "owner-bot", "--body", "{}"]) == 2
def test_seal_key_unsafe_refused(S):
    ids, al, m, kw, tmp = S; k = tmp / "loose.key"; new_seal_key(str(k)); os.chmod(k, 0o644); d = tmp / "s2"; d.mkdir()
    with pytest.raises(PermissionError, match="seal key"):
        revoke("dev-b-bot", allowlist=al, allowlist_path=str(tmp / "allow.json"), revoked_path=str(tmp / "rev.json"), quarantine_root=str(tmp / "q2"),
               seal_key_path=str(k), paths=[str(d)], audit_path=str(tmp / "a2.jsonl"), reason="t")
