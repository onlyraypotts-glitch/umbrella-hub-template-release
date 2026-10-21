"""Revoke (lockout + seal) and erase (separate, confirmed, after hold). Synthetic data and synthetic seal key only."""
import io, json, os, stat, sys, tarfile
from datetime import datetime, timedelta
import pytest
from conftest import pin
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from devbridge.core import Identity, Allowlist, Node, Reject, make_envelope
from devbridge.transports import FileMailbox
from devbridge.revoke import revoke, erase, new_seal_key, unseal_for_evidence, sign_erase_permit
from devbridge import cli

MARK = "SYNTHETIC-DEV-A-DATA-7f3c"

@pytest.fixture
def env(tmp_path):
    ids = {n: Identity.generate(n) for n in ("owner-bot", "dev-a-bot", "dev-b-bot")}
    al = Allowlist()
    al.add("owner-bot", ids["owner-bot"].pub_b64, "owner", ["dev-a-bot", "dev-b-bot"])
    al.add("dev-a-bot", ids["dev-a-bot"].pub_b64, "dev-a", ["owner-bot"]); al.add("dev-b-bot", ids["dev-b-bot"].pub_b64, "dev-b", ["owner-bot"])
    alp = str(tmp_path / "allow.json"); al.save(alp); mb = FileMailbox(tmp_path / "mail")
    a = Node(ids["dev-a-bot"], al, mb, str(tmp_path / "state-dev-a")); a.send("owner-bot", "info", {"t": MARK})
    ownr = Node(ids["owner-bot"], al, mb, str(tmp_path / "state-ownr")); ownr.send("dev-a-bot", "info", {"t": MARK})
    repo = tmp_path / "dev-a-template-checkout"; repo.mkdir(); (repo / "notes.md").write_text(MARK)
    paths = [str(tmp_path / "mail" / "dev-a-bot"), str(tmp_path / "state-dev-a"), str(repo)]
    key = new_seal_key(str(tmp_path / "seal.key"))
    kw = dict(allowlist=al, allowlist_path=alp, revoked_path=str(tmp_path / "revoked.json"), quarantine_root=str(tmp_path / "quarantine"),
              seal_key_path=key, paths=paths, audit_path=str(tmp_path / "admin-audit.jsonl"), reason="test revoke")
    return ids, al, mb, ownr, kw, tmp_path

def _open_all(q):  # test helper to restore perms so pytest can clean tmp
    for d, ds, fs in os.walk(q):
        for x in ds + fs: os.chmod(os.path.join(d, x), 0o700)

def test_revoke_locks_out_to_and_from(env):
    ids, al, mb, ownr, kw, tmp = env; revoke("dev-a-bot", **kw)
    with pytest.raises(Reject) as r: ownr.accept(make_envelope(ids["dev-a-bot"], "owner-bot", "hello", {}))
    assert r.value.code == "revoked"
    with pytest.raises(Reject) as r: ownr.send("dev-a-bot", "info", {})
    assert r.value.code == "revoked"
    assert ownr.accept(make_envelope(ids["dev-b-bot"], "owner-bot", "hello", {}))  # others unaffected
    os.chmod(kw["quarantine_root"] + "/dev-a-bot", 0o700); _open_all(kw["quarantine_root"])

def test_revoke_removes_allowlist_and_records_key(env):
    ids, al, mb, ownr, kw, tmp = env; revoke("dev-a-bot", **kw)
    saved = json.load(open(kw["allowlist_path"])); rev = json.load(open(kw["revoked_path"]))
    assert "dev-a-bot" not in saved and all("dev-a-bot" not in p["may_send_to"] for p in saved.values())
    assert rev["dev-a-bot"]["pub"] == ids["dev-a-bot"].pub_b64
    assert Allowlist.load(kw["allowlist_path"], kw["revoked_path"]).route_ok("owner-bot", "dev-a-bot") is False
    os.chmod(kw["quarantine_root"] + "/dev-a-bot", 0o700); _open_all(kw["quarantine_root"])

def test_revoke_seals_everything_encrypted_and_unreadable(env):
    ids, al, mb, ownr, kw, tmp = env; meta = revoke("dev-a-bot", **kw)
    assert meta["sources"] == 3 and not any(os.path.exists(p) for p in kw["paths"])  # mailbox, state, repo access all moved
    q = os.path.join(kw["quarantine_root"], "dev-a-bot"); assert stat.S_IMODE(os.stat(q).st_mode) == 0o000
    if os.geteuid() != 0:
        with pytest.raises(PermissionError): os.listdir(q)  # a dev's (non-root) user cannot read it
    tar = unseal_for_evidence("dev-a-bot", kw["quarantine_root"], kw["seal_key_path"])
    names = tarfile.open(fileobj=io.BytesIO(tar)).getnames(); assert any(n.endswith("notes.md") for n in names)
    os.chmod(q, 0o700); _open_all(q)
    blob = open([os.path.join(q, f) for f in os.listdir(q) if f.startswith("sealed-")][0], "rb").read()
    assert MARK.encode() not in blob  # encrypted at rest

def test_erase_without_confirm_refuses(env, capsys):
    ids, al, mb, ownr, kw, tmp = env; revoke("dev-a-bot", **kw)
    e = dict(quarantine_root=kw["quarantine_root"], audit_path=kw["audit_path"], reason="r", hold_days=0, permit={}, admin_pin_path=pin(ids["owner-bot"].pub_b64))
    with pytest.raises(PermissionError): erase("dev-a-bot", confirm=False, typed="erase dev-a-bot", **e)
    with pytest.raises(PermissionError): erase("dev-a-bot", confirm=True, typed="yes", **e)
    pf = tmp / "permit.json"; pf.write_text("{}"); ap = tmp / "admin.pub.json"; ap.write_text(json.dumps({"pub": ids["owner-bot"].pub_b64}))
    assert cli.main(["erase", "dev-a-bot", "--quarantine", kw["quarantine_root"], "--audit", kw["audit_path"], "--reason", "r",
                     "--permit", str(pf), "--confirm"]) == 3  # BETA-DISABLED
    assert os.path.isdir(os.path.join(kw["quarantine_root"], "dev-a-bot"))
    os.chmod(kw["quarantine_root"] + "/dev-a-bot", 0o700); _open_all(kw["quarantine_root"])

@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_erase_blocked_during_hold(env):
    ids, al, mb, ownr, kw, tmp = env; m = revoke("dev-a-bot", **kw)
    p = sign_erase_permit(ids["owner-bot"], "dev-a-bot", m["sha256"], "owner", "yes")
    with pytest.raises(PermissionError, match="hold"):
        erase("dev-a-bot", quarantine_root=kw["quarantine_root"], audit_path=kw["audit_path"], reason="r", confirm=True, typed="erase dev-a-bot",
              permit=p, admin_pin_path=pin(ids["owner-bot"].pub_b64))
    os.chmod(kw["quarantine_root"] + "/dev-a-bot", 0o700); _open_all(kw["quarantine_root"])

@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_erase_wipes_data_and_keeps_tombstone(env):
    ids, al, mb, ownr, kw, tmp = env; meta = revoke("dev-a-bot", **kw)
    later = datetime.now().astimezone() + timedelta(days=31)
    h = erase("dev-a-bot", quarantine_root=kw["quarantine_root"], audit_path=kw["audit_path"], reason="dispute window over",
              confirm=True, typed="erase dev-a-bot", now=later,
              permit=sign_erase_permit(ids["owner-bot"], "dev-a-bot", meta["sha256"], "owner", "yes"), admin_pin_path=pin(ids["owner-bot"].pub_b64))
    assert h == meta["sha256"] and not os.path.exists(os.path.join(kw["quarantine_root"], "dev-a-bot"))
    log = open(kw["audit_path"]).read(); tomb = [json.loads(l) for l in log.splitlines() if "erased_tombstone" in l][0]
    assert tomb["sealed_sha256"] == h and tomb["reason"] == "dispute window over" and tomb["erased_at"]
    assert MARK not in log
