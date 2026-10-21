"""Legal hold (Legal Chief carve-out) and admin-signed key rotation (F14). Synthetic keys/data only."""
import json, os, sys
from datetime import datetime, timedelta
import pytest
from conftest import pin
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from devbridge.core import Identity, Allowlist, Node, Reject, make_envelope
from devbridge.transports import FileMailbox
from devbridge.revoke import revoke, erase, new_seal_key, set_hold, release_hold, sign_rotation, apply_rotation, sign_erase_permit
from devbridge import cli

def _open_all(q):
    if os.path.exists(q): os.chmod(q, 0o700)
    for d, ds, fs in os.walk(q):
        for x in ds + fs: os.chmod(os.path.join(d, x), 0o700)

@pytest.fixture
def sealed(tmp_path):
    ids = {n: Identity.generate(n) for n in ("owner-bot", "dev-a-bot")}
    al = Allowlist(); al.add("owner-bot", ids["owner-bot"].pub_b64, "owner", ["dev-a-bot"]); al.add("dev-a-bot", ids["dev-a-bot"].pub_b64, "dev-a", ["owner-bot"])
    alp = str(tmp_path / "allow.json"); al.save(alp); d = tmp_path / "dev-a-state"; d.mkdir(); (d / "x.txt").write_text("synthetic")
    q = str(tmp_path / "q"); audit = str(tmp_path / "admin.jsonl")
    m = revoke("dev-a-bot", allowlist=al, allowlist_path=alp, revoked_path=str(tmp_path / "rev.json"), quarantine_root=q,
           seal_key_path=new_seal_key(str(tmp_path / "k")), paths=[str(d)], audit_path=audit, reason="t")
    PERMIT.update(p=sign_erase_permit(ids["owner-bot"], "dev-a-bot", m["sha256"], "owner", "yes"), pub=ids["owner-bot"].pub_b64)
    yield q, audit, str(tmp_path / "holds.json")
    _open_all(os.path.join(q, "dev-a-bot"))

PERMIT = {}
LATER = lambda: datetime.now().astimezone() + timedelta(days=31)

@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_hold_blocks_erase_then_release_allows(sealed):
    q, audit, holds = sealed; set_hold("dev-a-bot", holds_path=holds, audit_path=audit, reason="dispute #1 (synthetic)")
    kw = dict(quarantine_root=q, audit_path=audit, reason="r", confirm=True, typed="erase dev-a-bot", now=LATER(), holds_path=holds,
              permit=PERMIT["p"], admin_pin_path=pin(PERMIT["pub"]))
    with pytest.raises(PermissionError, match="legal hold"): erase("dev-a-bot", **kw)
    assert os.path.exists(os.path.join(q, "dev-a-bot"))
    release_hold("dev-a-bot", holds_path=holds, audit_path=audit, reason="dispute closed")
    assert erase("dev-a-bot", **kw)
    ev = [json.loads(l)["event"] for l in open(audit)]
    assert ["legal_hold_set", "erase_refused_legal_hold", "legal_hold_released", "erased_tombstone"] == [e for e in ev if e not in ("revoked", "sealed")]

@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_hold_default_path_and_release_unknown(sealed):
    q, audit, _ = sealed; set_hold("dev-a-bot", holds_path=os.path.join(q, "holds.json"), audit_path=audit, reason="r")
    with pytest.raises(PermissionError, match="legal hold"):
        erase("dev-a-bot", quarantine_root=q, audit_path=audit, reason="r", confirm=True, typed="erase dev-a-bot", now=LATER(), permit=PERMIT["p"], admin_pin_path=pin(PERMIT["pub"]))
    with pytest.raises(KeyError): release_hold("dev-b-bot", holds_path=os.path.join(q, "holds.json"), audit_path=audit)

def test_hold_cli(sealed):
    q, audit, holds = sealed
    assert cli.main(["hold", "dev-a-bot", "--holds", holds, "--audit", audit, "--reason", "evidence"]) == 0
    assert json.load(open(holds))["dev-a-bot"]["reason"] == "evidence"
    assert cli.main(["release-hold", "dev-a-bot", "--holds", holds, "--audit", audit]) == 0 and json.load(open(holds)) == {}
    assert cli.main(["release-hold", "dev-a-bot", "--holds", holds, "--audit", audit]) == 2

@pytest.fixture
def rot(tmp_path):
    ids = {n: Identity.generate(n) for n in ("owner-bot", "dev-a-bot")}; new = Identity("dev-a-bot", Identity.generate("dev-a-bot").priv)
    al = Allowlist(); al.add("owner-bot", ids["owner-bot"].pub_b64, "owner", ["dev-a-bot"]); al.add("dev-a-bot", ids["dev-a-bot"].pub_b64, "dev-a", ["owner-bot"])
    p = {k: str(tmp_path / f) for k, f in [("al", "allow.json"), ("rot", "rot.json"), ("audit", "admin.jsonl")]}; al.save(p["al"])
    return ids, new, al, p, tmp_path

@pytest.mark.usefixtures("unlocked")  # M1: library is beta-locked; test simulates post-beta
def test_rotate_old_key_rejected_new_accepted(rot):
    ids, new, al, p, tmp = rot
    rec = sign_rotation(ids["owner-bot"], "dev-a-bot", ids["dev-a-bot"].pub_b64, new.pub_b64)
    ts = apply_rotation(rec, admin_pin_path=pin(ids["owner-bot"].pub_b64), allowlist=al, allowlist_path=p["al"], rotations_path=p["rot"], audit_path=p["audit"])
    ownr = Node(ids["owner-bot"], Allowlist.load(p["al"], None, p["rot"]), FileMailbox(tmp / "m"), str(tmp / "s"))
    with pytest.raises(Reject) as r: ownr.accept(make_envelope(ids["dev-a-bot"], "owner-bot", "info", {}))
    assert r.value.code == "key_rotated" and ts in str(r.value)
    assert ownr.accept(make_envelope(new, "owner-bot", "info", {}))
    assert any(json.loads(l)["event"] == "key_rotated" for l in open(p["audit"]))

def test_rotate_requires_admin_signature(rot):
    ids, new, al, p, tmp = rot
    forged = sign_rotation(ids["dev-a-bot"], "dev-a-bot", ids["dev-a-bot"].pub_b64, new.pub_b64)  # dev signs its own rotation
    with pytest.raises(PermissionError):
        apply_rotation(forged, admin_pin_path=pin(ids["owner-bot"].pub_b64), allowlist=al, allowlist_path=p["al"], rotations_path=p["rot"], audit_path=p["audit"])
    rec = sign_rotation(ids["owner-bot"], "dev-a-bot", ids["dev-a-bot"].pub_b64, new.pub_b64); rec["new_pub"] = ids["owner-bot"].pub_b64  # tampered
    with pytest.raises(PermissionError):
        apply_rotation(rec, admin_pin_path=pin(ids["owner-bot"].pub_b64), allowlist=al, allowlist_path=p["al"], rotations_path=p["rot"], audit_path=p["audit"])
    assert al.peers["dev-a-bot"]["pub"] == ids["dev-a-bot"].pub_b64 and not os.path.exists(p["rot"])

def test_rotate_cli(tmp_path):
    k = tmp_path / "keys"; k2 = tmp_path / "newkeys"; al = str(tmp_path / "allow.json")
    for b in ("owner-bot", "dev-a-bot"): cli.main(["keygen", "--id", b, "--out", str(k)])
    cli.main(["keygen", "--id", "dev-a-bot", "--out", str(k2)])
    cli.main(["allow", "--allowlist", al, "--revoked", al + ".rev", "--pubfile", str(k / "owner-bot.pub.json"), "--namespace", "owner", "--may-send-to", "dev-a-bot"])
    cli.main(["allow", "--allowlist", al, "--revoked", al + ".rev", "--pubfile", str(k / "dev-a-bot.pub.json"), "--namespace", "dev-a", "--may-send-to", "owner-bot"])
    rc = cli.main(["rotate", "dev-a-bot", str(k2 / "dev-a-bot.pub.json"), "--admin-key", str(k / "owner-bot.key"), "--allowlist", al,
                   "--rotations", str(tmp_path / "rot.json"), "--audit", str(tmp_path / "a.jsonl"), "--revoked", al + ".rev"])
    assert rc == 3 and json.load(open(al))["dev-a-bot"]["pub"] == json.load(open(k / "dev-a-bot.pub.json"))["pub"]  # BETA-DISABLED, unchanged
