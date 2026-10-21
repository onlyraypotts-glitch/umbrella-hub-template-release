"""M1 (security re-review): beta disable + admin-pin owner check are enforced INSIDE the library. Synthetic keys only."""
import inspect, json, os, sys
from datetime import datetime, timedelta
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from conftest import pin
from devbridge.core import Identity, Allowlist
from devbridge.revoke import revoke, erase, new_seal_key, sign_erase_permit, sign_rotation, apply_rotation, load_pinned_admin_pub
from devbridge import beta

LATER = lambda: datetime.now().astimezone() + timedelta(days=31)

def _open(q):
    for d, ds, fs in os.walk(q):
        os.chmod(d, 0o700)
        for x in ds + fs: os.chmod(os.path.join(d, x), 0o700)

@pytest.fixture
def W(tmp_path):
    ids = {n: Identity.generate(n) for n in ("owner-bot", "dev-a-bot", "evil")}
    al = Allowlist(); al.add("owner-bot", ids["owner-bot"].pub_b64, "owner", ["dev-a-bot"]); al.add("dev-a-bot", ids["dev-a-bot"].pub_b64, "dev-a", ["owner-bot"])
    alp = str(tmp_path / "al.json"); al.save(alp)
    yield ids, al, alp, tmp_path
    q = tmp_path / "q"
    if q.exists(): os.chmod(q, 0o700); _open(str(q))

def _rot(ids, al, alp, tmp, signer="owner-bot", pinpub=None, **extra):
    new = Identity.generate("dev-a-bot")
    rec = sign_rotation(ids[signer], "dev-a-bot", al.peers["dev-a-bot"]["pub"], new.pub_b64)
    return apply_rotation(rec, allowlist=al, allowlist_path=alp, rotations_path=str(tmp / "rot.json"), audit_path=str(tmp / "aud.jsonl"),
                          admin_pin_path=pin(pinpub or ids["owner-bot"].pub_b64), **extra)

def _sealed(ids, al, alp, tmp):
    d = tmp / "st"; d.mkdir(); (d / "x").write_text("synthetic")
    m = revoke("dev-a-bot", allowlist=al, allowlist_path=alp, revoked_path=str(tmp / "rev.json"), quarantine_root=str(tmp / "q"),
               seal_key_path=new_seal_key(str(tmp / "k")), paths=[str(d)], audit_path=str(tmp / "aud.jsonl"), reason="t")
    return dict(quarantine_root=str(tmp / "q"), audit_path=str(tmp / "aud.jsonl"), reason="r", confirm=True, typed="erase dev-a-bot",
                permit=sign_erase_permit(ids["owner-bot"], "dev-a-bot", m["sha256"], "owner", "yes"), admin_pin_path=pin(ids["owner-bot"].pub_b64),
                holds_path=str(tmp / "holds.json"), now=LATER())

def test_M1a_apply_rotation_refused_in_beta_from_python(W, relax_pin):
    ids, al, alp, tmp = W; assert beta.BETA_BUILD is True; before = json.load(open(alp))["dev-a-bot"]["pub"]
    with pytest.raises(PermissionError, match="BETA-DISABLED"): _rot(ids, al, alp, tmp)
    assert json.load(open(alp))["dev-a-bot"]["pub"] == before and not os.path.exists(tmp / "rot.json")

def test_M1b_erase_refused_in_beta_from_python(W, relax_pin):
    ids, al, alp, tmp = W; kw = _sealed(ids, al, alp, tmp); assert beta.BETA_BUILD is True
    with pytest.raises(PermissionError, match="BETA-DISABLED"): erase("dev-a-bot", **kw)
    assert os.path.isdir(tmp / "q" / "dev-a-bot")
    assert "erased_tombstone" not in open(tmp / "aud.jsonl").read()

def test_M1c_strict_pin_not_public():
    for f in (erase, apply_rotation): assert "strict_pin" not in inspect.signature(f).parameters
    assert "strict_owner" not in inspect.signature(load_pinned_admin_pub).parameters
    with pytest.raises(TypeError): apply_rotation({}, allowlist=None, allowlist_path="x", rotations_path="x", audit_path="x", strict_pin=False)
    with pytest.raises(TypeError): erase("dev-a-bot", quarantine_root="x", audit_path="x", reason="r", confirm=True, typed="t", permit={}, strict_pin=False)
    with pytest.raises(TypeError): load_pinned_admin_pub("x", False)

def test_M1d_probe_8d_replay_pin_check_not_disableable(W, monkeypatch):
    ids, al, alp, tmp = W; monkeypatch.setattr(beta, "BETA_BUILD", False)  # even post-beta, no public pin bypass
    before = json.load(open(alp))["dev-a-bot"]["pub"]
    with pytest.raises(TypeError): _rot(ids, al, alp, tmp, signer="evil", pinpub=ids["evil"].pub_b64, strict_pin=False)
    with pytest.raises(PermissionError, match="owned outside"): _rot(ids, al, alp, tmp, signer="evil", pinpub=ids["evil"].pub_b64)
    with pytest.raises(PermissionError, match="owned outside"): _rot(ids, al, alp, tmp)
    assert json.load(open(alp))["dev-a-bot"]["pub"] == before
    kw = _sealed(ids, al, alp, tmp)
    with pytest.raises(PermissionError, match="owned outside"): erase("dev-a-bot", **kw)
    assert os.path.isdir(tmp / "q" / "dev-a-bot")

def test_M1e_garbled_beta_fails_closed(W, relax_pin, monkeypatch):
    ids, al, alp, tmp = W; monkeypatch.delattr(beta, "BETA_BUILD")
    with pytest.raises(PermissionError, match="BETA-DISABLED"): _rot(ids, al, alp, tmp)  # rotate first: revoke() drops the peer
    kw = _sealed(ids, al, alp, tmp)
    with pytest.raises(PermissionError, match="BETA-DISABLED"): erase("dev-a-bot", **kw)
