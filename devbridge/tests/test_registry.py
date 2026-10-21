"""1.5.0-beta.1 hub-assigned identity registry. Synthetic keys, synthetic watermark secret, synthetic labels only."""
import json, os, stat, sys
import pytest
from conftest import pin
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from devbridge.core import Identity, Allowlist, Node, make_envelope, Reject
from devbridge.transports import FileMailbox
from devbridge import registry as R, cli
from devbridge.revoke import revoke, set_hold, release_hold, new_seal_key

@pytest.fixture
def hub(tmp_path, relax_pin):
    admin = Identity.generate("owner-admin"); ak = admin.save(str(tmp_path / "admin"))
    ownr = Identity.generate("owner-bot"); al = Allowlist(); al.add("owner-bot", ownr.pub_b64, "owner", [])
    alp, rvp = str(tmp_path / "allow.json"), str(tmp_path / "revoked.json"); al.save(alp); json.dump({}, open(rvp, "w"))
    ws = str(tmp_path / "wm.secret"); fd = os.open(ws, os.O_WRONLY | os.O_CREAT, 0o600); os.write(fd, b"SYNTHETIC-WATERMARK-SECRET-0001"); os.close(fd)
    kw = dict(admin_ident=admin, admin_pin_path=pin(admin.pub_b64), registry_path=str(tmp_path / "registry.jsonl"), allowlist_path=alp,
              revoked_path=rvp, audit_path=str(tmp_path / "admin-audit.jsonl"), out_dir=str(tmp_path / "bundles"), watermark_secret_path=ws)
    return kw, ownr, ak, tmp_path

def test_issue_assigns_unique_sequential_ids(hub):
    kw, *_ = hub
    ids = [R.issue_dev(**kw, label="backend")[0]["subject_id"] for _ in range(3)]
    assert ids == ["dev-0001", "dev-0002", "dev-0003"]
    assert len({r["fingerprint"] for r in R.Registry(kw["registry_path"], admin_pin_path=kw["admin_pin_path"]).current().values()}) == 3

def test_duplicate_key_refused(hub):
    kw, *_ = hub; dev = Identity.generate("x-dev")
    R.issue_dev(**kw, enroll=R.make_enrollment(dev.priv, dev.pub_b64, "owner-bot"))
    with pytest.raises(PermissionError, match="duplicate"): R.issue_dev(**kw, enroll=R.make_enrollment(dev.priv, dev.pub_b64, "owner-bot"))
    assert list(R.Registry(kw["registry_path"], admin_pin_path=kw["admin_pin_path"]).current()) == ["dev-0001"]

def test_tampered_registry_fails_verify_closed(hub):
    kw, *_ = hub; R.issue_dev(**kw); R.issue_dev(**kw); p = kw["registry_path"]
    s = open(p).read(); open(p, "w").write(s.replace('"status": "active"', '"status": "revoked"', 1))
    with pytest.raises(R.RegistryTampered): R.Registry(p, admin_pin_path=kw["admin_pin_path"])
    with pytest.raises(R.RegistryTampered): R.issue_dev(**kw)
    assert cli.main(["registry", "list", "--registry", p, "--admin-pin", kw["admin_pin_path"]]) == 2

def test_revoke_updates_registry_and_whois(hub):
    kw, ownr, ak, tmp = hub; R.issue_dev(**kw)
    al = Allowlist.load(kw["allowlist_path"], kw["revoked_path"])
    revoke("dev-0001", allowlist=al, allowlist_path=kw["allowlist_path"], revoked_path=kw["revoked_path"], quarantine_root=str(tmp / "q"),
           seal_key_path=new_seal_key(str(tmp / "seal.key")), paths=[], audit_path=kw["audit_path"], reason="synthetic test revoke",
           registry_path=kw["registry_path"], registry_admin_pin=kw["admin_pin_path"])
    w = R.whois(kw["registry_path"], "dev-0001", admin_pin_path=kw["admin_pin_path"])
    assert w["status"] == "revoked" and w["revoked_at"] and w["reason"] == "revoked"
    assert R.check(kw["registry_path"], kw["allowlist_path"], kw["revoked_path"], admin_pin_path=kw["admin_pin_path"]) == []
    os.chmod(str(tmp / "q" / "dev-0001"), 0o700)
    for f in os.listdir(str(tmp / "q" / "dev-0001")): os.chmod(str(tmp / "q" / "dev-0001" / f), 0o600)

def test_hold_and_release_update_registry(hub):
    kw, ownr, ak, tmp = hub; R.issue_dev(**kw); h = str(tmp / "holds.json")
    set_hold("dev-0001", holds_path=h, audit_path=kw["audit_path"], reason="synthetic hold", registry_path=kw["registry_path"], registry_admin_pin=kw["admin_pin_path"])
    assert R.whois(kw["registry_path"], "dev-0001", admin_pin_path=kw["admin_pin_path"])["status"] == "held"
    release_hold("dev-0001", holds_path=h, audit_path=kw["audit_path"], registry_path=kw["registry_path"], registry_admin_pin=kw["admin_pin_path"])
    assert R.whois(kw["registry_path"], "dev-0001", admin_pin_path=kw["admin_pin_path"])["status"] == "active"

def test_mismatch_registry_vs_allowlist_detected(hub):
    kw, *_ = hub; R.issue_dev(**kw); R.issue_dev(**kw)
    al = Allowlist.load(kw["allowlist_path"], kw["revoked_path"]); al.peers.pop("dev-0001")
    al.add("dev-0009", Identity.generate("zz-dev").pub_b64, "dev-0009", ["owner-bot"]); al.save(kw["allowlist_path"])
    bad = R.check(kw["registry_path"], kw["allowlist_path"], kw["revoked_path"], admin_pin_path=kw["admin_pin_path"])
    assert any("dev-0001" in b and "missing from allowlist" in b for b in bad) and any("dev-0009" in b for b in bad)
    assert cli.main(["registry", "check", "--registry", kw["registry_path"], "--allowlist", kw["allowlist_path"], "--revoked", kw["revoked_path"], "--admin-pin", kw["admin_pin_path"]]) == 1

def test_report_line_joins_subject(hub, capsys):
    kw, ownr, ak, tmp = hub; R.issue_dev(**kw, label="qa")
    line = json.dumps({"id": "r-1", "ts": "2026-10-20T22:50:00-04:00", "bot": "Chief of Staff (Chief of Staff)", "type": "bug", "severity": "S3",
                       "summary": "synthetic report", "status": "new", "subject_id": "dev-0001"})
    j = R.join_report(line, kw["registry_path"], admin_pin_path=kw["admin_pin_path"]); assert j["subject"] == {"subject_id": "dev-0001", "status": "active"}
    assert R.join_report(json.dumps({"id": "r-2"}), kw["registry_path"], admin_pin_path=kw["admin_pin_path"])["subject"] is None  # field is optional
    p = tmp / "intake.jsonl"; p.write_text(line + "\n")
    assert cli.main(["report-join", "--intake", str(p), "--registry", kw["registry_path"], "--admin-pin", kw["admin_pin_path"]]) == 0
    assert '"subject_id": "dev-0001"' in capsys.readouterr().out

def test_no_private_key_in_registry_or_audit(hub):
    kw, *_ = hub; rec, bundle = R.issue_dev(**kw); R.issue_dev(**kw)
    raw = json.load(open(os.path.join(bundle, "dev-0001.key")))["ed25519_raw"]
    for p in (kw["registry_path"], kw["audit_path"], kw["allowlist_path"]):
        t = open(p).read(); assert raw not in t and "ed25519_raw" not in t
    with pytest.raises(ValueError): R.Registry(kw["registry_path"], admin_pin_path=kw["admin_pin_path"])._append({"subject_id": "dev-0001", "ed25519_raw": raw})

def test_non_admin_cannot_issue(hub):
    kw, *_ = hub
    with pytest.raises(PermissionError): R.issue_dev(**{**kw, "admin_ident": Identity.generate("mallory-bot")})
    assert not os.path.exists(kw["registry_path"]) and "dev-0001" not in json.load(open(kw["allowlist_path"]))

def test_enroll_requires_valid_proof_of_possession(hub):
    kw, *_ = hub; dev, other = Identity.generate("aa-dev"), Identity.generate("bb-dev")
    with pytest.raises(PermissionError, match="enrollment"): R.issue_dev(**kw, enroll=R.make_enrollment(other.priv, dev.pub_b64, "owner-bot"))
    rec, bundle = R.issue_dev(**kw, enroll=R.make_enrollment(dev.priv, dev.pub_b64, "owner-bot"))
    assert bundle is None and "enrolled" not in rec and rec["fingerprint"] == R.fingerprint(dev.pub_b64)

def test_bundle_key_0600_and_allowlist_entry(hub):
    kw, *_ = hub; rec, bundle = R.issue_dev(**kw)
    assert stat.S_IMODE(os.stat(os.path.join(bundle, "dev-0001.key")).st_mode) == 0o600
    al = json.load(open(kw["allowlist_path"]))
    assert al["dev-0001"]["namespace"] == "dev-0001" and al["dev-0001"]["may_send_to"] == ["owner-bot"] and "dev-0001" in al["owner-bot"]["may_send_to"]
    assert "watermark_ref" not in rec and "issued_by" not in rec   # 1.5.0-beta.2 R-7: chain holds Legal Chief fields only

def test_registry_list_plain_table(hub, capsys):
    kw, *_ = hub; R.issue_dev(**kw, label="frontend"); R.issue_dev(**kw)
    assert cli.main(["registry", "list", "--registry", kw["registry_path"], "--admin-pin", kw["admin_pin_path"]]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("SUBJECT") and out[1].startswith("dev-0001") and "active" in out[1] and "frontend" in out[1]

def test_whois_counts_accepted_rejected_from_audit(hub, tmp_path):
    kw, ownr, ak, tmp = hub; rec, bundle = R.issue_dev(**kw); dev = Identity.load(os.path.join(bundle, "dev-0001.key"))
    al = Allowlist.load(kw["allowlist_path"], kw["revoked_path"]); mb = FileMailbox(tmp / "mail")
    n = Node(ownr, al, mb, str(tmp / "state-ownr"))
    n.accept(make_envelope(dev, "owner-bot", "hello", {"t": "synthetic"})); n.accept(make_envelope(dev, "owner-bot", "info", {"t": "synthetic 2"}))
    bad = make_envelope(dev, "owner-bot", "info", {}); bad["body"] = {"x": 1}
    with pytest.raises(Reject): n.accept(bad)
    w = R.whois(kw["registry_path"], rec["fingerprint"], [n.audit.path], admin_pin_path=kw["admin_pin_path"])
    assert w["subject_id"] == "dev-0001" and w["accepted"] == 2 and w["rejected"] == 1

def test_reserved_kinds_refused_now(hub):
    kw, *_ = hub
    for k in ("user", "bot"):
        with pytest.raises(PermissionError, match="reserved"): R.issue_dev(**kw, kind=k)
    assert R.SUBJECT_RE.match("usr-0001") and R.SUBJECT_RE.match("dev-0001")
