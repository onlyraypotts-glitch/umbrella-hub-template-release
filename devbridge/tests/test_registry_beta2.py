"""1.5.0-beta.2 registry hardening (security re-review R-1..R-7 + Legal Chief legal requirements + HQ scan/migrate).
Synthetic keys, synthetic ids, synthetic 'personal' strings only (555-01xx numbers, example.invalid emails)."""
import hashlib, json, multiprocessing as mp, os, stat, sys
from datetime import datetime, timedelta
import pytest
from conftest import pin
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from devbridge.core import Identity, Allowlist, AuditLog, canonical, b64e
from devbridge import registry as R, cli

@pytest.fixture
def hub(tmp_path, relax_pin):
    admin = Identity.generate("owner-admin"); ak = admin.save(str(tmp_path / "admin"))
    ownr = Identity.generate("owner-bot"); al = Allowlist(); al.add("owner-bot", ownr.pub_b64, "owner", [])
    alp, rvp = str(tmp_path / "allow.json"), str(tmp_path / "revoked.json"); al.save(alp); json.dump({}, open(rvp, "w"))
    kw = dict(admin_ident=admin, admin_pin_path=pin(admin.pub_b64), registry_path=str(tmp_path / "registry.jsonl"), allowlist_path=alp,
              revoked_path=rvp, audit_path=str(tmp_path / "admin-audit.jsonl"), out_dir=str(tmp_path / "bundles"))
    return kw, admin, ak, tmp_path

def _rechain(path, recs):
    """Attacker with write access to registry.jsonl AND .head: rewrite history and recompute the hash chain."""
    prev, out = "0" * 64, b""
    for r in recs:
        r = {**r, "prev": prev}; line = json.dumps(r, sort_keys=True).encode(); out += line + b"\n"; prev = hashlib.sha256(line).hexdigest()
    open(path, "wb").write(out); json.dump({"count": len(recs), "head": prev}, open(path + ".head", "w"))

def _pin(kw): return {"admin_pin_path": kw["admin_pin_path"]}

# ---------------- R-1 ----------------
def test_R1_append_refuses_unsigned_or_foreign_signed_issue_record(hub):
    kw, admin, *_ = hub; R.issue_dev(**kw); reg = R.Registry(kw["registry_path"], **_pin(kw))
    base = {"subject_id": "dev-0002", "kind": "dev", "status": "active", "fingerprint": "a" * 64, "issued_at": "2026-10-20T23:00:00-04:00", "reason": "issued"}
    with pytest.raises(PermissionError, match="unsigned"): reg._append(dict(base))
    with pytest.raises(PermissionError, match="pinned"): reg._append({**base, "admin_sig": R.sign_issue(Identity.generate("mallory-admin"), base)})
    assert list(reg.current()) == ["dev-0001"]

@pytest.mark.parametrize("mode", ["strip", "tamper", "foreign"])
def test_R1_rechained_bad_sig_fails_verify_whois_check_join(hub, mode, capsys):
    kw, admin, *_ = hub; R.issue_dev(**kw); p = kw["registry_path"]
    recs = [json.loads(l) for l in open(p)]
    if mode == "strip": recs[0].pop("admin_sig")
    elif mode == "tamper": recs[0]["admin_sig"] = recs[0]["admin_sig"][:-4] + ("AAAA" if not recs[0]["admin_sig"].endswith("AAAA") else "BBBB")
    else: recs[0]["admin_sig"] = R.sign_issue(Identity.generate("mallory-admin"), recs[0])
    _rechain(p, recs)
    assert R.AuditLog(p).verify()   # the hash chain alone is fine: only the admin_sig check catches it
    with pytest.raises(R.RegistryTampered, match="admin_sig"): R.Registry(p, **_pin(kw))
    for fn in (lambda: R.whois(p, "dev-0001", **_pin(kw)), lambda: R.check(p, kw["allowlist_path"], kw["revoked_path"], **_pin(kw)),
               lambda: R.join_report(json.dumps({"subject_id": "dev-0001"}), p, **_pin(kw))):
        with pytest.raises(R.RegistryTampered): fn()
    assert cli.main(["registry", "verify", "--registry", p, "--admin-pin", kw["admin_pin_path"]]) == 2
    assert "REGISTRY OK" not in capsys.readouterr().out

def test_R1_forged_extra_record_with_rechained_head_detected(hub):
    kw, *_ = hub; R.issue_dev(**kw); p = kw["registry_path"]; recs = [json.loads(l) for l in open(p)]
    recs.append({"ts": "2026-10-20T23:01:00-04:00", "subject_id": "dev-0002", "kind": "dev", "status": "active", "fingerprint": "b" * 64,
                 "issued_at": "2026-10-20T23:01:00-04:00", "reason": "issued", "admin_sig": "Zm9yZ2Vk"})
    _rechain(p, recs)
    with pytest.raises(R.RegistryTampered): R.Registry(p, **_pin(kw))

# ---------------- R-3 ----------------
_KW = {}
def _issue_one(i):
    kw = _KW
    dev = Identity.generate(f"par-{i:02d}-dev")
    try: return R.issue_dev(**kw, enroll=R.make_enrollment(dev.priv, dev.pub_b64, "owner-bot"))[0]["subject_id"]
    except Exception as x: return f"ERR {type(x).__name__}: {x}"

def test_R3_40_parallel_issues_give_40_distinct_ids(hub):
    kw, *_ = hub
    _KW.clear(); _KW.update(kw)   # inherited by fork (Ed25519 keys are not picklable)
    with mp.get_context("fork").Pool(40) as pool: ids = pool.map(_issue_one, range(40))
    assert not [x for x in ids if x.startswith("ERR")], ids
    assert len(set(ids)) == 40 and sorted(ids) == [f"dev-{i:04d}" for i in range(1, 41)]
    al = json.load(open(kw["allowlist_path"])); assert len([k for k in al if k.startswith("dev-")]) == 40
    reg = R.Registry(kw["registry_path"], **_pin(kw)); assert len(reg.current()) == 40 and reg.verify()
    assert R.check(kw["registry_path"], kw["allowlist_path"], kw["revoked_path"], **_pin(kw)) == []
    assert sorted(os.listdir(kw["registry_path"] + ".ids")) == sorted(ids)

# ---------------- R-5 ----------------
def test_R5_append_validates_values(hub):
    kw, admin, *_ = hub; R.issue_dev(**kw); reg = R.Registry(kw["registry_path"], **_pin(kw))
    for bad, exc in [({"subject_id": "../../x", "status": "held", "reason": "held"}, ValueError),
                     ({"subject_id": "dev-0001", "status": "pwned", "reason": "held"}, ValueError),
                     ({"subject_id": "dev-0001", "status": "held", "reason": "held", "updated_at": "../../etc"}, ValueError),
                     ({"subject_id": "dev-0001", "status": "held", "reason": "Alex Example complained"}, ValueError)]:
        with pytest.raises(exc): reg._append(bad)
    r = {"subject_id": "dev-0002", "kind": "dev", "status": "active", "fingerprint": "ZZ<script>", "issued_at": "2026-10-20T23:00:00-04:00", "reason": "issued"}
    with pytest.raises(ValueError, match="fingerprint"): reg._append({**r, "admin_sig": R.sign_issue(admin, r)})
    assert len(reg.records()) == 1

# ---------------- R-6 ----------------
def test_R6_missing_status_no_crash_and_join_returns_no_label(hub):
    kw, admin, *_ = hub; R.issue_dev(**kw, label="qa"); p = kw["registry_path"]
    j = R.join_report(json.dumps({"id": "r-1", "subject_id": "dev-0001"}), p, **_pin(kw))
    assert j["subject"] == {"subject_id": "dev-0001", "status": "active"}
    recs = [json.loads(l) for l in open(p)]
    r2 = {"subject_id": "dev-0002", "kind": "dev", "status": None, "fingerprint": "c" * 64, "issued_at": "2026-10-20T23:00:00-04:00", "reason": "issued"}
    recs.append({"ts": "2026-10-20T23:00:00-04:00", **{k: v for k, v in r2.items() if k != "status"}, "admin_sig": R.sign_issue(admin, r2)})
    _rechain(p, recs)   # a validly signed record with no status (status=None was signed)
    assert R.join_report(json.dumps({"subject_id": "dev-0002"}), p, **_pin(kw))["subject"] == {"subject_id": "dev-0002", "status": "unknown"}
    assert R.whois(p, "dev-0002", **_pin(kw))["status"] is None
    assert any("no valid status" in m for m in R.check(p, kw["allowlist_path"], kw["revoked_path"], **_pin(kw)))

# ---------------- R-7 + Legal Chief (a) ----------------
def test_R7_chain_holds_only_rhodes_fields_labels_deletable(hub):
    kw, *_ = hub; R.issue_dev(**kw, label="backend"); R.issue_dev(**kw, label="security"); p = kw["registry_path"]
    allowed = {"ts", "prev", "subject_id", "kind", "status", "fingerprint", "issued_at", "revoked_at", "updated_at", "reason", "admin_sig"}
    for r in (json.loads(l) for l in open(p)): assert set(r) <= allowed
    raw = open(p).read(); assert "backend" not in raw and "security" not in raw and "display_label" not in raw
    reg = R.Registry(p, **_pin(kw)); lp = reg.labels_path
    assert reg.labels() == {"dev-0001": "backend", "dev-0002": "security"} and stat.S_IMODE(os.stat(lp).st_mode) == 0o600
    reg.clear_label("dev-0001"); assert reg.labels() == {"dev-0002": "security"}
    reg.clear_all_labels(); assert not os.path.exists(lp)
    assert R.Registry(p, **_pin(kw)).verify() and R.whois(p, "dev-0002", **_pin(kw))["role"] is None

@pytest.mark.parametrize("label", ["Alex Example", "alex example", "555-012-3456", "+1 (555) 012-3456", "jane@example.invalid",
                                   "synthetic backend dev", "Backend", "backend ", "../../etc/passwd", "Jane Doe, QA"])
def test_R7_rhodes_a_free_text_labels_refused_everywhere(hub, label):
    kw, *_ = hub
    with pytest.raises(ValueError, match="role"): R.issue_dev(**kw, label=label)
    assert not os.path.exists(kw["registry_path"]) or not R.Registry(kw["registry_path"], **_pin(kw)).current()
    R.issue_dev(**kw, label="ops"); reg = R.Registry(kw["registry_path"], **_pin(kw))
    with pytest.raises(ValueError, match="role"): reg.set_label("dev-0001", label)
    assert reg.labels() == {"dev-0001": "ops"} and label not in open(kw["registry_path"]).read()

# ---------------- Legal Chief (b): usr kind refused in the LIBRARY ----------------
def test_rhodes_b_usr_kind_refused_in_library(hub):
    kw, admin, *_ = hub; R.issue_dev(**kw); reg = R.Registry(kw["registry_path"], **_pin(kw))
    for k in ("user", "usr", "bot"):
        with pytest.raises(PermissionError, match="reserved"): R.issue_dev(**kw, kind=k)
    u = {"subject_id": "usr-0001", "kind": "dev", "status": "active", "fingerprint": "d" * 64, "issued_at": "2026-10-20T23:00:00-04:00", "reason": "issued"}
    with pytest.raises(PermissionError, match="usr"): reg._append({**u, "admin_sig": R.sign_issue(admin, u)})
    u2 = {**u, "subject_id": "dev-0009", "kind": "user"}
    with pytest.raises(PermissionError, match="kind"): reg._append({**u2, "admin_sig": R.sign_issue(admin, u2)})
    with pytest.raises(PermissionError): reg._append({"subject_id": "usr-0001", "status": "held", "reason": "held"})
    with pytest.raises(PermissionError): reg.set_label("usr-0001", "qa")
    assert R.join_report(json.dumps({"subject_id": "usr-0001"}), kw["registry_path"], **_pin(kw))["subject_error"].startswith("kind refused")
    a = AuditLog(kw["audit_path"]); a.append("note", peer="usr-0001", frm="bot-0001")
    e = a.events()[-1]; assert e["peer"] == "[REFUSED:peer:reserved-kind]" and e["frm"] == "[REFUSED:frm:reserved-kind]" and a.verify()
    assert list(reg.current()) == ["dev-0001"]

# ---------------- Legal Chief (d) + HQ (2): name redaction in audit free text ----------------
def test_rhodes_d_audit_redacts_names_in_free_text_only(tmp_path):
    a = AuditLog(str(tmp_path / "a.jsonl"))
    a.append("legal_hold_set", peer="dev-0001", reason="complaint from Jane Doe re: Mary-Ann O'Neil and John Q. Public")
    a.append("note", peer="dev-0001", reason="owner alex example asked; also Alex Example and ALEX EXAMPLE", body={"text": "ping Alex Rivera"})
    e1, e2 = a.events()
    for name in ("Jane Doe", "Mary-Ann O'Neil", "John Q. Public"): assert name not in e1["reason"]
    assert e1["reason"].count("[REDACTED:person_name]") == 3 and e1["peer"] == "dev-0001"
    assert "alex example" not in json.dumps(e2).lower() and "Alex Rivera" not in json.dumps(e2) and a.verify()

# ---------------- R-4 ----------------
def test_R4_enrollment_nonce_expiry_audience(hub):
    kw, *_ = hub; dev = Identity.generate("enr-dev"); dev2 = Identity.generate("enr2-dev")
    with pytest.raises(PermissionError, match="different hub"): R.issue_dev(**kw, enroll=R.make_enrollment(dev.priv, dev.pub_b64, "other-hub"))
    old = datetime.now().astimezone() - timedelta(hours=1)
    with pytest.raises(PermissionError, match="expired"): R.issue_dev(**kw, enroll=R.make_enrollment(dev.priv, dev.pub_b64, "owner-bot", now=old))
    with pytest.raises(PermissionError, match="15 minutes"): R.issue_dev(**kw, enroll=R.make_enrollment(dev.priv, dev.pub_b64, "owner-bot", ttl_seconds=3600))
    e = R.make_enrollment(dev.priv, dev.pub_b64, "owner-bot"); t = dict(e); t["hub"] = "owner-bot2"
    with pytest.raises(PermissionError): R.issue_dev(**kw, enroll=t)   # audience is under the signature
    R.issue_dev(**kw, enroll=e)
    n = R.make_enrollment(dev2.priv, dev2.pub_b64, "owner-bot", nonce=e["nonce"])
    with pytest.raises(PermissionError, match="replay"): R.issue_dev(**kw, enroll=n)
    assert list(R.Registry(kw["registry_path"], **_pin(kw)).current()) == ["dev-0001"]

# ---------------- R-2 (partial) ----------------
def test_R2_cosigned_head_detects_rechained_history(hub):
    kw, admin, ak, tmp = hub; R.issue_dev(**kw); R.issue_dev(**kw); p = kw["registry_path"]
    assert cli.main(["registry", "cosign", "--registry", p, "--admin-pin", kw["admin_pin_path"], "--admin-key", ak]) == 0
    R.Registry(p, **_pin(kw)); R.issue_dev(**kw)   # growth after the co-sign is fine (prefix still matches)
    recs = [json.loads(l) for l in open(p)]; recs[1]["issued_at"] = "2026-10-20T23:59:00-04:00"
    recs[1]["admin_sig"] = R.sign_issue(admin, recs[1])   # even an admin-signed rewrite of history is caught by the co-signed prefix
    _rechain(p, recs)
    with pytest.raises(R.RegistryTampered, match="co-signed"): R.Registry(p, **_pin(kw))
    with pytest.raises(PermissionError): R.cosign_head(p + "x", Identity.generate("mallory"), **_pin(kw))

# ---------------- HQ (1): registry scan + migration ----------------
def _legacy_chain(path, admin):
    """A 1.5.0-beta.1-format chain (display_label + free-text reason inside the chain), signed the old way."""
    def issue(sid, fp, label):
        r = {"subject_id": sid, "kind": "dev", "display_label": label, "namespace": sid, "fingerprint": fp, "status": "active",
             "issued_at": "2026-10-20T22:50:00-04:00", "issued_by": "owner-admin", "revoked_at": None, "reason": "issued",
             "watermark_ref": "0" * 32, "action": "issue", "enrolled": False}
        r["admin_sig"] = b64e(admin.priv.sign(canonical(r))); return {"ts": "2026-10-20T22:50:00-04:00", **r}
    recs = [issue("dev-0001", "1" * 64, "Alex Example"), issue("dev-0002", "2" * 64, "qa"),
            {"ts": "2026-10-20T22:55:00-04:00", "subject_id": "dev-0002", "status": "revoked", "reason": "call back 555-012-3456",
             "action": "revoked", "revoked_at": "2026-10-20T22:55:00-04:00"}]
    _rechain(path, recs)

def test_HQ_scan_flags_personal_records_and_migration_keeps_dated_backup(hub, capsys):
    kw, admin, ak, tmp = hub; p = kw["registry_path"]; _legacy_chain(p, admin); before = open(p, "rb").read()
    hits = R.scan(p)
    assert {(h["line"], h["field"]) for h in hits} == {(1, "display_label"), (3, "reason")}
    assert "owner_name" in hits[0]["hits"] and "phone" in hits[1]["hits"]
    assert cli.main(["registry", "scan", "--registry", p]) == 1 and "FLAGGED 2" in capsys.readouterr().out
    assert open(p, "rb").read() == before   # scan is read-only
    with pytest.raises(R.RegistryTampered): R.Registry(p, **_pin(kw))   # legacy format does not pass the new verify
    assert cli.main(["registry", "migrate", "--registry", p, "--admin-pin", kw["admin_pin_path"], "--admin-key", ak]) == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert open(out["backup"], "rb").read() == before and os.path.exists(out["backup"] + ".head")   # old file kept, never deleted
    reg = R.Registry(p, **_pin(kw)); raw = open(p).read()
    assert "Alex Example" not in raw and "555" not in raw and "display_label" not in raw and R.scan(p) == []
    assert reg.current()["dev-0002"]["status"] == "revoked" and reg.labels() == {"dev-0002": "qa"}
    with pytest.raises(ValueError, match="already"): R.migrate(p, admin, admin_pin_path=kw["admin_pin_path"])
    p2 = str(tmp / "r2.jsonl"); _legacy_chain(p2, admin); b2 = open(p2, "rb").read(); open(p2 + ".pre-migration-X", "w").write("earlier backup")
    with pytest.raises(FileExistsError): R.migrate(p2, admin, admin_pin_path=kw["admin_pin_path"], stamp="X")   # never overwrites a backup
    assert open(p2 + ".pre-migration-X").read() == "earlier backup" and open(p2, "rb").read() == b2

def test_HQ_migration_refuses_forged_legacy_chain(hub):
    kw, admin, ak, tmp = hub; p = kw["registry_path"]; _legacy_chain(p, Identity.generate("mallory-admin"))
    with pytest.raises(R.RegistryTampered, match="legacy"): R.migrate(p, admin, admin_pin_path=kw["admin_pin_path"])
    assert not [f for f in os.listdir(tmp) if "pre-migration" in f]
