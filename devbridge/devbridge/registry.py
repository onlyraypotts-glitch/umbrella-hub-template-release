"""Hub-assigned identity registry (1.5.0-beta.2). INFORMATIONAL ONLY until Security reviewer GO: recv never consults it.
Append-only, hash-chained JSONL (same chain + .head anchor as AuditLog). The latest record for a subject_id is its state.
R-7 / Legal Chief rule: the chain holds ONLY an opaque id, kind, status, fingerprint, timestamps, a reason CODE and admin_sig.
Display labels live in a separate deletable store (<registry>.labels.json, 0600, NOT hash-chained) and are a ROLE from a
fixed allowlist only. kind=dev is the only enabled kind; user/usr and bot are refused inside the library.
R-1: every issue record carries admin_sig over its canonical fields, verified against the PINNED admin pub FIRST in verify().
NO private key material is ever written here."""
import fcntl, hashlib, json, os, re, secrets, shutil, stat
from datetime import datetime, timedelta
from .core import AuditLog, atomic_write_json, now_iso, b64e, b64d, Identity, Allowlist
from .revoke import load_pinned_admin_pub, DEFAULT_ADMIN_PIN
from . import pii_scan
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

KINDS_ENABLED = {"dev"}
KINDS_RESERVED = {"user", "usr", "bot"}
PREFIX = {"dev": "dev", "user": "usr", "bot": "bot"}
SUBJECT_RE = re.compile(r"^(dev|usr|bot)-[0-9]{4,}$")   # general id grammar (join/scan); only dev- may be WRITTEN
DEV_ID_RE = re.compile(r"^dev-[0-9]{4,}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
STATUSES = {"active", "held", "revoked"}
REASON_CODES = {"issued", "revoked", "held", "released", "migrated"}
ROLES = {"backend", "frontend", "fullstack", "mobile", "qa", "docs", "design", "security", "ops", "data", "contractor"}
FIELDS = {"subject_id", "kind", "status", "fingerprint", "issued_at", "revoked_at", "updated_at", "reason", "admin_sig"}
SIGNED = ("subject_id", "kind", "status", "fingerprint", "issued_at", "reason")  # canonical issue-record fields
ENROLL_MAX_SECONDS = 15 * 60

class RegistryTampered(RuntimeError): pass

def fingerprint(pub_b64): return hashlib.sha256(b64d(pub_b64)).hexdigest()

def _issue_payload(rec):
    return json.dumps({"domain": "devbridge-registry-issue-v1", **{k: rec.get(k) for k in SIGNED}},
                      sort_keys=True, separators=(",", ":")).encode()

def sign_issue(admin_ident, rec): return b64e(admin_ident.priv.sign(_issue_payload(rec)))

def _sig_ok(pub_b64, payload, sig):
    try: Ed25519PublicKey.from_public_bytes(b64d(pub_b64)).verify(b64d(sig), payload); return True
    except (InvalidSignature, ValueError, TypeError): return False

def check_role(label):
    """R-7 / Legal Chief (a): role from a fixed allowlist only. Free text, names, phones, emails are refused."""
    if label in (None, ""): return ""
    if not isinstance(label, str) or label not in ROLES:
        raise ValueError(f"label must be one role from {sorted(ROLES)} (free text / names / phone / email refused)")
    return label

def _check_rec(rec):
    """R-5 + Legal Chief (b): library-level validation of every value written to the chain."""
    bad = set(rec) - FIELDS
    if bad: raise ValueError(f"registry field(s) not allowed: {sorted(bad)}")
    for k, v in rec.items():
        if isinstance(v, str) and k != "admin_sig" and any(c in v for c in ("/", "\\", "..", "\x00", "\n")):
            raise ValueError(f"path-like / control value refused in {k}")
        if isinstance(v, str) and ("ed25519_raw" in v or "PRIVATE" in v): raise ValueError("private key material refused")
    sid = rec.get("subject_id")
    if not isinstance(sid, str) or not SUBJECT_RE.match(sid): raise ValueError("subject_id must be dev-NNNN")
    if not DEV_ID_RE.match(sid): raise PermissionError(f"{sid}: only kind=dev ids may be written (usr/bot refused)")
    if "kind" in rec and rec["kind"] not in KINDS_ENABLED:
        raise PermissionError(f"kind={rec['kind']!r} refused (only dev enabled; user/usr/bot reserved)")
    if "fingerprint" in rec and not (isinstance(rec["fingerprint"], str) and HEX64_RE.match(rec["fingerprint"])):
        raise ValueError("fingerprint must be 64 lowercase hex")
    if "status" in rec and rec["status"] not in STATUSES: raise ValueError("bad status")
    if "reason" in rec and rec["reason"] not in REASON_CODES: raise ValueError(f"reason must be a code from {sorted(REASON_CODES)}")
    if rec.get("reason") == "issued" or "kind" in rec or "fingerprint" in rec:   # an issue record
        missing = [k for k in SIGNED if rec.get(k) is None]
        if missing or not rec.get("admin_sig"): raise PermissionError(f"unsigned/incomplete issue record refused (missing {missing or ['admin_sig']})")

class Registry:
    def __init__(self, path, head_path=None, *, admin_pin_path=DEFAULT_ADMIN_PIN, admin_pub_b64=None):
        self.path = path; self.log = AuditLog(path, head_path)
        self.admin_pub = admin_pub_b64 or load_pinned_admin_pub(admin_pin_path)   # fail closed if the pin is missing/unsafe
        self.labels_path = path + ".labels.json"; self.cosign_path = path + ".head.sig"
        if os.path.exists(path):
            err = self.problems()
            if err: raise RegistryTampered(f"registry {path} fails verification ({err[0]}); refusing to start (fail closed)")
    # ---- verification ----
    def sig_problems(self):
        """R-1: runs FIRST. Every issue record must carry a valid admin_sig against the pinned admin pub."""
        out = []
        for i, r in enumerate(self.records()):
            if not isinstance(r, dict) or not isinstance(r.get("subject_id"), str): out.append(f"line {i+1}: malformed"); continue
            is_issue = r.get("reason") == "issued" or "fingerprint" in r or "kind" in r
            if is_issue and not (r.get("admin_sig") and _sig_ok(self.admin_pub, _issue_payload(r), r["admin_sig"])):
                out.append(f"line {i+1} {r.get('subject_id')}: issue record admin_sig missing/invalid")
            elif "admin_sig" in r and not is_issue:
                out.append(f"line {i+1}: admin_sig on a non-issue record")
            if not DEV_ID_RE.match(r["subject_id"]) or r.get("kind", "dev") not in KINDS_ENABLED: out.append(f"line {i+1}: non-dev subject refused")
        return out
    def cosign_problems(self):
        """R-2 (partial): if <registry>.head.sig exists, the admin-signed (count, head) must match the chain prefix."""
        if not os.path.exists(self.cosign_path): return []
        try:
            c = json.load(open(self.cosign_path)); n, h = c["count"], c["head"]
            if not _sig_ok(self.admin_pub, _cosign_payload(n, h), c["sig"]): return ["co-signed head: bad admin signature"]
            lines = open(self.path, "rb").read().splitlines()
            if n > len(lines) or (n and hashlib.sha256(lines[n - 1]).hexdigest() != h): return ["co-signed head does not match chain"]
            return []
        except Exception as x: return [f"co-signed head unreadable ({type(x).__name__})"]
    def problems(self):
        out = self.sig_problems()                       # Legal Chief (c): admin_sig check first
        if not self.log.verify(): out.append("hash chain / .head anchor broken")
        return out + self.cosign_problems()
    def verify(self): return not self.problems()
    def records(self): return self.log.events()
    def current(self):
        cur = {}
        for r in self.records():
            if isinstance(r, dict) and isinstance(r.get("subject_id"), str): cur[r["subject_id"]] = {**cur.get(r["subject_id"], {}), **r}
        return cur
    def by_fingerprint(self, fp):
        for sid, r in self.current().items():
            if r.get("fingerprint") == fp: return r
        return None
    def next_id(self, kind):
        p = PREFIX[kind]; n = [int(s.split("-")[1]) for s in self.current() if s.startswith(p + "-")]
        return f"{p}-{(max(n) if n else 0) + 1:04d}"
    def _append(self, rec):
        _check_rec(rec)
        if "admin_sig" in rec and not _sig_ok(self.admin_pub, _issue_payload(rec), rec["admin_sig"]):
            raise PermissionError("issue record admin_sig does not verify against the pinned admin pub")
        os.makedirs(os.path.dirname(self.path) or ".", mode=0o700, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a+b") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                if os.path.getsize(self.path) and not self.verify(): raise RegistryTampered("registry fails verification")
                h = self.log._head() or {"count": 0, "head": "0" * 64}
                line = json.dumps({"ts": now_iso(), "prev": h["head"], **rec}, sort_keys=True).encode()
                f.write(line + b"\n"); f.flush(); os.fsync(f.fileno())
                atomic_write_json(self.log.head_path, {"count": h["count"] + 1, "head": hashlib.sha256(line).hexdigest()})
            finally: fcntl.flock(f, fcntl.LOCK_UN)
    def set_status(self, subject_id, status, reason=None):
        """Status changes are unsigned partial records (bot-side revoke/hold has no admin key). reason is a CODE only;
        free-text reasons go to the (redacted) audit log, never into the chain."""
        if status not in STATUSES: raise ValueError("bad status")
        if subject_id not in self.current(): return False  # unregistered (legacy) peer: nothing to update
        code = {"revoked": "revoked", "held": "held", "active": "released"}[status]
        rec = {"subject_id": subject_id, "status": status, "reason": code, "updated_at": now_iso()}
        if status == "revoked": rec["revoked_at"] = rec["updated_at"]
        self._append(rec); return True
    # ---- R-7: separate deletable label store (NOT hash-chained) ----
    def labels(self):
        try: d = json.load(open(self.labels_path))
        except (OSError, ValueError): return {}
        return {k: v for k, v in d.items() if v in ROLES} if isinstance(d, dict) else {}
    def set_label(self, subject_id, role):
        role = check_role(role)
        if not DEV_ID_RE.match(subject_id or ""): raise PermissionError("labels only for dev-NNNN ids")
        d = self.labels(); d.pop(subject_id, None)
        if role: d[subject_id] = role
        atomic_write_json(self.labels_path, d); os.chmod(self.labels_path, 0o600)
    def clear_label(self, subject_id): self.set_label(subject_id, "")
    def clear_all_labels(self):
        if os.path.exists(self.labels_path): os.unlink(self.labels_path)

def _cosign_payload(count, head):
    return json.dumps({"domain": "devbridge-registry-head-v1", "count": count, "head": head}, sort_keys=True).encode()

def cosign_head(registry_path, admin_ident, *, admin_pin_path=DEFAULT_ADMIN_PIN):
    """R-2 (partial): admin co-signs the current (count, head). Real fix: move .head out of the bot user's write access."""
    reg = Registry(registry_path, admin_pin_path=admin_pin_path)
    if admin_ident.pub_b64 != reg.admin_pub: raise PermissionError("co-signer is not the pinned admin")
    h = reg.log._head() or {"count": 0, "head": "0" * 64}
    atomic_write_json(reg.cosign_path, {"count": h["count"], "head": h["head"], "sig": b64e(admin_ident.priv.sign(_cosign_payload(h["count"], h["head"])))})
    return h

# ---------- R-4: signed enrollment with nonce, expiry (<=15 min) and audience (hub id) ----------
def make_enrollment(ident_priv, pub_b64, hub, ttl_seconds=600, nonce=None, now=None):
    t = now or datetime.now().astimezone()
    rec = {"kind": "enroll", "pub": pub_b64, "hub": hub, "nonce": nonce or secrets.token_hex(16),
           "ts": t.isoformat(timespec="seconds"), "exp": (t + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds")}
    rec["sig"] = b64e(ident_priv.sign(_enroll_payload(rec))); return rec

def _enroll_payload(rec): return json.dumps({k: rec.get(k) for k in ("kind", "pub", "hub", "nonce", "ts", "exp")}, sort_keys=True).encode()

def check_enrollment(rec, *, hub, seen_path, now=None):
    try:
        if rec.get("kind") != "enroll" or not _sig_ok(rec["pub"], _enroll_payload(rec), rec["sig"]): raise ValueError
        ts, exp = datetime.fromisoformat(rec["ts"]), datetime.fromisoformat(rec["exp"])
        nonce = rec["nonce"]
        if not (isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{16,64}", nonce)): raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError): raise PermissionError("enrollment not signed by the enrolled key / malformed")
    now = now or datetime.now().astimezone()
    if rec["hub"] != hub: raise PermissionError("enrollment is for a different hub (audience mismatch)")
    if (exp - ts).total_seconds() > ENROLL_MAX_SECONDS or exp <= ts: raise PermissionError("enrollment validity window exceeds 15 minutes")
    if now > exp or now < ts - timedelta(seconds=120): raise PermissionError("enrollment expired / not yet valid")
    fd = os.open(seen_path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX); f.seek(0)
        if nonce in f.read().split(): raise PermissionError("enrollment nonce already used (replay)")
        f.write(nonce + "\n"); f.flush(); os.fsync(f.fileno())
    return rec["pub"]

# ---------- issue (R-3: one flock across read-max-id -> allowlist add -> append, plus O_EXCL per-id file) ----------
def issue_dev(*, admin_ident, admin_pin_path, registry_path, allowlist_path, revoked_path, audit_path, out_dir,
              watermark_secret_path=None, label="", hub="owner-bot", enroll=None, kind="dev"):
    if kind in KINDS_RESERVED: raise PermissionError(f"kind={kind} is reserved for the future company-wide id space")
    if kind not in KINDS_ENABLED: raise ValueError("unknown kind")
    if admin_ident.pub_b64 != load_pinned_admin_pub(admin_pin_path): raise PermissionError("issuer key does not match the pinned admin pub")
    role = check_role(label)
    os.makedirs(os.path.dirname(registry_path) or ".", mode=0o700, exist_ok=True)
    ids_dir = registry_path + ".ids"; os.makedirs(ids_dir, mode=0o700, exist_ok=True)
    with open(registry_path + ".issue.lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            reg = Registry(registry_path, admin_pin_path=admin_pin_path)
            pub = check_enrollment(enroll, hub=hub, seen_path=registry_path + ".nonces") if enroll is not None else None
            if not os.path.exists(revoked_path): atomic_write_json(revoked_path, {})
            al = Allowlist.load(allowlist_path, revoked_path)
            sid = reg.next_id(kind)
            while True:   # uniqueness guard independent of the chain: O_CREAT|O_EXCL per id
                try: os.close(os.open(os.path.join(ids_dir, sid), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)); break
                except FileExistsError: sid = f"{PREFIX[kind]}-{int(sid.split('-')[1]) + 1:04d}"
            ident = None
            if pub is None: ident = Identity.generate(sid); pub = ident.pub_b64
            fp = fingerprint(pub)
            if reg.by_fingerprint(fp) or al.is_retired(pub) or any(p.get("pub") == pub for p in al.peers.values()):
                raise PermissionError("duplicate key: this public key is already registered/allowlisted/retired")
            if sid in al.peers or sid in al.revoked: raise PermissionError(f"{sid} already present in allowlist/revoked list")
            bundle = None
            if ident is not None:
                bundle = os.path.join(out_dir, sid); ident.save(bundle)  # private key 0600, O_EXCL; hand-off only
            al.add(sid, pub, sid, [hub])
            if hub in al.peers and sid not in al.peers[hub]["may_send_to"]: al.peers[hub]["may_send_to"].append(sid)
            al.save(allowlist_path)
            rec = {"subject_id": sid, "kind": kind, "status": "active", "fingerprint": fp, "issued_at": now_iso(), "reason": "issued"}
            rec["admin_sig"] = sign_issue(admin_ident, rec)
            reg._append(rec)
            if role: reg.set_label(sid, role)
        finally: fcntl.flock(lk, fcntl.LOCK_UN)
    AuditLog(audit_path).append("dev_issued", peer=sid, admin=admin_ident.bot_id, fingerprint=fp, enrolled=enroll is not None)
    return rec, bundle

# ---------- consistency / whois / list ----------
def check(registry_path, allowlist_path, revoked_path, *, admin_pin_path=DEFAULT_ADMIN_PIN):
    reg = Registry(registry_path, admin_pin_path=admin_pin_path); al = Allowlist.load(allowlist_path, revoked_path); out = []
    cur = reg.current()
    for sid, r in cur.items():
        st = r.get("status"); peer = al.peers.get(sid)
        if st in ("active", "held"):
            if sid in al.revoked: out.append(f"{sid}: registry={st} but in revoked list")
            if not peer: out.append(f"{sid}: registry={st} but missing from allowlist")
            elif fingerprint(peer["pub"]) != r.get("fingerprint"): out.append(f"{sid}: allowlist key fingerprint differs from registry")
        elif st == "revoked":
            if peer: out.append(f"{sid}: registry=revoked but still in allowlist")
            if sid not in al.revoked: out.append(f"{sid}: registry=revoked but not in revoked list")
        else: out.append(f"{sid}: record has no valid status")
    for sid in al.peers:
        if SUBJECT_RE.match(sid) and sid not in cur: out.append(f"{sid}: in allowlist but not in registry")
    for sid in al.revoked:
        r = cur.get(sid)
        if r and r.get("status") != "revoked": out.append(f"{sid}: in revoked list but registry={r.get('status')}")
    return out

def whois(registry_path, query, audit_paths=(), *, admin_pin_path=DEFAULT_ADMIN_PIN):
    reg = Registry(registry_path, admin_pin_path=admin_pin_path); r = reg.current().get(query) or reg.by_fingerprint(query)
    if not r: return None
    sid = r.get("subject_id"); acc = rej = 0
    for p in audit_paths:
        a = AuditLog(p)
        if not a.verify(): raise RuntimeError(f"audit {p} fails verification")
        for e in a.events():
            if e.get("frm") == sid or e.get("peer") == sid:
                acc += e.get("event") == "accepted"; rej += e.get("event") == "rejected"
    return {k: r.get(k) for k in ("subject_id", "kind", "status", "fingerprint", "issued_at", "revoked_at", "reason")} | \
           {"role": reg.labels().get(sid), "accepted": acc, "rejected": rej}

def list_table(registry_path, *, admin_pin_path=DEFAULT_ADMIN_PIN):
    reg = Registry(registry_path, admin_pin_path=admin_pin_path); lab = reg.labels()
    rows = [("SUBJECT", "KIND", "STATUS", "ISSUED", "REVOKED", "KEY(fp)", "ROLE")]
    for sid, r in sorted(reg.current().items()):
        rows.append((sid, r.get("kind", ""), r.get("status") or "?", (r.get("issued_at") or "")[:16], (r.get("revoked_at") or "-")[:16],
                     (r.get("fingerprint") or "")[:12], lab.get(sid, "")))
    w = [max(len(str(x[i])) for x in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(str(c).ljust(w[i]) for i, c in enumerate(row)).rstrip() for row in rows)

# ---------- user-report join (R-6: subject_id + status only, never a label) ----------
def join_report(report_line, registry_path, *, admin_pin_path=DEFAULT_ADMIN_PIN):
    rep = json.loads(report_line) if isinstance(report_line, str) else report_line
    sid = rep.get("subject_id")
    if not sid or sid == "UNKNOWN": return {**rep, "subject": None}
    if not isinstance(sid, str) or not SUBJECT_RE.match(sid): return {**rep, "subject": None, "subject_error": "bad subject_id"}
    if not DEV_ID_RE.match(sid): return {**rep, "subject": None, "subject_error": "kind refused (only dev ids are joined)"}
    r = Registry(registry_path, admin_pin_path=admin_pin_path).current().get(sid)
    return {**rep, "subject": ({"subject_id": sid, "status": r.get("status") or "unknown"} if r else None)}

# ---------- registry scan + migration (HQ: legacy chains that hold personal data) ----------
_NAME_RE = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+\b")
def _looks_personal(v):
    if not isinstance(v, str) or not v: return []
    hits = [k for k in ("owner_name", "email", "phone", "handle") if re.search(pii_scan.RULES[k], v)]
    if _NAME_RE.search(v): hits.append("person_name")
    return hits

def scan(registry_path):
    """Read-only. Flags records whose free-text fields (display_label, reason, or any unknown string field) look personal.
    Does NOT need the chain to be in the new format and does not modify anything (the chain can't be rewritten in place)."""
    out = []
    for i, line in enumerate(open(registry_path, "rb").read().splitlines(), 1):
        try: r = json.loads(line)
        except ValueError: out.append({"line": i, "subject_id": None, "field": None, "hits": ["unparseable"]}); continue
        for k, v in r.items():
            if k in ("ts", "prev", "admin_sig", "fingerprint", "subject_id", "kind", "status", "issued_at", "revoked_at", "updated_at"): continue
            if k == "reason" and v in REASON_CODES: continue
            h = _looks_personal(v)
            if k == "display_label" and v and v not in ROLES: h = h or ["free_text_label"]
            if h: out.append({"line": i, "subject_id": r.get("subject_id"), "field": k, "hits": sorted(set(h))})
    return out

def migrate(registry_path, admin_ident, *, admin_pin_path=DEFAULT_ADMIN_PIN, stamp=None):
    """Rebuild a FRESH chain holding only the Legal Chief fields. The old registry (+ .head) is kept as a dated backup, NEVER deleted.
    Refuses unless the old chain's hash chain verifies and every old issue record's admin_sig (legacy canonical form) verifies,
    so a forged legacy chain is not laundered into a newly signed one. Labels that are allowed roles move to the label store;
    everything else (names, phones, free text, watermark_ref, namespace) is dropped from the new chain."""
    from .core import canonical
    pub = load_pinned_admin_pub(admin_pin_path)
    if admin_ident.pub_b64 != pub: raise PermissionError("migration signer is not the pinned admin")
    try: Registry(registry_path, admin_pub_b64=pub); raise ValueError("registry already in the 1.5.0-beta.2 format; nothing to migrate")
    except RegistryTampered: pass
    old = AuditLog(registry_path)
    if not old.verify(): raise RegistryTampered("legacy chain fails hash verification; refusing to migrate")
    recs = old.events(); new = []; labels = {}
    for r in recs:
        sid = r.get("subject_id")
        if not isinstance(sid, str) or not DEV_ID_RE.match(sid): raise PermissionError(f"non-dev subject {sid!r} in legacy chain; refusing")
        if r.get("action") == "issue" or "fingerprint" in r:
            legacy = {k: v for k, v in r.items() if k not in ("ts", "prev", "admin_sig")}
            if not (r.get("admin_sig") and _sig_ok(pub, canonical(legacy), r["admin_sig"])):
                raise RegistryTampered(f"{sid}: legacy issue record admin_sig invalid; refusing to migrate")
            n = {"subject_id": sid, "kind": "dev", "status": r.get("status", "active"), "fingerprint": r["fingerprint"],
                 "issued_at": r.get("issued_at") or r.get("ts"), "reason": "issued"}
            n["admin_sig"] = sign_issue(admin_ident, n); new.append(n)
            if r.get("display_label") in ROLES: labels[sid] = r["display_label"]
        else:
            st = r.get("status")
            if st not in STATUSES: continue
            n = {"subject_id": sid, "status": st, "reason": {"revoked": "revoked", "held": "held", "active": "released"}[st],
                 "updated_at": r.get("revoked_at") or r.get("ts")}
            if st == "revoked": n["revoked_at"] = n["updated_at"]
            new.append(n)
    stamp = stamp or datetime.now().strftime("%Y%m%dT%H%M%S")
    backup = f"{registry_path}.pre-migration-{stamp}"
    for src, dst in ((registry_path, backup), (registry_path + ".head", backup + ".head")):
        if os.path.exists(src):
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # never overwrite an earlier backup
            with os.fdopen(fd, "wb") as f, open(src, "rb") as s: shutil.copyfileobj(s, f); f.flush(); os.fsync(f.fileno())
    tmp = registry_path + ".migrating"
    for p in (tmp, tmp + ".head"):
        if os.path.exists(p): os.unlink(p)
    t = Registry(tmp, admin_pub_b64=pub)
    for n in new: t._append(n)
    os.replace(tmp + ".head", registry_path + ".head"); os.replace(tmp, registry_path)
    for p in (registry_path + ".head.sig",):   # an old co-signature no longer matches the new chain; keep it with the backup
        if os.path.exists(p): os.replace(p, backup + ".head.sig")
    reg = Registry(registry_path, admin_pin_path=admin_pin_path)
    for sid, role in labels.items(): reg.set_label(sid, role)
    return {"backup": backup, "records_in": len(recs), "records_out": len(new), "labels_kept": len(labels)}
