"""Revoke = immediate full lockout + SEAL (encrypt at rest, move to a 0000 quarantine dir).
Erase = separate, later, typed-confirmation step: overwrite + unlink sealed data, keep a content-free tombstone.
We cannot erase anything on the developer's own machine; revocation only makes their copies useless against our system."""
import hashlib, io, json, os, shutil, stat, tarfile, time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .core import AuditLog, atomic_write_json, now_iso, ID_RE

DEFAULT_HOLD_DAYS = 30
MIN_HOLD_DAYS = 30  # E1: hard floor, cannot be lowered by flags or callers
DEFAULT_ADMIN_PIN = "/etc/umbrella/admin.pub"

# M1/M1b (security re-reviews): there is NO public keyword and NO module flag to relax the pin-owner check.
# Tests (which cannot create root-owned files) monkeypatch the private helper _pin_owner_ok in a fixture only.
# Production installs must be read-only and root/custody-owned (DEVELOPER_QUICKSTART.md).

def _pin_owner_ok(st):
    """Pin must be owned outside the bot uid (e.g. root). Private; tests monkeypatch it, nothing in prod overrides it."""
    return st.st_uid != os.getuid()

def _require_enabled(op):
    """M1: beta disable enforced INSIDE the library (not only the CLI). Fails closed if beta.py is missing/garbled."""
    try:
        from . import beta
        enabled = beta.BETA_BUILD is False or op not in beta.DISABLED_IN_BETA
    except Exception:
        enabled = False
    if not enabled: raise PermissionError(f"BETA-DISABLED: {op} is disabled in the beta build (library check)")

def load_pinned_admin_pub(path=DEFAULT_ADMIN_PIN):
    """K1: the admin public key is PINNED in a read-only file the bot user and devs cannot write
    (production: root-owned 0444, e.g. /etc/umbrella/admin.pub). Admin identity is NEVER derived from a CLI key file.
    M1: no caller-controlled way to disable the owner check."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode): raise PermissionError("admin pin must be a regular file")
    if st.st_mode & 0o222: raise PermissionError("admin pin must be read-only (0444)")
    if not _pin_owner_ok(st): raise PermissionError("admin pin must be owned outside the bot uid (e.g. root)")
    if os.stat(os.path.dirname(os.path.abspath(path))).st_mode & 0o022: raise PermissionError("admin pin directory is group/world-writable")
    from .core import b64d
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = json.load(open(path))["pub"]; Ed25519PublicKey.from_public_bytes(b64d(pub)); return pub

def _check_seal_key(path):
    """Refuse a seal key that is group/world accessible, not ours, a symlink, or in a group/world-writable dir."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode): raise PermissionError("seal key must be a regular file")
    if st.st_mode & 0o077 or st.st_uid != os.getuid(): raise PermissionError("seal key must be 0600 and owned by this user")
    d = os.stat(os.path.dirname(os.path.abspath(path)))
    if d.st_mode & 0o022: raise PermissionError("seal key directory is group/world-writable")
    return open(path, "rb").read()

def load_revoked(path):
    try: return json.load(open(path))
    except (OSError, ValueError): return {}

def new_seal_key(path):
    """Synthetic/test seal key (32 bytes, 0600). Production key custody needs the owner + security review."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f: f.write(AESGCM.generate_key(256))
    return path

def _wipe_tree(root):
    """Overwrite every regular file with random bytes, fsync, unlink; then remove dirs. Symlinks are unlinked, not followed."""
    for d, dirs, files in os.walk(root, topdown=False):
        os.chmod(d, 0o700)
        for f in files:
            p = os.path.join(d, f)
            if os.path.islink(p) or not os.path.isfile(p): os.unlink(p); continue
            os.chmod(p, 0o600); n = os.path.getsize(p)
            with open(p, "r+b") as h: h.write(os.urandom(n)); h.flush(); os.fsync(h.fileno())
            os.unlink(p)
        for x in dirs:
            q = os.path.join(d, x)
            if os.path.islink(q): os.unlink(q)
            else: os.rmdir(q)
    os.rmdir(root)

def revoke(peer, *, allowlist, allowlist_path, revoked_path, quarantine_root, seal_key_path, paths, audit_path, reason, registry_path=None,
           registry_admin_pin=DEFAULT_ADMIN_PIN):
    """1) reject to/from (revoked list checked in verify + send) 2) remove from allowlist and every may_send_to
    3) record the key as revoked 4) seal: tar+AES-GCM paths into quarantine/<peer>/sealed-*.bin, wipe plaintext, chmod dir 0000.
    Relay tokens: see README (design note) - the HTTP relay must check the same revoked list / KV-D1 revocation."""
    if not ID_RE.match(peer): raise ValueError("bad peer id")
    if registry_path:
        from .registry import Registry; Registry(registry_path, admin_pin_path=registry_admin_pin)  # fail closed BEFORE any lockout/seal if registry is tampered
    audit = AuditLog(audit_path); entry = allowlist.peers.get(peer, {})
    rev = load_revoked(revoked_path)
    rev[peer] = {"pub": entry.get("pub") or rev.get(peer, {}).get("pub"), "revoked_at": now_iso(), "reason": reason}
    atomic_write_json(revoked_path, rev)
    allowlist.revoke(peer, rev[peer])
    allowlist.save(allowlist_path)
    qdir = os.path.join(quarantine_root, peer); os.makedirs(qdir, mode=0o700, exist_ok=True); os.chmod(qdir, 0o700)
    buf = io.BytesIO(); existing = [p for p in paths if os.path.lexists(p)]
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for p in existing: t.add(p, arcname=os.path.basename(os.path.normpath(p)) + "-" + hashlib.sha256(p.encode()).hexdigest()[:8])
    key = _check_seal_key(seal_key_path); nonce = os.urandom(12)
    blob = nonce + AESGCM(key).encrypt(nonce, buf.getvalue(), peer.encode())
    name = f"sealed-{int(time.time())}.bin"
    fd = os.open(os.path.join(qdir, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f: f.write(blob); f.flush(); os.fsync(f.fileno())
    meta = {"peer": peer, "sealed_at": now_iso(), "sha256": hashlib.sha256(blob).hexdigest(), "sources": len(existing), "reason": reason}
    atomic_write_json(os.path.join(qdir, "seal.json"), meta)
    for p in existing:  # plaintext must not remain once the encrypted copy is durable
        if os.path.isdir(p) and not os.path.islink(p): _wipe_tree(p)
        else: os.unlink(p)
    os.chmod(os.path.join(qdir, name), 0o000); os.chmod(os.path.join(qdir, "seal.json"), 0o000); os.chmod(qdir, 0o000)
    audit.append("sealed", peer=peer, sealed_sha256=meta["sha256"], sources=len(existing))
    audit.append("revoked", peer=peer, reason=reason, sealed_sha256=meta["sha256"], sources=len(existing))
    _registry_status(registry_path, peer, "revoked", reason, registry_admin_pin)
    return meta

def _registry_status(registry_path, peer, status, reason, admin_pin=DEFAULT_ADMIN_PIN):
    """1.5.0: keep the identity registry in step with the allowlist/revoked list (no-op if no registry given)."""
    if registry_path:
        from .registry import Registry
        Registry(registry_path, admin_pin_path=admin_pin).set_status(peer, status)  # chain gets a reason CODE only

def unseal_for_evidence(peer, quarantine_root, seal_key_path):
    """Owner-only read for disputes (returns tar bytes). Restores 0000 afterwards."""
    qdir = os.path.join(quarantine_root, peer); os.chmod(qdir, 0o700)
    try:
        f = [x for x in os.listdir(qdir) if x.startswith("sealed-")][0]; p = os.path.join(qdir, f); os.chmod(p, 0o400)
        blob = open(p, "rb").read(); os.chmod(p, 0o000)
        return AESGCM(_check_seal_key(seal_key_path)).decrypt(blob[:12], blob[12:], peer.encode())
    finally: os.chmod(qdir, 0o000)

def sign_erase_permit(admin_ident, peer, sealed_sha256, approver, typed_yes):
    """E3: The owner's separate typed yes, recorded as an admin-signed permit bound to one sealed blob."""
    from .core import canonical, b64e
    if typed_yes != "yes" or not approver: raise PermissionError("erase permit needs the approver's typed 'yes'")
    rec = {"kind": "erase_permit", "peer": peer, "sealed_sha256": sealed_sha256, "approver": approver, "typed": "yes",
           "ts": now_iso(), "admin": admin_ident.bot_id}
    rec["sig"] = b64e(admin_ident.priv.sign(canonical(rec))); return rec

def _check_permit(permit, admin_pub_b64, peer, sha):
    from .core import canonical, b64d
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try: Ed25519PublicKey.from_public_bytes(b64d(admin_pub_b64)).verify(b64d(permit["sig"]), canonical(permit))
    except (InvalidSignature, ValueError, KeyError, TypeError): raise PermissionError("erase permit not signed by admin")
    if permit.get("kind") != "erase_permit" or permit.get("peer") != peer or permit.get("sealed_sha256") != sha or permit.get("typed") != "yes":
        raise PermissionError("erase permit does not match this sealed data")

def erase(peer, *, quarantine_root, audit_path, reason, confirm, typed, permit, admin_pin_path=DEFAULT_ADMIN_PIN,
          hold_days=DEFAULT_HOLD_DAYS, now=None, holds_path=None):
    """Separate, human-only step (agents must not invoke it). Requires: no legal hold, confirm=True, typed 'erase <peer>',
    an admin-signed erase permit for this exact sealed blob, and >= 30 days since the AUDIT-ANCHORED seal time (E1/E2).
    seal.json is informational only and never trusted for timing."""
    _require_enabled("erase")
    if holds_path is None: holds_path = os.path.join(quarantine_root, "holds.json")
    audit = AuditLog(audit_path)
    if peer in load_holds_strict(holds_path, audit_path):
        audit.append("erase_refused_legal_hold", peer=peer); raise PermissionError(f"legal hold on {peer}; release-hold first")
    if not confirm or typed != f"erase {peer}": raise PermissionError(f"erase needs --confirm and the typed phrase 'erase {peer}'")
    if not audit.verify(): raise PermissionError("admin audit log fails verification; refusing erase")
    qdir = os.path.join(quarantine_root, peer)
    if not os.path.isdir(qdir): raise FileNotFoundError(qdir)
    os.chmod(qdir, 0o700)
    try:
        blobs = [f for f in os.listdir(qdir) if f.startswith("sealed-")]
        if len(blobs) != 1: raise PermissionError("expected exactly one sealed blob")
        bp = os.path.join(qdir, blobs[0]); os.chmod(bp, 0o400); sha = hashlib.sha256(open(bp, "rb").read()).hexdigest(); os.chmod(bp, 0o000)
        anchors = [e for e in audit.events() if e.get("event") in ("sealed", "revoked") and e.get("peer") == peer and e.get("sealed_sha256") == sha]
        if not anchors: raise PermissionError("no audit-anchored seal record for this blob")
        sealed_at = anchors[0]["ts"]  # E2: FIRST authenticated record; seal.json is never trusted for timing
        _check_permit(permit, load_pinned_admin_pub(admin_pin_path), peer, sha)
        hold = max(int(hold_days), MIN_HOLD_DAYS); now = now or datetime.now().astimezone()
        if now - datetime.fromisoformat(sealed_at) < timedelta(days=hold):
            raise PermissionError(f"hold period not over: sealed {sealed_at} (audit), hold {hold} days")
    except BaseException:
        os.chmod(qdir, 0o000); raise
    _wipe_tree(qdir)
    audit.append("erased_tombstone", peer=peer, sealed_sha256=sha, sealed_at=sealed_at, erased_at=now_iso(), reason=reason,
                 permit_approver=permit.get("approver"), permit_ts=permit.get("ts"))
    return sha

# ---------- legal hold (Legal Chief carve-out) ----------
def load_holds(path):
    try: return json.load(open(path))
    except (OSError, ValueError): return {}

def load_holds_strict(holds_path, audit_path):
    """L1: if a holds file has ever existed (sentinel) or the audit shows any hold, a missing/corrupt holds file
    fails CLOSED: every peer is treated as on hold."""
    ever = os.path.exists(holds_path + ".ever") or any(e.get("event") == "legal_hold_set" for e in AuditLog(audit_path).events())
    try:
        h = json.load(open(holds_path))
        if not isinstance(h, dict): raise ValueError
        return h
    except FileNotFoundError:
        if ever: return _ALL_HELD
        return {}
    except (OSError, ValueError):
        return _ALL_HELD

class _AllHeld(dict):
    def __contains__(self, k): return True
_ALL_HELD = _AllHeld({"*": {"reason": "holds file missing/corrupt - fail closed"}})

def set_hold(peer, *, holds_path, audit_path, reason, registry_path=None, registry_admin_pin=DEFAULT_ADMIN_PIN):
    if not ID_RE.match(peer) or not reason: raise ValueError("peer id and reason required")
    open(holds_path + ".ever", "a").close()
    h = load_holds(holds_path); h[peer] = {"since": now_iso(), "reason": reason}; atomic_write_json(holds_path, h)
    AuditLog(audit_path).append("legal_hold_set", peer=peer, reason=reason)
    _registry_status(registry_path, peer, "held", reason, registry_admin_pin)

def release_hold(peer, *, holds_path, audit_path, reason="released", registry_path=None, registry_admin_pin=DEFAULT_ADMIN_PIN):
    h = load_holds_strict(holds_path, audit_path)
    if isinstance(h, _AllHeld): raise PermissionError("holds file missing/corrupt; restore it before releasing (fail closed)")
    if peer not in h: raise KeyError(f"no hold on {peer}")
    h.pop(peer); atomic_write_json(holds_path, h)
    AuditLog(audit_path).append("legal_hold_released", peer=peer, reason=reason)
    if registry_path:
        from .registry import Registry
        r = Registry(registry_path, admin_pin_path=registry_admin_pin); cur = r.current().get(peer)
        if cur and cur.get("status") == "held": r.set_status(peer, "active")

# ---------- key rotation (F14) ----------
def sign_rotation(admin_ident, peer, old_pub, new_pub):
    """Admin signs {peer, old_pub, new_pub, ts}. Applied only if the admin signature verifies."""
    from .core import canonical, b64e
    rec = {"kind": "rotation", "peer": peer, "old_pub": old_pub, "new_pub": new_pub, "ts": now_iso(), "admin": admin_ident.bot_id}
    rec["sig"] = b64e(admin_ident.priv.sign(canonical(rec))); return rec

def apply_rotation(rec, *, allowlist, allowlist_path, rotations_path, audit_path, admin_pin_path=DEFAULT_ADMIN_PIN):
    from .core import canonical, b64d, Reject
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    _require_enabled("rotate")
    admin_pub_b64 = load_pinned_admin_pub(admin_pin_path)
    try: Ed25519PublicKey.from_public_bytes(b64d(admin_pub_b64)).verify(b64d(rec["sig"]), canonical(rec))
    except (InvalidSignature, ValueError, KeyError): raise PermissionError("rotation not signed by admin")
    peer = rec["peer"]; cur = allowlist.peers.get(peer)
    if not cur or cur["pub"] != rec["old_pub"]: raise ValueError("old_pub does not match current allowlist key")
    Ed25519PublicKey.from_public_bytes(b64d(rec["new_pub"]))
    if allowlist.is_retired(rec["new_pub"]) or rec["new_pub"] == rec["old_pub"]:  # K2
        raise PermissionError("new key is revoked/retired and can never be reused")
    rot = load_holds(rotations_path); rot[rec["old_pub"]] = {"peer": peer, "revoked_at": rec["ts"]}; atomic_write_json(rotations_path, rot)
    allowlist.rotated[rec["old_pub"]] = rot[rec["old_pub"]]; cur["pub"] = rec["new_pub"]; allowlist.save(allowlist_path)
    AuditLog(audit_path).append("key_rotated", peer=peer, admin=rec["admin"], revoked_at=rec["ts"],
                                old_pub_sha256=hashlib.sha256(rec["old_pub"].encode()).hexdigest())
    return rec["ts"]
