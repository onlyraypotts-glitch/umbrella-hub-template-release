"""Lease SERVER (local, persistent). The moat. Holds KEK + per-dev data keys; nothing
security-critical runs on the developer's hardware.

Hardened per the security reviewer's lease review (L-1,L-2,L-6,L-7,L-10):
- single-use, server-issued challenge nonces with a TTL, tracked and consumed (L-1);
- DK delivered ECIES-wrapped to the device's X25519 public key, so a replayed capture
  without the device private key yields nothing (L-1);
- lease signed over nonce+counter+epoch+expiry+device+wrapped-DK hash (L-2 verification is client-side);
- all state (keys, epochs, revocations, counters, challenges) persisted atomically at 0600 (L-7);
- 30-day encrypted backup with a backup key the dev never holds, hold-start from a signed record,
  hard 30-day minimum, tombstone, scheduled-deletion marker (L-10). NOT wired to devbridge erase.
"""
import os, time, json, base64, hashlib
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as _s
from .crypto import canon, ecies_wrap, atomic_write, RAW

LEASE_MAX_SECONDS = 15 * 60
CHALLENGE_TTL = 30.0
RATE_LIMIT_WINDOW = 60.0
RATE_LIMIT_MAX = 10
BACKUP_MIN_HOLD_DAYS = 30
b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)

class LeaseDenied(Exception): pass

class LeaseServer:
    def __init__(self, statedir, now=None):
        self.statedir = statedir; os.makedirs(statedir, mode=0o700, exist_ok=True)
        try: os.chmod(statedir, 0o700)
        except OSError: pass
        self._now = now or (lambda: time.time())
        self._secrets_path = os.path.join(statedir, "secrets.json")
        self._state_path = os.path.join(statedir, "state.json")
        self._backup_dir = os.path.join(statedir, "backups"); os.makedirs(self._backup_dir, mode=0o700, exist_ok=True)
        self._load_or_init()

    # ---------- persistence ----------
    def _load_or_init(self):
        if os.path.exists(self._secrets_path):
            sec = json.load(open(self._secrets_path))
            self._kek = b64d(sec["kek"])
            self._backup_kek = b64d(sec["backup_kek"])
            self._admin = Ed25519PrivateKey.from_private_bytes(b64d(sec["admin"]))
            self._sign = Ed25519PrivateKey.from_private_bytes(b64d(sec["sign"]))
        else:
            self._kek = AESGCM.generate_key(256)
            self._backup_kek = AESGCM.generate_key(256)   # dev NEVER holds this (L-10)
            self._admin = Ed25519PrivateKey.generate()
            self._sign = Ed25519PrivateKey.generate()
            self._save_secrets()
        self.admin_pub = self._admin.public_key()
        self.sign_pub = self._sign.public_key()
        self.admin_pub_bytes = self.admin_pub.public_bytes(*RAW)
        self.sign_pub_bytes = self.sign_pub.public_bytes(*RAW)
        if os.path.exists(self._state_path):
            self._st = json.load(open(self._state_path))
        else:
            self._st = {"wrapped_dk": {}, "device": {}, "counter": {}, "epoch": {},
                        "challenges": {}, "rl": {}, "access_log": [], "backups": {}}
            self._save_state()

    def _save_secrets(self):
        priv = lambda k: b64e(k.private_bytes(_s.Encoding.Raw, _s.PrivateFormat.Raw, _s.NoEncryption()))
        atomic_write(self._secrets_path, canon({
            "kek": b64e(self._kek), "backup_kek": b64e(self._backup_kek),
            "admin": priv(self._admin), "sign": priv(self._sign)}))
    def _save_state(self): atomic_write(self._state_path, canon(self._st))

    # ---------- provisioning ----------
    def enroll(self, peer, registration):
        """registration = {'ed': b64 device ed25519 pub, 'x': b64 device x25519 pub}."""
        dk = AESGCM.generate_key(256)
        n = os.urandom(12)
        wrapped = n + AESGCM(self._kek).encrypt(n, dk, peer.encode())
        self._st["wrapped_dk"][peer] = b64e(wrapped)
        self._st["device"][peer] = {"ed": registration["ed"], "x": registration["x"]}
        self._st["counter"][peer] = 0
        self._set_epoch(peer, 1, "active")
        self._save_state()
        return dk   # returned once so client can encrypt its payload; client forgets it after

    def _unwrap_dk(self, peer):
        w = self._st["wrapped_dk"].get(peer)
        if w is None: raise LeaseDenied("data key crypto-shredded (revoked)")
        blob = b64d(w)
        return AESGCM(self._kek).decrypt(blob[:12], blob[12:], peer.encode())

    # ---------- admin epoch (sole authority) ----------
    def _set_epoch(self, peer, epoch, state):
        payload = {"peer": peer, "epoch": epoch, "state": state}
        sig = self._admin.sign(canon(payload))
        self._st["epoch"][peer] = {**payload, "sig": sig.hex()}

    def provision_workdir_marker(self, peer):
        """LH-11: admin-signed marker proving a client workdir was provisioned by Umbrella for this peer."""
        rec = {"kind": "umbrella-workdir", "peer": peer, "workdir_id": os.urandom(16).hex(), "issued": int(self._now())}
        rec["sig"] = self._admin.sign(canon(rec)).hex(); return rec

    def current_epoch(self, peer): return dict(self._st["epoch"][peer])

    def admin_revoke(self, peer, *, backup=True):
        if backup and self._st["wrapped_dk"].get(peer) is not None:
            self._make_backup(peer)
        e = self._st["epoch"][peer]["epoch"] + 1
        self._set_epoch(peer, e, "revoked")
        self._st["wrapped_dk"][peer] = None     # CRYPTO-SHRED (future access only; L-3)
        self._save_state()
        return self.current_epoch(peer)

    def admin_unrevoke(self, peer):
        e = self._st["epoch"][peer]["epoch"] + 1
        self._set_epoch(peer, e, "active")
        dk = AESGCM.generate_key(256)
        n = os.urandom(12)
        self._st["wrapped_dk"][peer] = b64e(n + AESGCM(self._kek).encrypt(n, dk, peer.encode()))
        self._st["counter"][peer] = 0
        self._save_state()
        return dk

    # ---------- challenge / lease ----------
    def request_challenge(self, peer):
        now = self._now()
        ch = os.urandom(32).hex()
        chs = {k: v for k, v in self._st["challenges"].get(peer, {}).items() if v > now}  # drop expired
        chs[ch] = now + CHALLENGE_TTL
        self._st["challenges"][peer] = chs
        self._save_state()
        return ch

    def grant_lease(self, peer, device_sig, challenge_hex):
        now = self._now()
        hist = [t for t in self._st["rl"].get(peer, []) if now - t < RATE_LIMIT_WINDOW]
        if len(hist) >= RATE_LIMIT_MAX:
            self._st["rl"][peer] = hist; self._save_state(); raise LeaseDenied("rate limited")
        hist.append(now); self._st["rl"][peer] = hist
        ep = self._st["epoch"].get(peer)
        if ep is None or ep["state"] != "active":
            self._save_state(); raise LeaseDenied("revoked or unknown peer")
        # single-use challenge: must have been issued by us, unconsumed, unexpired (L-1)
        chs = self._st["challenges"].get(peer, {})
        exp = chs.get(challenge_hex)
        if exp is None: self._save_state(); raise LeaseDenied("unknown/consumed challenge")
        if exp <= now: chs.pop(challenge_hex, None); self._save_state(); raise LeaseDenied("challenge expired")
        chs.pop(challenge_hex, None)                    # consume
        dev = self._st["device"][peer]
        try:
            Ed25519PublicKey.from_public_bytes(b64d(dev["ed"])).verify(device_sig, bytes.fromhex(challenge_hex))
        except InvalidSignature:
            self._save_state(); raise LeaseDenied("device signature invalid")
        self._st["counter"][peer] += 1
        dk = self._unwrap_dk(peer)
        wrapped = ecies_wrap(b64d(dev["x"]), dk, peer.encode())   # device-bound (L-1)
        lease = {
            "peer": peer, "nonce": challenge_hex, "counter": self._st["counter"][peer],
            "epoch": ep["epoch"], "issued_server_time": now, "expires_server_time": now + LEASE_MAX_SECONDS,
            "device_fpr": hashlib.sha256(b64d(dev["ed"])).hexdigest()[:16],
            "wrapped_dk_sha256": hashlib.sha256(wrapped).hexdigest(),
        }
        sig = self._sign.sign(canon(lease))
        self._save_state()
        return {"lease": lease, "sig": sig.hex(), "wrapped_dk": b64e(wrapped)}

    # ---------- 30-day backup / hold / tombstone (L-10) ----------
    def _make_backup(self, peer):
        dk = self._unwrap_dk(peer)
        n = os.urandom(12)
        blob = n + AESGCM(self._backup_kek).encrypt(n, dk, ("backup:" + peer).encode())
        now = self._now()
        start_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        record = {"peer": peer, "hold_start": start_iso, "hold_start_epoch": now,
                  "min_hold_days": BACKUP_MIN_HOLD_DAYS, "sha256": hashlib.sha256(blob).hexdigest()}
        record["sig"] = self._admin.sign(canon(record)).hex()   # signed hold-start record
        atomic_write(os.path.join(self._backup_dir, peer + ".bak"), blob)
        atomic_write(os.path.join(self._backup_dir, peer + ".hold.json"), canon(record))
        self._st["backups"][peer] = {"deletion_due_epoch": now + BACKUP_MIN_HOLD_DAYS * 86400, "deleted": False}
        return record

    def access_backup_key(self, peer, who, reason):
        self._st["access_log"].append({"peer": peer, "who": who, "reason": reason, "at": self._now()})
        self._save_state()
        return True

    def erase_backup(self, peer, *, confirm_phrase, now=None):
        """Hard 30-day minimum from the SIGNED hold-start record. Writes a content-free tombstone."""
        now = now if now is not None else self._now()
        if confirm_phrase != f"erase-backup {peer}":
            raise PermissionError("needs typed confirmation phrase")
        hp = os.path.join(self._backup_dir, peer + ".hold.json")
        rec = json.loads(open(hp).read())
        payload = {k: rec[k] for k in rec if k != "sig"}
        try: self.admin_pub.verify(bytes.fromhex(rec["sig"]), canon(payload))
        except InvalidSignature: raise PermissionError("hold-start record signature invalid")
        elapsed_days = (now - rec["hold_start_epoch"]) / 86400.0
        if elapsed_days < BACKUP_MIN_HOLD_DAYS:
            raise PermissionError(f"30-day hold not met ({elapsed_days:.1f}d); refused")
        bp = os.path.join(self._backup_dir, peer + ".bak")
        n = os.path.getsize(bp)
        with open(bp, "r+b") as h: h.write(os.urandom(n)); h.flush(); os.fsync(h.fileno())
        os.unlink(bp); os.unlink(hp)
        tomb = {"peer": peer, "sha256": rec["sha256"], "hold_start": rec["hold_start"],
                "erased_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat()}  # no content
        atomic_write(os.path.join(self._backup_dir, peer + ".tombstone.json"), canon(tomb))
        self._st["backups"][peer]["deleted"] = True; self._save_state()
        return tomb
