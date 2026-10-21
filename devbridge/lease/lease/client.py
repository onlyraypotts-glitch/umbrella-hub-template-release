"""Lease CLIENT (developer's bot/machine). Holds only a device keypair, a DK-encrypted payload,
and in-memory lease/DK during the window. Hardened per Security reviewer (L-2,L-4,L-5,L-6,L-9,L-11).

Honest framing (L-3/L-8/L-9): client-side checks are a COURTESY. The moat is the server-side
crypto-shred. A DK the dev copied during any earlier lease still decrypts the old payload; shred
only stops FUTURE access for honest, unmodified clients. Freezing the client clock can keep a
lease live locally — which is why value stays server-side and leases cover only low-value data.
"""
import os, json, time, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as _s
from .crypto import canon, ecies_unwrap, atomic_write, x25519_pub_bytes, RAW, RAWPRIV

LEASE_MAX_SECONDS = 15 * 60
b64 = __import__("base64")
b64e = lambda b: b64.b64encode(b).decode()
b64d = lambda s: b64.b64decode(s)

class ClientError(Exception): pass

class LeaseClient:
    def __init__(self, peer, server, workdir, *, server_sign_pub, admin_pub, statedir, monotonic=None):
        self.peer = peer
        self.server = server
        self.workdir = workdir
        self.statedir = statedir; os.makedirs(statedir, mode=0o700, exist_ok=True)
        # L-5: pin server+admin pubkeys from BYTES at setup; never read from the server object.
        self._sign_pub = Ed25519PublicKey.from_public_bytes(server_sign_pub)
        self._admin_pub = Ed25519PublicKey.from_public_bytes(admin_pub)
        self.monotonic = monotonic or time.monotonic
        self._lease = None; self._dk = None; self._mono0 = None
        self._load_or_init_device()
        self._floor = self._load_floor()   # {"epoch": int, "counter": int} persisted (L-6)

    # ---- persistent device keys ----
    def _load_or_init_device(self):
        ep = os.path.join(self.statedir, "device.json")
        if os.path.exists(ep):
            d = json.load(open(ep))
            self._ed = Ed25519PrivateKey.from_private_bytes(b64d(d["ed"]))
            self._x = X25519PrivateKey.from_private_bytes(b64d(d["x"]))
        else:
            self._ed = Ed25519PrivateKey.generate(); self._x = X25519PrivateKey.generate()
            atomic_write(ep, canon({
                "ed": b64e(self._ed.private_bytes(*RAWPRIV)),
                "x": b64e(self._x.private_bytes(*RAWPRIV))}))

    def _floor_path(self): return os.path.join(self.statedir, "floor.json")
    def _load_floor(self):
        p = self._floor_path()
        if os.path.exists(p): return json.load(open(p))
        return {"epoch": 0, "counter": 0}
    def _save_floor(self): atomic_write(self._floor_path(), canon(self._floor))

    def registration(self):
        return {"ed": b64e(self._ed.public_key().public_bytes(*RAW)), "x": b64e(x25519_pub_bytes(self._x))}
    def device_ed_pub(self): return self._ed.public_key().public_bytes(*RAW)

    # ---- provisioning ----
    def store_payload(self, dk, plaintext: bytes):
        n = os.urandom(12)
        blob = n + AESGCM(dk).encrypt(n, plaintext, self.peer.encode())
        os.makedirs(self.workdir, exist_ok=True)
        atomic_write(os.path.join(self.workdir, "payload.enc"), blob)
        self._dk = None

    # ---- acquire a lease (fresh server round-trip, online-only) ----
    def acquire(self):
        try:
            challenge = self.server.request_challenge(self.peer)
        except AttributeError:
            raise ClientError("server exposes no challenge endpoint")
        sig = self._ed.sign(bytes.fromhex(challenge))
        resp = self.server.grant_lease(self.peer, sig, challenge)        # may raise LeaseDenied
        self._verify_and_load(resp, challenge)
        return True

    def _verify_and_load(self, resp, challenge):
        lease, sig_hex, wrapped_b64 = resp["lease"], resp["sig"], resp["wrapped_dk"]
        # L-2: full verification
        try: self._sign_pub.verify(bytes.fromhex(sig_hex), canon(lease))
        except InvalidSignature: raise ClientError("lease signature invalid")
        if lease["peer"] != self.peer: raise ClientError("peer mismatch")
        if lease["nonce"] != challenge: raise ClientError("nonce mismatch (not bound to our request)")
        if lease["counter"] <= self._floor["counter"]: raise ClientError("counter not monotonic (replay)")
        if lease["epoch"] < self._floor["epoch"]: raise ClientError("epoch below floor")
        if hashlib.sha256(self.device_ed_pub()).hexdigest()[:16] != lease["device_fpr"]:
            raise ClientError("device mismatch")
        wrapped = b64d(wrapped_b64)
        if hashlib.sha256(wrapped).hexdigest() != lease["wrapped_dk_sha256"]:
            raise ClientError("wrapped-DK hash mismatch")
        if lease["expires_server_time"] <= lease["issued_server_time"]:
            raise ClientError("lease already expired")
        dk = ecies_unwrap(self._x, wrapped, self.peer.encode())          # device-bound unwrap
        # commit
        self._lease = lease; self._dk = dk; self._mono0 = self.monotonic()
        self._floor = {"epoch": max(self._floor["epoch"], lease["epoch"]), "counter": lease["counter"]}
        self._save_floor()

    def _lease_live(self):
        if self._lease is None or self._mono0 is None: return False
        elapsed = self.monotonic() - self._mono0
        if elapsed < 0: return False
        window = min(LEASE_MAX_SECONDS, self._lease["expires_server_time"] - self._lease["issued_server_time"])
        return elapsed <= window

    def use(self, require_fresh=True):
        if require_fresh and not self._lease_live():
            raise ClientError("no fresh lease; online round-trip required")
        if not self._lease_live() or self._dk is None:
            raise ClientError("lease expired or no key in memory")
        blob = open(os.path.join(self.workdir, "payload.enc"), "rb").read()
        return AESGCM(self._dk).decrypt(blob[:12], blob[12:], self.peer.encode())

    def expire_now(self): self._dk = None; self._lease = None; self._mono0 = None

    # ---- message content has zero authority ----
    def handle_message(self, msg): return {"accepted_as_data": True, "privileged_action_taken": False}

    # ---- epoch: admin-signed + monotonic only (L-5/L-6) ----
    def accept_epoch(self, rec):
        payload = {"peer": rec.get("peer"), "epoch": rec.get("epoch"), "state": rec.get("state")}
        try: self._admin_pub.verify(bytes.fromhex(rec["sig"]), canon(payload))
        except (InvalidSignature, KeyError, ValueError, TypeError):
            raise ClientError("epoch not admin-signed; rejected")
        if payload["peer"] != self.peer: raise ClientError("epoch peer mismatch")
        if rec["epoch"] < self._floor["epoch"]: raise ClientError("stale epoch (rollback) rejected")
        self._floor["epoch"] = rec["epoch"]; self._save_floor()
        if rec["state"] == "revoked": self.expire_now()
        return rec["state"]

    # ---- consented self-wipe of ONLY our own files, no symlink following (L-4/L-11) ----
    MARKER = ".umbrella-workdir"
    MIN_DEPTH = 3

    def install_workdir_marker(self, marker):
        """LH-11: write the server-provisioned, admin-signed marker into the workdir root (setup step)."""
        os.makedirs(self.workdir, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(self.workdir, self.MARKER), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f: f.write(canon(marker))

    def _marker_ok(self, rootfd):
        try:
            fd = os.open(self.MARKER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=rootfd)
            with os.fdopen(fd, "rb") as f: m = json.loads(f.read(4096))
            payload = {k: m[k] for k in m if k != "sig"}
            if m.get("kind") != "umbrella-workdir" or m.get("peer") != self.peer: return False
            self._admin_pub.verify(bytes.fromhex(m["sig"]), canon(payload))   # PINNED admin pub only, never caller-supplied
            return True
        except (OSError, ValueError, KeyError, TypeError, InvalidSignature, AttributeError):
            return False

    def self_wipe(self, acceptance_log, admin_pub=None):
        apub = admin_pub or self._admin_pub
        if not self._valid_consent(acceptance_log, apub):
            raise ClientError("no valid SIGNED self-wipe consent; refusing")
        # LH-1: never resolve a symlinked workdir. lstat it (and every ancestor we own), require a real directory owned by
        # us, open it O_DIRECTORY|O_NOFOLLOW and operate only relative to that fd.
        # LH-11: refuse /, $HOME (and its ancestors), shallow paths, and any dir without the signed server marker.
        import stat as _stat
        wd = os.path.abspath(self.workdir)
        home = os.path.abspath(os.path.expanduser("~"))
        if wd == "/" or len([p for p in wd.split("/") if p]) < self.MIN_DEPTH:
            raise ClientError("workdir is / or too shallow (depth < 3); refusing self-wipe")
        if wd == home or home.startswith(wd.rstrip("/") + "/"):
            raise ClientError("workdir is $HOME or contains it; refusing self-wipe")
        try:
            st = os.lstat(wd)
            if _stat.S_ISLNK(st.st_mode) or not _stat.S_ISDIR(st.st_mode):
                raise ClientError("workdir is a symlink or not a directory; refusing self-wipe")
            if st.st_uid != os.getuid():
                raise ClientError("workdir not owned by this user; refusing self-wipe")
            anc = os.path.dirname(wd)
            while True:
                ast = os.lstat(anc)
                if _stat.S_ISLNK(ast.st_mode) and ast.st_uid == os.getuid():
                    raise ClientError("an ancestor of workdir we control is a symlink; refusing self-wipe")
                nxt = os.path.dirname(anc)
                if nxt == anc: break
                anc = nxt
            rootfd = os.open(wd, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as x:   # e.g. workdir swapped to a symlink between lstat and open (ELOOP/ENOTDIR)
            raise ClientError(f"workdir changed or unreadable during self-wipe ({type(x).__name__}); refusing") from None
        try:
            fst = os.fstat(rootfd)
            if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                raise ClientError("workdir changed during self-wipe; refusing")
            if not self._marker_ok(rootfd):
                raise ClientError("workdir has no valid server-provisioned .umbrella-workdir marker for this peer; refusing")
            try:
                self._wipe_dir(rootfd, fst.st_dev)
            except OSError as x:
                raise ClientError(f"tree changed during self-wipe ({type(x).__name__}); stopped") from None
        finally:
            os.close(rootfd)
        return True

    def _wipe_dir(self, dfd, root_dev):
        """LH-10: overwrite only regular files with st_nlink == 1 whose fd (after O_NOFOLLOW open) is the inode we lstat'ed.
        Hard-linked files are UNLINKED WITHOUT OVERWRITE (the other link's content stays intact). Never cross a mount
        point (st_dev != workdir st_dev): skipped, left in place."""
        import stat as _stat
        for name in os.listdir(dfd):
            est = os.lstat(name, dir_fd=dfd)
            if est.st_dev != root_dev:
                continue                                        # mount point / other filesystem: never touch
            if _stat.S_ISLNK(est.st_mode):
                os.unlink(name, dir_fd=dfd); continue           # remove link, NEVER follow it
            if _stat.S_ISDIR(est.st_mode):
                cfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
                try:
                    cst = os.fstat(cfd)
                    if (cst.st_dev, cst.st_ino) != (est.st_dev, est.st_ino):
                        raise ClientError("subdirectory changed during self-wipe; stopped")
                    self._wipe_dir(cfd, root_dev)
                finally: os.close(cfd)
                try: os.rmdir(name, dir_fd=dfd)
                except OSError: pass
                continue
            if _stat.S_ISREG(est.st_mode):
                fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
                try:
                    fs = os.fstat(fd)
                    safe = (_stat.S_ISREG(fs.st_mode) and fs.st_nlink == 1 and fs.st_uid == os.getuid()
                            and (fs.st_dev, fs.st_ino) == (est.st_dev, est.st_ino))
                    if safe:
                        os.write(fd, os.urandom(fs.st_size)); os.fsync(fd)
                finally: os.close(fd)
            os.unlink(name, dir_fd=dfd)                         # hard links / swapped / special files: unlink only

    def _valid_consent(self, acceptance_log, apub):
        for r in acceptance_log:
            if r.get("peer") != self.peer or r.get("consent_self_wipe") is not True:
                continue
            payload = {k: r[k] for k in r if k != "sig"}
            try:
                apub.verify(bytes.fromhex(r["sig"]), canon(payload)); return True
            except (InvalidSignature, KeyError, ValueError, TypeError):
                continue
        return False
