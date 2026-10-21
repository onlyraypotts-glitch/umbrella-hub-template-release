"""Shared crypto helpers. Synthetic keys only, local only."""
import os, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization as _s

RAW = (_s.Encoding.Raw, _s.PublicFormat.Raw)
RAWPRIV = (_s.Encoding.Raw, _s.PrivateFormat.Raw, _s.NoEncryption())

def canon(d): return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

def x25519_pub_bytes(priv): return priv.public_key().public_bytes(*RAW)

def ecies_wrap(recipient_pub_bytes, plaintext, aad):
    """Wrap plaintext to a recipient X25519 public key. Only the holder of the matching
    private key can unwrap. A replayer without the device key gets nothing (L-1)."""
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub_bytes))
    key = HKDF(hashes.SHA256(), 32, None, b"devbridge-lease-dk-v1").derive(shared)
    n = os.urandom(12)
    ct = AESGCM(key).encrypt(n, plaintext, aad)
    return eph.public_key().public_bytes(*RAW) + n + ct

def ecies_unwrap(recipient_priv, blob, aad):
    eph_pub, n, ct = blob[:32], blob[32:44], blob[44:]
    shared = recipient_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = HKDF(hashes.SHA256(), 32, None, b"devbridge-lease-dk-v1").derive(shared)
    return AESGCM(key).decrypt(n, ct, aad)

def atomic_write(path, data: bytes, mode=0o600):
    d = os.path.dirname(path) or "."
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
