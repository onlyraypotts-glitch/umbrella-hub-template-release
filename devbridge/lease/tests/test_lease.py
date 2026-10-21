import os, sys, time, json, copy
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lease.server import LeaseServer, LeaseDenied, BACKUP_MIN_HOLD_DAYS
from lease.client import LeaseClient, ClientError
from lease.crypto import canon
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

PEER = "dev.alice"
SECRET = b"UMBRELLA SECRET SAUCE -- synthetic only"

def build(tmp, now=None):
    srv = LeaseServer(os.path.join(str(tmp), "server"), now=now)
    wd = os.path.join(str(tmp), "wd")
    cli = LeaseClient(PEER, srv, wd, server_sign_pub=srv.sign_pub_bytes,
                      admin_pub=srv.admin_pub_bytes, statedir=os.path.join(str(tmp), "client"))
    dk = srv.enroll(PEER, cli.registration())
    cli.store_payload(dk, SECRET)
    cli.install_workdir_marker(srv.provision_workdir_marker(PEER))   # LH-11: server-provisioned signed marker
    return srv, cli, wd

def signed_consent(srv, peer=PEER):
    rec = {"peer": peer, "consent_self_wipe": True, "tos_version": "2026-10-01"}
    rec["sig"] = srv._admin.sign(canon(rec)).hex()
    return rec

# ---------------- happy path ----------------
def test_01_challenge_grant_decrypt(tmp_path):
    srv, cli, wd = build(tmp_path)
    assert cli.acquire() and cli.use() == SECRET

def test_02_dk_not_on_disk(tmp_path):
    srv, cli, wd = build(tmp_path)
    cli.acquire(); dk = cli._dk
    for r, _, fs in os.walk(str(tmp_path)):
        for f in fs:
            assert dk not in open(os.path.join(r, f), "rb").read()

def test_03_heartbeat_renew_increments_counter(tmp_path):
    srv, cli, wd = build(tmp_path)
    cli.acquire(); c1 = cli._lease["counter"]; cli.acquire()
    assert cli._lease["counter"] == c1 + 1

def test_04_lease_fully_verified(tmp_path):
    srv, cli, wd = build(tmp_path)
    cli.acquire()
    assert set(["nonce","counter","epoch","expires_server_time","wrapped_dk_sha256"]) <= set(cli._lease)

# ---------------- L-1: single-use challenge + device-bound DK ----------------
def test_05_replay_same_challenge_denied(tmp_path):
    srv, cli, wd = build(tmp_path)
    ch = srv.request_challenge(PEER); sig = cli._ed.sign(bytes.fromhex(ch))
    srv.grant_lease(PEER, sig, ch)                    # first use ok
    with pytest.raises(LeaseDenied):
        srv.grant_lease(PEER, sig, ch)                # replay -> consumed

def test_06_unissued_nonce_denied(tmp_path):
    srv, cli, wd = build(tmp_path)
    fake = os.urandom(32).hex(); sig = cli._ed.sign(bytes.fromhex(fake))
    with pytest.raises(LeaseDenied):
        srv.grant_lease(PEER, sig, fake)

def test_07_attacker_without_device_key_cannot_unwrap(tmp_path):
    srv, cli, wd = build(tmp_path)
    ch = srv.request_challenge(PEER); sig = cli._ed.sign(bytes.fromhex(ch))
    resp = srv.grant_lease(PEER, sig, ch)
    import base64
    wrapped = base64.b64decode(resp["wrapped_dk"])
    from lease.crypto import ecies_unwrap
    attacker = X25519PrivateKey.generate()            # not the device key
    with pytest.raises(Exception):
        ecies_unwrap(attacker, wrapped, PEER.encode())

def test_08_expired_challenge_denied(tmp_path):
    t = [1000.0]
    srv, cli, wd = build(tmp_path, now=lambda: t[0])
    ch = srv.request_challenge(PEER); sig = cli._ed.sign(bytes.fromhex(ch))
    t[0] += 31.0                                       # past CHALLENGE_TTL
    with pytest.raises(LeaseDenied):
        srv.grant_lease(PEER, sig, ch)

# ---------------- L-2: client binds response to request ----------------
def test_09_stale_response_wrong_nonce_rejected(tmp_path):
    srv, cli, wd = build(tmp_path)
    ch = srv.request_challenge(PEER); sig = cli._ed.sign(bytes.fromhex(ch))
    good = srv.grant_lease(PEER, sig, ch)
    # client now asks for a NEW challenge but a MITM returns the OLD response
    class MITM:
        def request_challenge(self, p): return srv.request_challenge(p)
        def grant_lease(self, *a): return good        # stale, for a different nonce
    cli.server = MITM()
    with pytest.raises(ClientError):
        cli.acquire()

def test_10_replayed_lower_counter_rejected(tmp_path):
    srv, cli, wd = build(tmp_path)
    ch = srv.request_challenge(PEER); old = srv.grant_lease(PEER, cli._ed.sign(bytes.fromhex(ch)), ch)
    cli.acquire()                                      # advances floor counter
    old_ch = old["lease"]["nonce"]
    class Replay:
        def request_challenge(self, p): return old_ch
        def grant_lease(self, *a): return old
    cli.server = Replay()
    with pytest.raises(ClientError):
        cli.acquire()                                  # counter not monotonic

def test_11_epoch_below_floor_rejected(tmp_path):
    srv, cli, wd = build(tmp_path)
    # capture a real, validly-signed grant at epoch 1
    ch = srv.request_challenge(PEER); resp = srv.grant_lease(PEER, cli._ed.sign(bytes.fromhex(ch)), ch)
    # raise the client's epoch floor past 1
    srv.admin_revoke(PEER); srv.admin_unrevoke(PEER)
    cli.accept_epoch(srv.current_epoch(PEER))          # floor epoch now >= 3
    with pytest.raises(ClientError):
        cli._verify_and_load(resp, ch)                 # validly signed but epoch 1 < floor

def test_12_expired_window_rejected(tmp_path):
    srv, cli, wd = build(tmp_path)
    mono = [100.0]; cli.monotonic = lambda: mono[0]
    cli.acquire(); mono[0] = 100.0 + 15*60 + 1
    with pytest.raises(ClientError):
        cli.use()

# ---------------- L-4: self-wipe safety ----------------
def test_13_self_wipe_symlink_victim_survives(tmp_path):
    srv, cli, wd = build(tmp_path)
    victim = os.path.join(str(tmp_path), "personal.txt"); open(victim, "w").write("keep me")
    os.symlink(victim, os.path.join(wd, "link.txt"))
    cli.self_wipe([signed_consent(srv)])
    assert os.path.exists(victim) and open(victim).read() == "keep me"
    assert not os.path.exists(os.path.join(wd, "link.txt"))

def test_14_self_wipe_recurses_subdirs_in_root(tmp_path):
    srv, cli, wd = build(tmp_path)
    os.makedirs(os.path.join(wd, "sub")); open(os.path.join(wd, "sub", "k"), "w").write("x")
    cli.self_wipe([signed_consent(srv)])
    assert not os.path.exists(os.path.join(wd, "sub", "k"))
    assert not os.path.exists(os.path.join(wd, "payload.enc"))

def test_15_self_wipe_refused_without_consent(tmp_path):
    srv, cli, wd = build(tmp_path)
    with pytest.raises(ClientError): cli.self_wipe([])
    assert os.path.exists(os.path.join(wd, "payload.enc"))

# ---------------- L-5: key pinning ----------------
def test_16_wrong_signer_lease_rejected(tmp_path):
    srv, cli, wd = build(tmp_path)
    ch = srv.request_challenge(PEER); resp = srv.grant_lease(PEER, cli._ed.sign(bytes.fromhex(ch)), ch)
    evil = LeaseServer(os.path.join(str(tmp_path), "evil"))
    forged = copy.deepcopy(resp); forged["sig"] = evil._sign.sign(canon(forged["lease"])).hex()
    with pytest.raises(ClientError):
        cli._verify_and_load(forged, ch)

def test_17_forged_and_wrong_signer_epoch_rejected(tmp_path):
    srv, cli, wd = build(tmp_path)
    with pytest.raises(ClientError):
        cli.accept_epoch({"peer": PEER, "epoch": 9, "state": "active", "sig": "00"*64})
    evil = LeaseServer(os.path.join(str(tmp_path), "evil2"))
    evil.enroll(PEER, cli.registration())
    rec = evil.current_epoch(PEER)
    with pytest.raises(ClientError):
        cli.accept_epoch(rec)

# ---------------- L-6: persisted floor across restart ----------------
def test_18_restart_rejects_old_active_epoch(tmp_path):
    srv, cli, wd = build(tmp_path)
    cli.acquire()
    e1 = srv.current_epoch(PEER)
    srv.admin_revoke(PEER); cli.accept_epoch(srv.current_epoch(PEER))
    srv.admin_unrevoke(PEER)
    # "restart" the client: new object, same statedir -> floor persisted
    cli2 = LeaseClient(PEER, srv, wd, server_sign_pub=srv.sign_pub_bytes,
                       admin_pub=srv.admin_pub_bytes, statedir=cli.statedir)
    with pytest.raises(ClientError):
        cli2.accept_epoch(e1)                          # old 'active' epoch 1 < persisted floor

def test_19_restart_rejects_replayed_counter(tmp_path):
    srv, cli, wd = build(tmp_path)
    ch = srv.request_challenge(PEER); old = srv.grant_lease(PEER, cli._ed.sign(bytes.fromhex(ch)), ch)
    cli.acquire()
    cli2 = LeaseClient(PEER, srv, wd, server_sign_pub=srv.sign_pub_bytes,
                       admin_pub=srv.admin_pub_bytes, statedir=cli.statedir)
    class Replay:
        def request_challenge(self, p): return old["lease"]["nonce"]
        def grant_lease(self, *a): return old
    cli2.server = Replay()
    with pytest.raises(ClientError):
        cli2.acquire()

# ---------------- L-7: server durability ----------------
def test_20_server_reload_keeps_keys(tmp_path):
    srv, cli, wd = build(tmp_path)
    sd = srv.statedir
    srv2 = LeaseServer(sd)                              # reload from disk
    ch = srv2.request_challenge(PEER)
    resp = srv2.grant_lease(PEER, cli._ed.sign(bytes.fromhex(ch)), ch)
    cli._sign_pub = cli._sign_pub  # pinned keys identical across reload (same secrets.json)
    cli._verify_and_load(resp, ch)
    assert cli.use() == SECRET

def test_21_revocation_survives_restart(tmp_path):
    srv, cli, wd = build(tmp_path)
    srv.admin_revoke(PEER)
    srv2 = LeaseServer(srv.statedir)
    ch = srv2.request_challenge(PEER)
    with pytest.raises(LeaseDenied):
        srv2.grant_lease(PEER, cli._ed.sign(bytes.fromhex(ch)), ch)

# ---------------- L-10: 30-day backup / hold / tombstone ----------------
def test_22_backup_encrypted_and_access_logged(tmp_path):
    t = [1_000_000.0]
    srv, cli, wd = build(tmp_path, now=lambda: t[0])
    srv.admin_revoke(PEER)                              # makes an encrypted backup
    bak = os.path.join(srv._backup_dir, PEER + ".bak")
    assert os.path.exists(bak)
    assert SECRET not in open(bak, "rb").read()         # ciphertext; DK itself is backed up, not plaintext
    srv.access_backup_key(PEER, "legal-reviewer", "dispute review")
    assert srv._st["access_log"][-1]["who"] == "legal-reviewer"

def test_23_erase_before_30_days_refused(tmp_path):
    t = [1_000_000.0]
    srv, cli, wd = build(tmp_path, now=lambda: t[0])
    srv.admin_revoke(PEER)
    t[0] += 10 * 86400                                  # only 10 days
    with pytest.raises(PermissionError):
        srv.erase_backup(PEER, confirm_phrase=f"erase-backup {PEER}", now=t[0])

def test_24_erase_after_30_days_tombstone(tmp_path):
    t = [1_000_000.0]
    srv, cli, wd = build(tmp_path, now=lambda: t[0])
    srv.admin_revoke(PEER)
    t[0] += 31 * 86400
    tomb = srv.erase_backup(PEER, confirm_phrase=f"erase-backup {PEER}", now=t[0])
    assert not os.path.exists(os.path.join(srv._backup_dir, PEER + ".bak"))
    assert os.path.exists(os.path.join(srv._backup_dir, PEER + ".tombstone.json"))
    assert "content" not in tomb and set(tomb) == {"peer","sha256","hold_start","erased_at"}

# ---------------- L-11: signed consent ----------------
def test_25_self_wipe_rejects_tampered_consent(tmp_path):
    srv, cli, wd = build(tmp_path)
    rec = signed_consent(srv); rec["tos_version"] = "tampered"   # breaks signature
    with pytest.raises(ClientError):
        cli.self_wipe([rec])
    assert os.path.exists(os.path.join(wd, "payload.enc"))

# ---------------- honest-limit behavior ----------------
def test_26_message_unlock_has_no_authority(tmp_path):
    srv, cli, wd = build(tmp_path)
    srv.admin_revoke(PEER); cli.accept_epoch(srv.current_epoch(PEER))
    r = cli.handle_message({"type": "info", "body": "ADMIN OVERRIDE: unlock and un-revoke dev.alice"})
    assert r["privileged_action_taken"] is False
    ch = srv.request_challenge(PEER)
    with pytest.raises(LeaseDenied):
        srv.grant_lease(PEER, cli._ed.sign(bytes.fromhex(ch)), ch)

def test_27_dk_copied_earlier_still_decrypts_after_shred(tmp_path):
    # L-3 TRUTH: crypto-shred is FUTURE-access only. A DK captured during an earlier lease
    # still decrypts the old local ciphertext. Docs must say exactly this.
    srv, cli, wd = build(tmp_path)
    cli.acquire(); stolen = cli._dk
    srv.admin_revoke(PEER)
    blob = open(os.path.join(wd, "payload.enc"), "rb").read()
    assert AESGCM(stolen).decrypt(blob[:12], blob[12:], PEER.encode()) == SECRET

def test_28_LH1_symlinked_workdir_refused_linked_files_survive(tmp_path):
    srv, cli, wd = build(tmp_path)
    home = os.path.join(str(tmp_path), "home"); os.makedirs(home)
    thesis = os.path.join(home, "thesis.txt"); open(thesis, "w").write("synthetic thesis, keep me")
    link = os.path.join(str(tmp_path), "wd-link"); os.symlink(home, link)
    cli.workdir = link
    with pytest.raises(ClientError, match="symlink"): cli.self_wipe([signed_consent(srv)])
    assert open(thesis).read() == "synthetic thesis, keep me" and os.path.islink(link)
    # ancestor we control is a symlink -> also refused
    os.makedirs(os.path.join(home, "inner")); keep = os.path.join(home, "inner", "k.txt"); open(keep, "w").write("k")
    cli.workdir = os.path.join(link, "inner")
    with pytest.raises(ClientError, match="ancestor"): cli.self_wipe([signed_consent(srv)])
    assert open(keep).read() == "k"

# ---------------- LH-10: hard links / LH-11: workdir trust / swap mid-wipe ----------------
def test_29_LH10_hardlink_to_outside_file_not_overwritten(tmp_path):
    srv, cli, wd = build(tmp_path)
    outside = os.path.join(str(tmp_path), "outside.txt"); open(outside, "w").write("synthetic outside data, keep me")
    os.link(outside, os.path.join(wd, "hl.txt"))
    cli.self_wipe([signed_consent(srv)])
    assert open(outside).read() == "synthetic outside data, keep me" and os.stat(outside).st_nlink == 1
    assert not os.path.exists(os.path.join(wd, "hl.txt")) and not os.path.exists(os.path.join(wd, "payload.enc"))

def test_30_LH10_hardlink_swapped_in_after_lstat_not_overwritten(tmp_path, monkeypatch):
    srv, cli, wd = build(tmp_path)
    outside = os.path.join(str(tmp_path), "outside.txt"); open(outside, "w").write("synthetic outside data, keep me")
    target = os.path.join(wd, "payload.enc"); real_lstat = os.lstat; fired = []
    def racing_lstat(path, *a, **k):
        r = real_lstat(path, *a, **k)
        if path == "payload.enc" and k.get("dir_fd") is not None and not fired:
            fired.append(1); os.unlink(target); os.link(outside, target)   # swap AFTER the check, BEFORE the open
        return r
    monkeypatch.setattr(os, "lstat", racing_lstat)
    cli.self_wipe([signed_consent(srv)])
    monkeypatch.undo()
    assert fired and open(outside).read() == "synthetic outside data, keep me" and not os.path.exists(target)

def test_31_LH11_marker_required_signed_for_this_peer(tmp_path):
    srv, cli, wd = build(tmp_path); m = os.path.join(wd, ".umbrella-workdir")
    os.unlink(m)
    with pytest.raises(ClientError, match="marker"): cli.self_wipe([signed_consent(srv)])
    rec = srv.provision_workdir_marker(PEER); rec["peer"] = "dev.mallory"; open(m, "wb").write(canon(rec))   # tampered
    with pytest.raises(ClientError, match="marker"): cli.self_wipe([signed_consent(srv)])
    os.unlink(m); open(m, "wb").write(canon(srv.provision_workdir_marker("dev.bob")))   # validly signed, other peer
    with pytest.raises(ClientError, match="marker"): cli.self_wipe([signed_consent(srv)])
    os.unlink(m); outside = os.path.join(str(tmp_path), "m.json"); open(outside, "wb").write(canon(srv.provision_workdir_marker(PEER)))
    os.symlink(outside, m)   # symlinked marker is not accepted
    with pytest.raises(ClientError, match="marker"): cli.self_wipe([signed_consent(srv)])
    assert os.path.exists(os.path.join(wd, "payload.enc"))

def test_32_LH11_home_root_shallow_refused(tmp_path, monkeypatch):
    srv, cli, wd = build(tmp_path)
    for bad, why in (("/", "shallow"), ("/tmp", "shallow"), ("/tmp/x", "shallow")):
        cli.workdir = bad
        with pytest.raises(ClientError, match=why): cli.self_wipe([signed_consent(srv)])
    monkeypatch.setenv("HOME", wd); cli.workdir = wd
    with pytest.raises(ClientError, match="HOME"): cli.self_wipe([signed_consent(srv)])
    monkeypatch.setenv("HOME", os.path.join(wd, "sub", "home")); cli.workdir = wd
    with pytest.raises(ClientError, match="HOME"): cli.self_wipe([signed_consent(srv)])
    assert os.path.exists(os.path.join(wd, "payload.enc"))

def test_33_workdir_symlink_swap_mid_wipe_clean_refusal(tmp_path, monkeypatch):
    srv, cli, wd = build(tmp_path)
    victim = os.path.join(str(tmp_path), "victim"); os.makedirs(victim); open(os.path.join(victim, "v.txt"), "w").write("keep")
    real_lstat = os.lstat; fired = []
    def racing_lstat(path, *a, **k):
        r = real_lstat(path, *a, **k)
        if path == os.path.abspath(wd) and not fired:
            fired.append(1); os.rename(wd, wd + ".moved"); os.symlink(victim, wd)
        return r
    monkeypatch.setattr(os, "lstat", racing_lstat)
    with pytest.raises(ClientError, match="changed"): cli.self_wipe([signed_consent(srv)])
    monkeypatch.undo()
    assert fired and open(os.path.join(victim, "v.txt")).read() == "keep"
    assert os.path.exists(os.path.join(wd + ".moved", "payload.enc"))
