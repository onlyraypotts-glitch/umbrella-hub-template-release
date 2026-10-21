# lease/ — HARDENED PROTOTYPE — **NOT ENABLED** (not in the beta feature set, no network)

> **NOT ENABLED.** Not imported by devbridge, not wired into the CLI, erase or rotate. In-process only, no network code.
> Unreviewed: awaiting Security reviewer (security review) probe. Do not ship as a feature.

Snapshot of the hardened tree at revocation-research/prototype/lease/ (taken 2026-10-20 ~22:34 ET; replaces the old
unhardened copy that an earlier build shipped, which had L-1..L-11 live: client-picked nonce, plaintext DK in lease, memory-only
state, no backup). Hardened: server-issued challenges, ECIES-wrapped DK, persisted server/client state, signed hold-start
record + 30-day backup minimum, signed consent for self-wipe (LH-8: caller can supply the verify key, so not
admin-enforced). 1.4.0-beta.3: LH-1 fixed (self-wipe refuses a symlinked workdir / owned symlinked ancestor; test_28).
1.5.0-beta.2: LH-10 fixed (fstat after O_NOFOLLOW open; st_nlink>1 or inode change -> unlink only, never overwrite; mount
points skipped; test_29/30), LH-11 (signed `.umbrella-workdir` marker required; /, $HOME, depth<3 refused; test_31/32),
swap mid-wipe -> ClientError (test_33). Still NOT ENABLED.

## Known limits (for the security reviewer's probe — NOT fixed in this pass)
- **Custody not separated:** LeaseServer writes `secrets.json` (KEK, backup KEK, admin + signing private keys) into the
  server-user state dir. Anyone who can read/write that dir as the server user holds the admin key. Needs a custody user/KMS.
- L-3: a DK captured during a valid lease still decrypts after crypto-shred (shred is future-access only).
- L-8: a live lease survives revoke until expiry (<=15 min) without an epoch push.
- L-9: client-side clock/monotonic checks are a courtesy on dev-controlled hardware.
- LH-2: signed hold-start record is only as good as admin-key custody (key is in secrets.json, see above).
- LH-3: backup deletion is NOT scheduled; only a deletion-due marker is written, no sweeper.
- Self-wipe touches nothing outside the workdir only on an honest, unmodified client (not vs root/modified client).
- Self-wipe is a courtesy, not a security control. Only server-side access is the moat.

Run: `../../../.venv/bin/python -m pytest -q tests -p no:cacheprovider` (33 tests).
