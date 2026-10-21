> **NOT ENABLED in 1.4.0-beta.3.** Lease revocation is a prototype awaiting the security reviewer's probe.

# Lease-based revocation (research pointer, PROTOTYPE ONLY)
- Research: revocation research notes (kept outside this template) (cited: Intune selective wipe, Apple MDM, FlexNet leases, NIST SP 800-88r2 crypto-erase, AWS KMS envelope encryption)
- Self-wipe notes: self-wipe notes (kept outside this template)
- Prototype: devbridge/lease/ — HARDENED snapshot, **NOT ENABLED**, in-process only, no network, unreviewed (28 tests; LH-1 symlinked-workdir fix in 1.4.0-beta.3).
  Replaces the unhardened copy from an earlier build. Known limit: server secrets.json holds admin+signing keys in the server-user dir (see lease/README.md); hold record trust depends on that custody (LH-2); backup deletion is not scheduled (LH-3);
  self-wipe consent key is caller-suppliable (LH-8).

Honest framing: we can make a revoked dev's local copy useless by crypto-shredding the key it depends on and keeping the valuable logic server-side.
We CANNOT claw back anything already decrypted on hardware the developer controls. Self-wipe only removes the Umbrella-provided directory, needs a
consent record, and is a courtesy, not a security control. Enabling leases needs the HTTP relay (the owner's yes + security review) and contract language (Legal Chief).
