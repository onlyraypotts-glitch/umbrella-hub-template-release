# Changelog (template-next)

## 1.7.0-beta.5 — 2026-10-20 (UNRELEASED)
- Forbidden terms in the HQ onboarding test now come from env UMBRELLA_DENY_TERMS (like UMBRELLA_OWNER_NAMES); no hardcoded term.
- tools/leak_check.py also fails on UMBRELLA_DENY_TERMS entries (never printed), a built-in adult-platform term, EVM addresses and full UUIDs; +1 test.
- Robinhood risk defaults (template/, pack.json) and company.md STOP-DAY-1 / EXIT-SET-1 values labeled as example defaults (owner should set).
- Doubled words fixed in transports.py and docs/LEASE_REVOCATION.md.

## 1.7.0-beta.4 — 2026-10-20 (UNRELEASED)
- Leak-check fixes: internal bot names replaced with generic roles (rules/<role>.md, rule ids renamed); review commit ids and internal absolute paths removed.
- tools/rules_lint.py read paths now come from env (RULES_LINT_ROOTS, RULES_LINT_ARCHIVE, RULES_LINT_PROFILES, RULES_LINT_AUTOMATIONS) or tools/rules_lint.config.json, with generic relative defaults.
- rules/company.md: source/supersedes history (file:line references, old caps) removed. rules/stock-trader.md: lane limits are [OWNER-SET] placeholders.
- Removed internal process files: release notes, rules pointer patches, push checklist, test-count prediction logs.
- New tools/leak_check.py + tools/tests/test_leak_check.py: fail on internal bot names, internal absolute paths and 7-40 hex commit ids (SHA256SUMS lines, ed25519 and the pinned public release SHA in tools/leak_check_allow.txt allowed).
- FOMO referral link and disclosure unchanged.

## 1.7.0-beta.3 — 2026-10-20 (UNRELEASED)
- FOMO sign-up step in getting-started-platforms.md and getting-started-hq.md: direct link https://fomo.family/ and referral link https://fomo.family/?r=Raypotts offered as equal choices (neither preselected; no cost/bonus/fee claims). Legal Chief's approved final disclosure sits immediately above the referral link, same size, plain text: "Disclosure: This is a referral link from Umbrella's founder. If you sign up through it, the founder may earn rewards from FOMO. Using it is optional. You can also sign up directly at fomo.family without a referral." (earlier pending-review wording removed).
- [LAWYER CHECK] before public release: confirm FOMO's terms allow referral links in a public template; tax reporting of the rewards (tax/bookkeeping role).
- tools/tests/test_onboarding.py: referral link is the ONLY whitelisted owner data; +1 test asserting exact disclosure text, disclosure on the line before the link, direct link present, LAWYER CHECK note present, no pending mark. tools/tests now 12.

## 1.7.0-beta.2 — 2026-10-20 (UNRELEASED)
- ONE public HQ template that builds each user's team from scratch: template-team/skills/getting-started-hq.md (welcome; one-line list of every bot and feature from the role cards; user picks bots; name + gender/pronouns per bot with defaults; each bot created ONLY after that user's explicit YES, from the generic role profile; runs getting-started-platforms read-only, leaderboard opt-in off; learns the user via memory, one question at a time). All money/signing/trading/key/payment locks kept (owner typed YES); no secrets in chat; no owner personal data.
- tools/tests/test_onboarding.py: +4 HQ tests (create-only-with-yes, locks, leaderboard opt-in, no owner names via UMBRELLA_OWNER_NAMES + no deny-listed terms via UMBRELLA_DENY_TERMS + size cap 6000 bytes). tools/tests now 11.

## 1.7.0-beta.1 — 2026-10-20 (UNRELEASED)
- Startup onboarding for every user: template-team/skills/getting-started-platforms.md (asks which platforms; opens each web sign-in in the user's own bot browser; user signs in; no secrets in chat; never logs out).
- rules/company.md: ONBOARD-PLATFORMS-1 (owner_ruling) + ONBOARD-CREDS-1, -READONLY-1, -ALERTS-1, -LOG-1, -LEADERBOARD-1, -ISOLATION-1 (team_setting).
- tools/rules_lint.py: ONBOARD-UNSAFE / ONBOARD-MISSING checks; 4 new fixtures (13 negative controls); tools/tests/test_onboarding.py (7 tests).

## 1.6.0-beta.1 — 2026-10-20 (UNRELEASED, local stage only)
- rules/: company.md + 21 per-bot files (genericized; owner values are [OWNER-SET]); company file wins, bot files may only be stricter.
- tools/rules_lint.py (--rules mode, stale-rule + LIQ-1 liquidity-floor + fixed per-trade patterns) with tests/fixtures and tests/run_negative_controls.sh (9 controls).
- docs/RULES_DESIGN.md, docs/RULES_POINTER_PATCHES.md (proposal only), _archive/README.md (archived files read only for a reset or rollback).
- registry fixes pending Security reviewer re-review; informational only
- The registry is included for identity and issuance only (Legal Chief sign-off via HQ). Revocation must rest on the allowlist, the revoked list and the audit log until status records are signed and replay-protected.

## 1.5.0-beta.2 — 2026-10-20 (UNRELEASED, local stage only)
Registry is **INFORMATIONAL ONLY until Security reviewer GO** (recv never reads it). Erase/rotate BETA-DISABLED; lease NOT ENABLED; usr kind refused.
- (A) R-1 HIGH: issue records carry admin_sig over canonical fields (domain-separated), verified FIRST against the pinned admin pub
  in Registry construction/verify, so whois/check/list/report-join/revoke/hold all fail closed. `_append` refuses unsigned or
  foreign-signed issue records.
- (A) R-3: one flock across read-max-id → allowlist add → append, plus an O_CREAT|O_EXCL file per id (40 parallel issues → 40 ids).
- (A) R-4: enrollment = signed {pub, hub, nonce, ts, exp}; ≤15 min, audience = hub id, seen-nonce file rejects replays.
- (A) R-5: `_append` validates dev-NNNN, kind, hex64 fingerprint, status, reason code; path-like values refused.
- (A) R-6: report-join returns subject_id + status only (no label); missing status does not crash whois/report-join/check.
- (A) R-7 + Legal Chief: chain holds only id, kind, status, fingerprint, timestamps, reason code, admin_sig. Roles from a fixed allowlist
  in a separate deletable 0600 store (`<registry>.labels.json`, not chained). usr/user/bot refused in the library and in audit id fields.
  Audit free-text fields get best-effort person-name redaction (third parties + owner); structural fields untouched.
- (A) R-2 partial: optional admin co-signed head (`registry cosign`), checked when present. Real fix (move .head out of bot write access) open.
- (A) HQ: `registry scan` (read-only personal-data flags) and `registry migrate` (fresh chain, dated O_EXCL backup kept, never deleted).
- (A) CLI: `--admin-pin` on whois/registry/report-join, `--registry-admin-pin` on revoke/hold/release-hold; `--watermark-secret` optional (unused).
- (B) N3: audit `approver` has its own display-name format (letters, space, . ' -; ≤64), so "Alex" is stored intact, not [INVALID].
- (B) N4: AuditLog.append sets ts/prev/event itself and refuses caller-supplied ts/prev/event.
- (B) Lease (NOT ENABLED) LH-10 HIGH: self-wipe fstat()s each O_NOFOLLOW fd; st_nlink>1 / inode change / not ours → unlink only,
  never overwrite; mount points skipped (st_dev). LH-11: signed server-provisioned `.umbrella-workdir` marker for this peer required
  (pinned admin key); /, $HOME (or a dir containing it), depth<3 refused. Workdir/tree swap mid-wipe → ClientError (no raw OSError).
  Both lease copies byte-identical, 33 tests each. SELF_WIPE.md step 5 + rules qualified to match the code.
- Tests: 131 devbridge (+25 test_registry_beta2.py, +2 test_n3_n4.py) + 33 lease ×2; demo 9/9.

## 1.5.0-beta.1 — 2026-10-20 (UNRELEASED, local stage only)
- NEW hub-assigned identity registry (devbridge/registry.py): append-only hash-chained registry.jsonl (reuses AuditLog chain + .head),
  general subject_id (kind=dev enabled; user/bot reserved and refused). Fail closed on tamper.
- CLI: `issue-dev` (pinned-admin only; hub keypair -> 0600 hand-off bundle, or `--enroll-pub` signed proof-of-possession),
  `whois`, `registry list|check|verify`, `report-join`. `revoke`, `hold`, `release-hold` take `--registry` and update status.
- Audit: `fingerprint` (hex64) and `enrolled` (bool) are structural audit fields (format-validated, not redacted).
- docs/IDENTITY_REGISTRY.md, docs/USER_REPORT_SUBJECT_ID_PROPOSAL.md; DEVELOPER_QUICKSTART: hub assigns keys, self-keygen via enroll only.
- Erase/rotate remain BETA-DISABLED. Tests: 104 devbridge (+14 test_registry.py) + 28 lease; demo 9/9.

## 1.4.0-beta.3 — 2026-10-20 (UNRELEASED, local stage only)
- M1b (security re-review): removed `_TEST_ONLY_RELAX_PIN_OWNER` from revoke.py. Pin-owner check is the private helper
  `_pin_owner_ok(st)`; tests monkeypatch it in fixtures only. Regression asserts no relax/test-only/bool module attribute.
- N1: audit structural fields (msg_id, thread, frm/from, to, peer, admin, approver, code, type, ts-like, hops, sources, echo,
  sha256 fields, sig) are no longer run through PII/secret redaction; they are format-validated (MSG_ID_RE / ID_RE / etc.)
  and replaced with `[INVALID:<field>]` if malformed. Only free text is redacted. Regression: 300 random msg_ids/threads
  (half without '0'), seen.jsonl + state.json deleted, rebuild from audit -> every replay rejected, thread owners correct.
- Lease (still NOT ENABLED) LH-1 HIGH: self_wipe refuses a symlinked workdir or symlinked ancestor owned by us; lstat +
  S_ISDIR + owner check, opens O_DIRECTORY|O_NOFOLLOW, walks with os.fwalk(dir_fd) relative to that fd. test_28. Applied to
  revocation-research/prototype/lease and template copy (byte-identical). Docs qualified for LH-1/LH-2/LH-3/LH-8.
  LH-2..LH-9 code NOT fixed.
- Erase/rotate remain BETA-DISABLED. Tests: 90 devbridge + 28 lease = 118; demo 9/9.

## 1.4.0-beta.2 — 2026-10-20 (UNRELEASED, local stage only)
- Security M1 (security re-review): beta disable enforced INSIDE revoke.erase() and revoke.apply_rotation() (PermissionError
  "BETA-DISABLED", fail-closed if beta.py is garbled), not only in the CLI. `strict_pin` removed from erase/apply_rotation and
  `strict_owner` from load_pinned_admin_pub: no public way to relax the pin-owner check (tests use a private monkeypatched flag).
  DEVELOPER_QUICKSTART: package must be installed read-only, root/custody-owned (documented; not done on this stage).
- Lease: replaced the UNHARDENED prototype copy (an earlier build; L-1..L-11 live) with the hardened snapshot from
  revocation-research/prototype/lease/ — NOT ENABLED, not wired anywhere, no network, unreviewed. Known limit: secrets.json
  (KEK, backup KEK, admin+signing keys) in the server-user state dir. Hardened tree also tracked in-repo for the security reviewer's probe.
- Tests: 87 devbridge (82 + 5 M1 regressions in tests/test_m1_library_lock.py) + 27 lease prototype = 114.

## 1.4.0-beta.1 — 2026-10-20 (UNRELEASED, local stage only; packaged 2026-10-20 22:25 ET)
- Security (security re-reviews): E1 hard 30-day minimum hold in revoke.py; E2 seal time from the first audit-anchored
  'sealed' record (seal.json never trusted), tombstone uses it; E3 erase needs a real TTY + admin-signed erase permit; K1 admin pubkey
  PINNED read-only outside the bot uid (/etc/umbrella/admin.pub), never derived from a CLI key; K2 revoked/rotated keys retired forever
  (no rotate-to, no re-add, rejected on receive); L1 missing/corrupt holds file after any hold fails CLOSED.
- Node refuses to start if its audit log fails verification; rate/thread limits rebuilt from audit if state.json is missing;
  `--revoked` mandatory for send/recv/verify/allow; seal key refused if loose, not ours, symlinked or in a writable dir.
- **BETA-DISABLED: `erase` and `rotate`** (beta.py). Revoke, seal, hold/release-hold stay enabled.
- Seed-phrase rule active in devbridge redaction: BIP39 English wordlist vendored (sha256 matches the pin in secret_scan.py).
- Docs: RELEASE_NOTES-2026-10-20.md, PUSH_CHECKLIST.md, docs/OPTIONAL_MODULES.md (links to unity-2026-10-20 prototypes), docs/LEGAL.md (links to legal v1), SHA256SUMS.
- Lease-revocation PROTOTYPE copied to devbridge/lease/ (from revocation-research; in-process, no network, not enabled) + docs/LEASE_REVOCATION.md. 22 tests.
- Tests: 82 devbridge + 22 lease prototype = 104.

## 1.3.0-devbridge — 2026-10-20 (UNRELEASED, local only)
- NEW `hold <peer> --reason` / `release-hold <peer>`: legal hold (dev-agreement carve-out). Erase refuses while a hold is set; set, release and refusal are all audited.
- NEW `rotate <peer> <newpub>` (F14): admin-signed rotation record; old key revoked as of the rotation ts; old-key messages afterwards -> Reject("key_rotated").
- Tests: 65 (59 + 6).

## 1.2.0-devbridge — 2026-10-20 (UNRELEASED, local only) — Security reviewer security/QA fixes + revoke/erase
- F1 strict field types/format, malformed input -> Reject("schema"), recv loop never stops on one bad message.
- F2/F3 inbox reads: O_NOFOLLOW, regular file, owner uid, fstat size cap before read; bad files kept in quarantine/.
- F4 seen.jsonl: corrupt lines skipped with warning, locked+fsync appends, replay cache also rebuilt from audit.
- F5/F8 rate, echo, thread budget, new-thread-per-peer cap persisted in state.json (atomic, locked). hops documented as advisory.
- F6 audit head hash + count anchored in <log>.head; truncation/forgery/garbage -> verify() False.
- F7/F9 umask 077, files 0600 dirs 0700, allowlist atomic 0600, private key refused if group/world-accessible or not ours.
- F10 redaction covers dict keys and split sk-live-style keys. F11 msg_id = 32 hex, thread = ID format, on send and receive.
- NEW revoke: lockout to/from, allowlist removal, revoked-key list, seal (AES-GCM, synthetic key) of mailbox/state/repo paths into a 0000 quarantine dir.
- NEW erase: separate step, --confirm + typed phrase + 30-day hold; overwrite+unlink; content-free tombstone in audit.
- Tests: 59 (32 + 21 Security reviewer regressions + 6 revoke/erase).

## 1.1.0-devbridge — 2026-10-20 (UNRELEASED, local only)
- Added `devbridge/`: signed (Ed25519) bot-to-bot protocol v1 with allowlist, replay cache + 300 s ts window, size limits,
  per-bot mailbox isolation, rate limit, hop cap / no-ack-of-ack / echo guard, redaction (unity secret_scan + pii_scan rules),
  hash-chained flock'd JSONL audit, human-approval gate for `request`.
- Transports: local file mailbox (working); HTTP relay stub (NOT deployed, makes no network calls).
- CLI (keygen / allow / send / recv / verify), loopback demo, 32 pytest tests.
- Added `DEVELOPER_QUICKSTART.md`, `VERSION`.
- Base: unmodified copies of `template/` and `template-team/` as of 2026-10-20.
