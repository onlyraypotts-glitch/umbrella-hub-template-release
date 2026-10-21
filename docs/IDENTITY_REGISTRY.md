# Identity registry (1.5.0-beta.2, local only, synthetic data in tests)

> **INFORMATIONAL ONLY until Security reviewer GO.** Message delivery (`recv`) never reads the registry; it decides from the allowlist and
> revoked list only. Don't use `whois`, `list`, `check` or `report-join` output as identity or legal evidence until Security reviewer re-reviews.

## For the owner: what this is, in plain words
- Every developer gets an id **we** hand out: `dev-0001`, `dev-0002`, ... in order. The hub makes their key and hands it over
  privately, or the dev sends a signed enrollment (`--enroll-pub`).
- `registry.jsonl` is the record book. Lines are only ever added. Each line is chained to the one before, and every "issued"
  line carries the admin's signature, checked against the pinned admin key. If anything is edited or unsigned, every tool
  refuses to run ("fail closed").
- **No personal data in the record book.** It holds only: opaque id, kind (`dev`), status, key fingerprint, timestamps,
  a reason **code** (`issued|revoked|held|released|migrated`) and the admin signature.
- **Labels are a role, from a fixed list only:** backend, frontend, fullstack, mobile, qa, docs, design, security, ops, data,
  contractor. Names, phone numbers, emails and any other text are refused. Roles live in a **separate deletable file**
  (`registry.jsonl.labels.json`, 0600, not chained). Deleting it, or one entry, does not break the record book.
- Status: **active**, **held** (legal hold), **revoked**.

## Record fields (chain)
Issue record: `subject_id, kind, status, fingerprint, issued_at, reason="issued", admin_sig` (+ chain `ts, prev`).
`admin_sig` = Ed25519 over canonical JSON of `{domain:"devbridge-registry-issue-v1", subject_id, kind, status, fingerprint,
issued_at, reason}` with the PINNED admin key. Status records (revoke/hold/release): `subject_id, status, reason (code),
updated_at[, revoked_at]`; unsigned (the bot-side revoke has no admin key; see Limits). Free-text reasons go to the audit log,
which redacts secrets, PII and person names in free-text fields.

## Guards (library, not only CLI)
| guard | where |
|---|---|
| admin_sig verified FIRST, then hash chain + .head, then optional co-signed head | `Registry.problems()`; at construction, so verify/whois/check/list/report-join/revoke/hold all fail closed |
| unsigned or foreign-signed issue record refused | `Registry._append` |
| value formats: `dev-NNNN`, kind=dev, 64-hex fingerprint, status, reason code; path-like/control values refused | `_append` (R-5) |
| `user`/`usr`/`bot` kinds and `usr-`/`bot-` ids refused | `issue_dev`, `_append`, `set_label`, `join_report`; audit id fields store `[REFUSED:<field>:reserved-kind]` |
| one `flock` across read-max-id → allowlist add → append, plus `O_CREAT|O_EXCL` file per id in `registry.jsonl.ids/` | `issue_dev` (R-3; 40 parallel issues → 40 distinct ids) |
| enrollment: signed `{pub, hub, nonce, ts, exp}`; exp−ts ≤ 15 min; wrong hub, expired, replayed nonce refused | `check_enrollment` (R-4; seen nonces in `registry.jsonl.nonces`) |
| `report-join` returns `subject_id` + `status` only, never a label; missing status → `"unknown"` | `join_report` (R-6) |

## Commands
| Command | Who | What |
|---|---|---|
| `issue-dev [--label ROLE]` | admin (pinned key) | next id, keypair (or `--enroll-pub`), allowlist entry, signed registry record, role in label store |
| `revoke/hold/release-hold ... --registry [--registry-admin-pin]` | admin | existing behaviour, then a status record |
| `registry list/check/verify [--admin-pin]` | admin | table / mismatch report / full verification |
| `registry cosign --admin-key` | admin | sign the current (count, head) into `registry.jsonl.head.sig` (R-2, partial) |
| `registry scan` | admin | **read-only**: flag records whose label/reason/other text looks personal (names, phones, emails, handles); rc=1 if any |
| `registry migrate --admin-key` | admin | rebuild a fresh chain without personal fields (see below) |
| `whois <id or fingerprint> --audit <log>` | admin | status, dates, role, accepted/rejected counts |
| `report-join --intake <jsonl>` | admin | attach `{subject_id, status}` to user reports that carry `subject_id` |

## Migrating a 1.5.0-beta.1 chain (it holds display labels / free-text reasons)
The chain can't be edited in place, so:
1. `devbridge registry scan --registry R` lists flagged records (line, subject_id, field, categories). Nothing is changed.
2. `devbridge registry migrate --registry R --admin-key K --admin-pin P`:
   - refuses unless the old hash chain verifies AND every old issue record's admin_sig verifies (old canonical form), so a
     forged chain is never laundered into a freshly signed one; refuses if the chain is already in the new format;
   - copies `R` and `R.head` to `R.pre-migration-<YYYYmmddTHHMMSS>[.head]` (O_EXCL: an existing backup is never overwritten),
     **the backup is never deleted by the tool**;
   - writes a fresh chain with only the Legal Chief fields, re-signed by the pinned admin; moves allowed-role labels to the
     label store and drops everything else (names, phones, free text, `namespace`, `watermark_ref`, `issued_by`);
   - an old `R.head.sig` is moved next to the backup.
3. Then decide with Legal Chief what happens to the backup (it still holds the personal data). Deleting it is a manual, human step.

## Audit linkage
The dev's bot id IS its subject_id, so audit entries (`frm`/`peer`) resolve to the registry. A fingerprint also resolves via whois.

## Future: one id space for the whole company
`subject_id = <prefix>-<number>`; kind in {dev (enabled), user (`usr-NNNN`, reserved), bot (`bot-NNNN`, reserved)}. Reserved kinds
are refused in the library today (tested). Enabling them needs the owner's yes, Legal Chief's privacy review and the security reviewer's review. Any person
link must live in a separate deletable store (or an HMAC with a destroyable key), never in the chain.

## Limits (be honest)
- **R-2 / M3 class, NOT fixed:** someone who can rewrite `registry.jsonl` and `.head` can rewrite history. Fixing R-1 means
  forged *issue* records fail (they need the admin key), but **unsigned status records can still be forged or dropped** by
  that user. The optional co-signed head detects rewrites of the co-signed prefix only. **The real fix is to move `.head`
  (and the co-signed head) out of the bot user's write access** (root/custody-owned path, or an external append-only store).
- Name redaction in the audit log is best effort (capitalised "First Last" pairs + the owner's name). It misses single or
  lowercase names and non-Latin scripts, and can over-redact capitalised word pairs.
- Hub-generated keys mean the hub saw the private key once; use `--enroll-pub` where that matters.
- A failed issue can burn an id (its `.ids/` guard file stays); ids are then not gap-free.
- Status changes are unsigned; signing them needs the admin key on the revoke path (custody decision for the owner + security review).

## Scope note (1.6.0-beta.1)
The registry is included for identity and issuance only (Legal Chief sign-off via HQ). Revocation must rest on the allowlist, the revoked list and the audit log until registry status records are signed and replay-protected. The security reviewer's re-review is still pending; the registry stays INFORMATIONAL ONLY.
