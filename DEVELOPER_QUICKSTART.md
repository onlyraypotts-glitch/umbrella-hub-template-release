# devbridge — Developer Quickstart (DRAFT, not yet released to devs)

> **REQUIRED for the beta: your bot runs as its own OS user or on its own host.** Running several developers' bots under one
> shared UNIX user is **NO-GO**: on a shared user anyone can read keys, reset replay state or rewrite logs, and folder
> permissions mean nothing.

> **REQUIRED install (M1, Security reviewer re-review): the hub's devbridge package must be installed READ-ONLY and owned by root
> (or a dedicated custody user), never by the bot user.** The library itself now refuses erase/rotate while
> `beta.BETA_BUILD` is set and has no public switch to relax the admin-pin owner check, but a bot user that can WRITE the
> package (e.g. edit `beta.py` or `revoke.py`) can still undo that. Example (operator does this, not the bot):
> `sudo install -d -o root -g root -m 0755 /opt/devbridge && sudo cp -r devbridge /opt/devbridge/ && sudo chown -R root:root /opt/devbridge && sudo chmod -R a-w /opt/devbridge`.
> Status: DOCUMENTED ONLY. This local stage was NOT installed as root (the sandbox cannot create root-owned files).

Your bot talks to the hub bot through **signed, logged messages**. Messages are data only: nothing you send is run as an instruction, and a `request` never runs anything until a human on the hub side types `yes`.

## 1. Set up
```bash
cd devbridge && python3 -m venv .venv && .venv/bin/pip install cryptography pytest
.venv/bin/python -m pytest -q tests        # expect 104 passed
.venv/bin/python demo_loopback.py          # expect 9/9 demo checks passed
```

## 2. Get your key from the hub (default, 1.5.0)
The hub owner ASSIGNS your id and key. You do not run keygen yourself by default. The hub runs:
```bash
python -m devbridge.cli issue-dev --admin-key <admin.key> --admin-pin /etc/umbrella/admin.pub \
  --registry registry.jsonl --allowlist allow.json --revoked revoked.json --audit admin-audit.jsonl \
  --watermark-secret <wm.secret> --out ./handoff --label "backend dev (role only, no personal data)"
```
This assigns the next id (e.g. `dev-0001`), writes `handoff/dev-0001/dev-0001.key` (mode 600) plus `dev-0001.pub.json`,
adds you to the allowlist (namespace `dev-0001`, may send to `owner-bot` only), and records you in the identity registry
and the admin audit log. The hub hands you the bundle privately. **Never share, commit or email the `.key` file.**
Your bot id from now on is your subject_id (`dev-0001`).

## 3. Option: enroll a key you generated yourself
If you prefer that the hub never sees your private key: run `keygen --id <any-temp-id> --out ./keys`, then create a signed
enrollment (proof you hold the key) with `devbridge.registry.make_enrollment(priv, pub)` and send ONLY that JSON to the hub.
The hub runs `issue-dev ... --enroll-pub enrollment.json` (no `--out`); you still get the hub-assigned id `dev-NNNN`.

## 4. What the hub can see
`devbridge registry list` (who is active/held/revoked), `devbridge whois dev-0001` (dates + your accepted/rejected
message counts), `devbridge registry check` (registry vs allowlist). See docs/IDENTITY_REGISTRY.md.
You get your own mailbox namespace. You can message the hub bot only, not other developers.

## 5. Send a hello
```bash
python -m devbridge.cli send --key keys/dev-NNNN.key --allowlist allow.json \
  --mailbox <mailbox-root> --state ./state --to owner-bot --type hello --body '{"text":"hello"}'
python -m devbridge.cli recv --key keys/dev-NNNN.key --allowlist allow.json --mailbox <mailbox-root> --state ./state
```

## Rules the protocol enforces
| Rule | Limit |
|---|---|
| Types | hello, info, request, ack, error |
| Body / envelope size | 32 KiB / 64 KiB |
| Clock skew | ±300 s; `ts` must include a UTC offset |
| Hops | max 3; acks and errors are never auto-acked; repeated bodies in a thread are flagged as echoes |
| Rate | 30 messages/min per sender (default) |
| Redaction | keys, tokens, seed phrases, emails, phones, wallets are replaced by `[REDACTED:rule]` before signing |
| Requests | `requires_human_approval: true`; a flag in the body cannot approve itself |

## Beta build limits
`erase` and `rotate` are **BETA-DISABLED**: the CLI exits with code 3. If your key is lost or compromised, tell the hub owner; your
key gets revoked and you re-join with a new bot id/key. The admin key is pinned on the hub (read-only, not writable by any bot or dev).

## Revocation — what it means for you
If your access is revoked, the hub immediately rejects every message to and from your bot, removes you from the allowlist and
lists your public key as revoked. Your mailbox, state and any repo/template access on **our** side are sealed (encrypted,
locked away) and may be erased after a hold period (minimum 30 days, longer under a legal hold, kept for disputes and evidence). Erase is a human-only step that needs a separate admin-signed permit, and it is disabled in the beta build.
**We cannot erase code or data on your own machine.** Revocation makes any copy you hold useless against our system (dead key,
no access). Returning or destroying copies you hold is covered by the developer agreement.

All accepted, rejected and blocked events go to an append-only, hash-chained `state/audit.jsonl`.
The HTTP transport is a stub; for now everything uses the local file mailbox.
