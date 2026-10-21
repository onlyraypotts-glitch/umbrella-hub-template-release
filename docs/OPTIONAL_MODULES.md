# Optional modules (DOCS LINKS ONLY — not bundled, not enabled)
These are optional prototypes kept outside this template. They stay in their own folder. They are not copied into the template and not wired into devbridge.
Each needs its own security/QA pass and the owner's yes before it ships.

| Module | Path | What it is | Status |
|---|---|---|---|
| Secret scanner | <modules>/security/secret_scan.py | Regex + entropy + BIP39 seed-phrase rule (checksum-aware) | In use (vendored into devbridge/devbridge/) |
| BIP39 seed rule | <modules>/security/bip39_english.txt (sha256 pinned in secret_scan.py) | Wordlist for the seed-phrase rule | Vendored into devbridge; sha256 verified at vendoring |
| Personal-data scanner | <modules>/security/pii_scan.py | Names/emails/phones/wallets/handles | In use (vendored) |
| Least-privilege check | <modules>/security/least_priv.py, <modules>/security/PLAN.md | Connector scope check | Prototype (link only) |
| Update channel | <modules>/updates/manifest.py, <modules>/updates/PLAN.md, <modules>/updates/CHANGELOG.example.md | Signed update manifest | Prototype (link only, no network) |
| Antipiracy | <modules>/antipiracy/watermark.py, <modules>/antipiracy/license.py, <modules>/antipiracy/PLAN.md | Per-copy watermark + license check | Prototype (link only) |
| User reports | <modules>/reviews/user-reports/PROPOSAL.md, report.py, retest-v2/ | Bot user-report intake/rollup | DRAFT. Relevant later for dev bots filing reports over devbridge as `info` messages |
| Scan reports | <modules>/reports/secrets.count, <modules>/reports/pii.count | Counts from today's template scans (values redacted) | Reference |
