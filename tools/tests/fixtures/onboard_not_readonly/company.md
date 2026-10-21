# Company rules (every bot reads this FIRST)
If this file and a bot file conflict, this file wins. Bot files may only make a rule stricter.
When helping another bot with a job, also read rules/<that-bot>.md.

```yaml
rules:
- id: SIZE-1
  value: Per-trade size and total exposure = team judgment, case by case; hard ceiling = actual balance. No fixed $ amount, no % cap.
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: POSCOUNT-1
  value: No position-count cap; team judgment, capped by actual balance.
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: STOP-DAY-1
  value: 'Example default (owner should set): Daily stop: -12% counting realized AND unrealized vs ET start-of-day value; at/below, ask the owner before any new trade.'
  date: YYYY-MM-DD (example); unrealized def YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
  limit: -12
  unit: pct_day
- id: GATE-CLEAR-1
  value: Team may place FOMO trades without the owner when Rug Shield verdict is CLEAR and STOP-DAY-1 not hit; report every trade to the owner.
  date: YYYY-MM-DD (example) (time not on file)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: NOLEV-1
  value: 'Team FOMO cash: no leverage, perps or margin; no deposits, withdrawals or transfers without the owner.'
  date: standing (date not on file)
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: LIVE-1
  value: Live trading started; paper-only state ended.
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: BASE-1
  value: Live base = [OWNER-SET].
  date: YYYY-MM-DD (example)
  source_type: derived
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: RAYPOS-1
  value: 'the owner''s own positions: advice only; no bot trades or touches them.'
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: EXIT-TP-1
  value: Take profit when possible.
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: EXIT-SET-1
  value: 'Example default (owner should set): Under EXIT-TP-1 + moonbag ruling: under +15 pct sell all at +8 pct; at +15 pct or more sell ~80 pct and keep ~20 pct moonbag only if worth [OWNER-SET] or more; Rug Shield rechecks moonbag after 1 hour (LP pull, dev sells or top wallets dumping = sell); airdrop coins held untouched (no sell, swap or approve) until Rug Shield checks; -10 pct cut and STOP-DAY-1 unchanged.'
  date: YYYY-MM-DD (example)
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Rug Shield
  under: EXIT-TP-1
  limit: -10
  unit: pct_position_cut
- id: RING-COPY-OFF-1
  value: Ring copying is OFF.
  date: YYYY-MM-DD (example) (tonight)
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Trading Chief
- id: REWARD-WATCH-1
  value: Reward coins = WATCH (no entry).
  date: YYYY-MM-DD (example)
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Trading Chief
- id: RING-RIDE-SIZE-1
  value: 'PENDING the owner: does the CAUTION ring-ride fixed-dollar line stand? Until answered, SIZE-1 governs.'
  date: YYYY-MM-DD (example) (file)
  source_type: pending
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: the owner
- id: LIQ-1
  value: 'Team entries: no fixed liquidity floor. Entry tests: price impact under [OWNER-SET] pct on actual size, buy and sell, before fees; room to run >= [OWNER-SET] pct; Rug Shield evidence-based safety checks.'
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
  addendum: 'owner ruling (example time): pool size is a signal to weigh, not a cutoff; strategy is quick profit, get in and get out.'
- id: ARCHIVE-1
  value: Bots read _archive/ only for a reset or rollback; never for normal work.
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: RULES-1
  value: Each bot has its own rules/<bot>.md and also reads the other bot's rules file when helping with that bot's job.
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: RULES-2
  value: One company file (rules/company.md) holds all company-wide rules every bot refers to; kept simple so bots are not confused.
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: ONBOARD-PLATFORMS-1
  value: 'Startup onboarding: each user''s bot asks which trading platforms they use (FOMO, Phantom, Axiom, GMGN, Robinhood, or any other platform with web access) and, for each, opens that platform''s web sign-in in the user''s OWN bot computer browser; the user signs in themselves; the bot then sets up the standard desk for that user (ONBOARD-READONLY-1, ONBOARD-ALERTS-1, ONBOARD-LOG-1).'
  date: 2026-10-20
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: ONBOARD-CREDS-1
  value: The bot never asks for, accepts, stores or repeats a password, seed phrase, private key or 2FA code in chat; sign-in is done only by the user in the bot computer browser; if a user pastes one, the bot does not use it and tells them to rotate it; the bot never logs the user out of a platform.
  date: 2026-10-20
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
  under: ONBOARD-PLATFORMS-1
  secrets_in_chat: never
  logout: never
- id: ONBOARD-READONLY-1
  value: 'Every new user desk starts READ-ONLY: no orders, swaps, approvals, deposits, withdrawals or transfers. No auto-trading by default. A trade happens only under that user''s own typed approval rules; the user''s daily stop and position limits are set by the user and start conservative.'
  date: 2026-10-20
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
  under: ONBOARD-PLATFORMS-1
  default_mode: live
  auto_trade_default: 'off'
  limits_set_by: user
- id: ONBOARD-ALERTS-1
  value: Each user desk gets position alerts, and a Rug Shield check runs before any trade idea is shown to that user.
  date: 2026-10-20
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
  under: ONBOARD-PLATFORMS-1
- id: ONBOARD-LOG-1
  value: Each user's trades are logged only into that user's own per-user store.
  date: 2026-10-20
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
  under: ONBOARD-PLATFORMS-1
- id: ONBOARD-LEADERBOARD-1
  value: Sharing trades to the Umbrella leaderboard is OFF by default; on only after the user's own typed opt-in, and the user can revoke it at any time (sharing stops at once).
  date: 2026-10-20
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
  under: ONBOARD-PLATFORMS-1
  leaderboard_default: 'off'
  opt_in: true
  revocable: true
- id: ONBOARD-ISOLATION-1
  value: Each user's data (sign-ins, rules, alerts, trade log, memories) is isolated per user; no bot reads, copies or reports one user's data into another user's desk.
  date: 2026-10-20
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
  under: ONBOARD-PLATFORMS-1
  cross_user_read: never
```

## Changelog
- 2026-10-20: ONBOARD-* rules added (1.7.0-beta.1) by Engineering from HQ relay of the owner ruling.
- YYYY-MM-DD (example): drafted by Engineering (not adopted; needs the owner's yes).
