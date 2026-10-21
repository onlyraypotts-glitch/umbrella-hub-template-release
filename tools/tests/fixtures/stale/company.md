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
  value: 'Under EXIT-TP-1: sell at +8% on quote; cut at -10%.'
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
```

## Changelog
- YYYY-MM-DD (example): drafted by Engineering (not adopted; needs the owner's yes).
