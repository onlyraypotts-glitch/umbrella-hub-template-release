# Routine: weekly-team-review (HQ + Quant Lab; suggested Sunday 7:12 PM, owner's timezone)

Runs after Quant Lab's Sunday 6:12 PM calibration pass. Measurement only; it never loosens a rule.

1. Pull: `desk.py calibration`, `signal-value`, `leaderboard strategies|sources|callers`, `bot-scorecard --week <ISO week>`, `query events`, `ladder`.
2. Per bot (write a `bot_performance` row each): useful discoveries first, false positives, duplicates, latency, stale data, accuracy.
3. Calibration: did 0.75+ calls hit ≥ 55%? Per bucket n, actual, Wilson interval. n < 30 = "too small". Run `desk.py audit-bar` (it can only raise the bar).
4. Signals with no lift after n ≥ 20 per side → propose lower weight. Correlated signals → merge.
5. Sources and callers that earned or lost trust → update `source_reliability`.
6. Strategy stage moves (idea → backtest → validation → OOS → shadow/paper → small live → production, or retired) and the week's research-lab hypothesis result (recorded either way).
7. Compute: what to cache or drop. Near-misses of any rule: report them.
8. Send the owner one short review: what worked, what didn't, the one change that would most improve next week, any proposals waiting for their OK. Performance never loosens hard limits.
