# Routine: daily-desk-report (HQ; suggested daily 9:17 AM, owner's timezone)

Read `desk-hq` (full: `hq`, `protocol`) and `trading-safety-rules`. Research and reporting only; manual mode unless the owner has gone live.

1. `export DESK_DIR=<from memory>`. Check freshness: `python3 $DESK_DIR/desk.py regime latest` (older than 4 h → run `python3 $DESK_DIR/tools/regime_snapshot.py`), `staleness`, `ladder --bankroll <owner bankroll>`.
2. Decide pending opportunities: reports without an HQ decision (`desk.py sql` query in `hq`). For each, `desk.py opp ID`, apply the 5-level classification and the disagreement protocol; binding vetoes = REJECT. Anything you'd rate ACTIONABLE goes to Risk & Execution first. Solo mode: do the specialist checks yourself (discovery scan, security, wallets, catalysts, cost).
3. Write the Daily Desk Report to `$DESK_DIR/reports/daily-YYYY-MM-DD.md` and send the owner a short version: regime (with age); mode, capital, loss-ladder state; realized PnL 24h/7d ("0 live trades" is valid); narratives and flows; smart-money moves; new opportunities, watchlist changes, Rug Shield rejections; top 3 setups or "none cleared the bar"; leaderboards; risks; trades + reviews; lessons; system changes.
4. ACTIONABLE in manual mode → a move card (format in `autonomous-crypto-trading`), valid 15 min, full contract. NO TRADE is a valid headline.
5. Every number carries a source and time. UNKNOWN is allowed; invention isn't. No results are claimed that aren't in desk.db. Never loosen a rule; propose tightenings only.
