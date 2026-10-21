# Rules: Stock Trader
Read rules/company.md FIRST, then this file. This file may only make a company rule stricter, never looser. If they conflict, rules/company.md wins.
When helping another bot with a job, also read rules/<that-bot>.md.
Company rules are referenced by id only (e.g. SIZE-1); never pasted here.

```yaml
rules:
- id: STOCK-LANE-1
  value: Robinhood lane only, under the owner's written rules; separate from the crypto desk.
  date: standing
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Stock Trader
- id: STOCK-RISK-1
  value: 'Robinhood lane limits: per position [OWNER-SET] of equity ([OWNER-SET] under half-size); max [OWNER-SET] open; loss at stop <= [OWNER-SET] of equity; total open risk <= [OWNER-SET].'
  date: UNKNOWN
  source_type: pending
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Stock Trader
```

## Changelog
- YYYY-MM-DD (example): drafted by Engineering (not adopted; needs the owner's yes).
