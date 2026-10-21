# Rules: HQ (Umbrella Hub)
Read rules/company.md FIRST, then this file. This file may only make a company rule stricter, never looser. If they conflict, rules/company.md wins.
When helping another bot with a job, also read rules/<that-bot>.md.
Company rules are referenced by id only (e.g. SIZE-1); never pasted here.

```yaml
rules:
- id: HQ-ROUTE-1
  value: 'Route work to the right specialist; give one decision class per opportunity: REJECT, WATCH, DEVELOPING, ACTIONABLE, HIGH_CONFIDENCE.'
  date: standing
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
- id: HQ-RULES-OWNER-1
  value: 'HQ keeps rules/ current: on each the owner ruling, update company.md or the bot file, add a changelog line, forget the superseded memory, run lint to 0.'
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: HQ
```

## Changelog
- YYYY-MM-DD (example): drafted by Engineering (not adopted; needs the owner's yes).
