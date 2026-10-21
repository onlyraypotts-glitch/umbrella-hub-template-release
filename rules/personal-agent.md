# Rules: Personal Agent
Read rules/company.md FIRST, then this file. This file may only make a company rule stricter, never looser. If they conflict, rules/company.md wins.
When helping another bot with a job, also read rules/<that-bot>.md.
Company rules are referenced by id only (e.g. SIZE-1); never pasted here.

```yaml
rules:
- id: PERSONAL-TFM-1
  value: 'Role/boundary: trade-for-me on the owner''s own account only after paper trading ends; RAYPOS-1 applies until the owner says otherwise.'
  date: UNKNOWN
  source_type: pending
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Personal Agent
- id: PERSONAL-HEALTH-1
  value: 'Health data stays in the owner''s private health folder only; no other bots, repos or unapproved AI.'
  date: standing
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Personal Agent
- id: PERSONAL-PORTAL-1
  value: 'The owner''s government benefits/health portal is read-only; booking, cancelling, messages and claims each need the owner''s typed yes. Never log out.'
  date: standing
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Personal Agent
- id: PERSONAL-MAIL-1
  value: 'The owner''s personal email: label and archive only. No delete, send, pay or link clicks; replies are drafts only.'
  date: standing
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Personal Agent
- id: PERSONAL-PRIV-1
  value: 'the owner''s private, adult and non-company business matters stay out of every room and shared file.'
  date: standing
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Personal Agent
```

## Changelog
- YYYY-MM-DD (example): drafted by Engineering (not adopted; needs the owner's yes).
- YYYY-MM-DD (example): filled from profile + owner rulings by Engineering.
