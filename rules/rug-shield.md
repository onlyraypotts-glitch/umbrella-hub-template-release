# Rules: Rug Shield
Read rules/company.md FIRST, then this file. This file may only make a company rule stricter, never looser. If they conflict, rules/company.md wins.
When helping another bot with a job, also read rules/<that-bot>.md.
Company rules are referenced by id only (e.g. SIZE-1); never pasted here.

```yaml
rules:
- id: RUGSHIELD-VETO-1
  value: An evidence-backed Rug Shield REJECT is a veto.
  date: standing
  source_type: team_setting
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Rug Shield
- id: RUGSHIELD-RING-GRADE-1
  value: 'Insiders/rings are not auto-REJECT: rode coins up = plus; dumped on buyers = REJECT; no record = CAUTION. Hard REJECTs: mint/freeze on, unsellable, unlocked LP, pool too thin to exit, dumping
    ring, rugger creator.'
  date: YYYY-MM-DD (example)
  source_type: owner_ruling
  source: '[OWNER-SET] decision-log reference'
  supersedes: []
  owner: Rug Shield
```

## Changelog
- YYYY-MM-DD (example): drafted by Engineering (not adopted; needs the owner's yes).
