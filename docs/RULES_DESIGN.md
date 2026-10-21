# Rules design (draft, Engineering YYYY-MM-DD (example); the owner design rulings 11:01 + HH:MM ET (example) via HQ)
Goal: the simplest setup a bot can't misread. Each bot reads exactly two files: rules/company.md first, then rules/<bot>.md.
- company.md holds EVERY company-wide rule.
- Bot files are short and cover only that bot's own job. They never repeat a company rule and refer to one by id only (e.g. SIZE-1). A bot file may make a company rule stricter (`tightens: <ID>`, `limit:`), never looser. On any conflict, company.md wins; both headers say so.
- Every entry has: id, value, date (ET), source_type (owner_ruling | team_setting | derived | pending), source (quote or file:line), supersedes (old rule + file:line), owner. Every file has a Changelog section and the header "When helping another bot with a job, also read rules/<that-bot>.md."
- Team settings are never labeled owner_ruling. Uncited items are `pending`. Health & Wellness, Money Desk and Personal Agent files hold only role and boundary rules.
- Proposed live path: <workspace>/rules/ (NOT created). CURRENT_RULES.yaml is marked SUPERSEDED and kept as history.
- Lint: `python3 rules_lint.py --rules rules` fails on: a bot file restating company text or a number; a loosened company limit; a duplicate id or value across files; a missing field, header or changelog; a stale value; untracked earlier conflicts (SIZE-1, STOP-DAY-1, RING-RIDE-SIZE-1). Negative controls: tests/fixtures/<type>/ + tests/run_negative_controls.sh (7 types; each must fail).
- Workflow: the owner rules -> HQ edits one entry + changelog -> forget the superseded memory -> lint to 0 -> post the diff to the owner.
- Archive: bots read _archive/ only for a reset or rollback (draft text: ARCHIVE_README.draft.md).
