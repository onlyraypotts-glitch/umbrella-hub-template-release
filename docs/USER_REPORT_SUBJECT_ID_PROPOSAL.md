# Proposal: optional `subject_id` in Chief of Staff's user-report intake (Engineering, 2026-10-20). Status: PROPOSAL, not applied
Source format: the user-report intake proposal (kept outside this template).

## Change
Add one optional field to each intake.jsonl line: `subject_id` (e.g. `dev-0001`; later `usr-NNNN`). Missing = UNKNOWN, never guessed.
report.py would gain `--dev-id dev-0001` (maps to `subject_id`). The id is not personal data; never add names next to it.

## Join
`devbridge report-join --intake intake.jsonl --registry registry.jsonl` prints each report plus
`"subject": {"subject_id","status","display_label"}` (or null). Adapter: `devbridge.registry.join_report`.
Example (synthetic): `{"id":"r-1","type":"bug","severity":"S3","summary":"synthetic report","status":"new","subject_id":"dev-0001"}`
-> `... "subject": {"subject_id": "dev-0001", "status": "active", "display_label": "synthetic QA role"}`.
Tested: tests/test_registry.py::test_report_line_joins_subject.

## Needs
Chief of Staff/HQ to accept the field; any change to report.py or role cards follows the normal approvals (the owner's yes for bot changes).
