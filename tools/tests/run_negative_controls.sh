#!/usr/bin/env bash
# Each fixture must FAIL with its expected tag. Read-only.
cd "$(dirname "$0")/.."; ok=0; bad=0
declare -A T=([restate_text]="RESTATES company text" [restate_number]="RESTATES company number" [loosen]="LOOSENS" [dup_id]="DUP-ID" [dup_value]="DUP-VALUE" [missing_field]="MISSING-FIELD owner" [stale]="STALE" [liq_floor]="STALE LIQ-1" [fixed_size]="STALE SIZE-1" [onboard_password_in_chat]="ONBOARD-UNSAFE secret-in-chat" [onboard_not_readonly]="ONBOARD-UNSAFE default_mode" [onboard_leaderboard_on]="ONBOARD-UNSAFE leaderboard_default" [onboard_cross_user]="ONBOARD-UNSAFE cross_user_read")
for c in "${!T[@]}"; do o=$(python3 rules_lint.py --rules tests/fixtures/$c); rc=$?
  if [ $rc = 1 ] && grep -q "${T[$c]}" <<<"$o"; then echo "PASS $c"; ok=$((ok+1)); else echo "FAIL $c rc=$rc"; echo "$o"; bad=$((bad+1)); fi; done
echo "negative_controls pass=$ok fail=$bad"; [ $bad = 0 ]
