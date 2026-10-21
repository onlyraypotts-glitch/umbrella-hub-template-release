# Getting started: connect your trading platforms (startup onboarding, every user)

Rules: rules/company.md ONBOARD-PLATFORMS-1, ONBOARD-CREDS-1, ONBOARD-READONLY-1, ONBOARD-ALERTS-1, ONBOARD-LOG-1, ONBOARD-LEADERBOARD-1, ONBOARD-ISOLATION-1. company.md wins.

Say first: "I will never ask for, accept or store a password, seed phrase, private key or 2FA code in chat. You sign in yourself, in my computer's browser. If you paste one here, I won't use it; please change it right away."

## 1. Ask (one question, wait for the answer, save it as this user's memory)
"Which trading platforms do you use? For example FOMO, Phantom, Axiom, GMGN, Robinhood, or any other platform with a web sign-in."

## 2. For each platform the user names, one at a time
1. Open that platform's official web sign-in page in this user's OWN bot computer browser (the user's own desktop, never another user's). Check the address is the official domain before showing it.
2. Tell the user: "The sign-in page is open on my computer. Open my desktop and sign in yourself. Tell me 'done' when you're in."
3. Wait. Do not type credentials, do not read the password field, do not take screenshots of codes. Wallet extensions: the user creates or imports the wallet themselves; the bot never sees the seed phrase.
4. When the user says done, confirm you can see the signed-in page (read-only look). Never log out, and never clear that browser's sessions.
5. FOMO sign-up (only if the user has no FOMO account): show both choices as equals, same size, preselect neither, and make no claim about cost, bonus or fees. Show the disclosure in plain text, never in a tooltip, expander or footer.
   - Direct sign-up: https://fomo.family/
   - Disclosure: This is a referral link from Umbrella's founder. If you sign up through it, the founder may earn rewards from FOMO. Using it is optional. You can also sign up directly at fomo.family without a referral.
   - Referral sign-up: https://fomo.family/?r=Raypotts
   - [LAWYER CHECK] before public release: confirm FOMO's terms allow referral links in a public template; tax reporting of the rewards (tax/bookkeeping role).
6. Platform has no web access: say so and skip it; offer move cards for it instead.

## 3. Set up the standard desk for this user
- Mode: READ-ONLY by default. No orders, swaps, approvals, deposits, withdrawals or transfers. No auto-trading.
- Position alerts on every position the user holds on a connected platform.
- Rug Shield check before any trade idea is shown.
- Trade log: write every trade and trade idea only to this user's per-user store (`$USER_STORE/trades/`), never to a shared or another user's store.
- Leaderboard: sharing to the Umbrella leaderboard is OFF. Ask only once: "Want to share your trades on the Umbrella leaderboard? It's off unless you type YES, and you can turn it off any time by saying 'stop sharing'."
- Trading rules: trades happen only under the user's own typed approval rules. Ask the user to set their daily stop and position limits; suggest conservative defaults and only allow them to be made stricter until the user types a change.

## 4. Isolation
Every memory, rule, alert and log entry for this user lives in this user's store only. Never read, copy or report another user's data, and never mention another user's positions.

## 5. Close
"You're set up read-only. Nothing trades until you type your own approval rules and a YES. Say 'stop' any time."
