Full version: installed from the pinned repo during setup as skill `cdp-wallet-setup`. If it's missing, run `update-from-repo`.

# CDP wallet setup (tightened)

Sets up the capped Coinbase CDP Server Wallet engine so the bot can trade autonomously from its own accounts. Do the steps in order and report after each. Nothing trades live until step 9's typed YES.

**Ground rules:** secrets only via the assistant's secure secret request (env secrets); never ask for a key in chat, email or files; never print or copy a secret, check presence and length only; a leaked secret must be deleted and recreated. CDP private keys stay in Coinbase's enclave; nobody needs a seed phrase. The bot never moves money; funding and withdrawing are the owner's job. Any failure → explain plainly, fall back to manual mode.

1. **Code:** use the clone at the pinned commit (`$BOT_REPO`, same SHA as the prompts). `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt && python -m unittest tests/test_offline.py -v` must pass. Also `python3 -m unittest discover -s desk/tests -v`, `python3 desk/desk.py init` (shared desk) and `python3 research/shadow_selftest.py` (read-only research tools).
2. **Owner creates keys** (one at a time, wait for "done"): portal.cdp.coinbase.com → new project; **bot API key** (Ed25519) with Server Wallet account + transaction permissions but **not** `policies#manage`; a separate **admin key** with `policies#manage` (used only to apply policies); **wallet secret** (copy with the copy icon, one line); free **Jupiter** key (portal.jup.ag); optional free Helius key.
3. **Secure secret requests**, exact names: `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`, `CDP_WALLET_SECRET`, `JUPITER_API_KEY`, `CDP_ADMIN_API_KEY_ID`, `CDP_ADMIN_API_KEY_SECRET`; optional `HELIUS_API_KEY`, `COINGECKO_DEMO_API_KEY`. Verify by presence/length only (`secrets_loader.load()`).
4. **Accounts:** `python create_accounts.py` → `trading-bot-evm` (Base + Ethereum) and `trading-bot-sol`, saved to `accounts.json` (gitignored). `python balances.py` shows zero. Owner confirms both public addresses in chat.
5. **Devnet policy test:** `python scripts/devnet_policy_test.py` (throwaway testnet accounts). Every line PASS: swaps to self accepted; foreign recipients, transfers, unlimited approvals and message/typed-data/hash signing rejected.
6. **Mainnet policy:** `python scripts/apply_policy.py --print`, summarize in plain words (swaps to self only, $150/tx backstop, allowlisted routers, exact approvals to the sell router only, no signing); then apply; both accounts CONFIRMED. Suggest deleting the admin key secret afterwards.
7. **Mainnet dry run:** `python scripts/dryrun_mainnet.py` — real quotes, nothing signed; baselines PASS, tampered variants REJECTED. Test `KILL_SWITCH` (create → trade refused → remove).
8. **Owner funds small amounts** they can afford to lose (e.g. ~0.2 SOL on Solana; ~$50 of ETH on **Base**). Say plainly the bot never sends money back. Re-run `balances.py` and the dry run.
9. **Go live only on a typed YES:** "Everything is tested. Start live autonomous trading with your per-position cap (max $100)? Reply YES." Then set `BOT_DRY_RUN=false` and `BOT_LIVE_ACK=I-ACCEPT-LIVE-TRADING` in the trading routine's environment, save a memory with go-live time and addresses, set desk `live_mode = cdp_bot_live_funded`, and start the autonomous loop. Anything short of YES = dry run + move cards.

**Afterwards:** "stop" → create `KILL_SWITCH`. "CDP off" → no new buys, exit or hold only. 0x Settler rotation → tell the owner the policy needs an admin update; never loosen the guard.

## Standing research clause
Always keep researching proven crypto trading results and theories (papers, backtests with costs, post-mortems, documented track records), turn each into a pre-specified testable hypothesis, and test it shadow → paper → small live before it changes any weight. Research never changes hard safety limits.
