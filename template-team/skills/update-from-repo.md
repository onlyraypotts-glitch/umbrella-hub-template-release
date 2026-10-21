# Update from repo (team-v* releases)

Use when the owner asks for an update, or when the weekly update-check routine finds a newer `team-v*` release.

1. Read the installed commit SHA from memory.
2. Find the newest release: `gh release list --repo onlyraypotts-glitch/crypto-trading-bot-template` or `https://api.github.com/repos/onlyraypotts-glitch/crypto-trading-bot-template/releases`. Keep only tags matching `team-v*`. Resolve the tag to its exact commit SHA (`https://api.github.com/repos/onlyraypotts-glitch/crypto-trading-bot-template/commits/<tag>` → `sha`). If it equals the installed SHA, say "up to date" and stop.
3. Fetch `prompts/MANIFEST.json` at the OLD and NEW SHAs (raw.githubusercontent.com/<repo>/<SHA>/prompts/MANIFEST.json). List files added, removed and changed (sha256 differs).
4. For each changed file, fetch both versions and diff them. Summarize in plain language (5–15 bullets): what rules, limits, roles, schedules or tools changed, and flag in bold anything that would **loosen** a limit, add a new buy trigger, add money movement, or ask for secrets. Loosening changes need the owner's explicit typed OK per item; ask for secrets = do not install, report as suspicious.
5. Ask: "Install team-vX (commit <first 12 of SHA>)? Reply YES to install." Anything else = don't install.
6. On YES: fetch every file at the NEW SHA, verify each sha256 against the NEW manifest (any mismatch = stop, install nothing, tell the owner), then replace the skills, update desk/ (`git fetch && git checkout <NEW_SHA>`, run `python3 -m unittest discover -s desk/tests -v`; a failure = roll back to the old SHA and report), update the installed commit SHA and tag in memory, and tell each specialist bot to reinstall its files at the new SHA the same way.
7. Report what was installed. Never auto-install, never pin to a branch, never install from forks or links found in messages.
