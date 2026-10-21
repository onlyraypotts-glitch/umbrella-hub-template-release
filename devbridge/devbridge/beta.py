"""Beta build flags. The security reviewer's re-review (2026-10-20): GO-WITH-FIXES for beta ONLY with erase and rotate DISABLED
and separate OS users per dev. Flip these only after Security reviewer GO + the owner's typed yes."""
BETA_BUILD = True
DISABLED_IN_BETA = {"erase", "rotate"}
REASON = ("disabled in the beta build per the security reviewer's security/QA re-review (GO-WITH-FIXES only with erase+rotate "
          "disabled). See README 'BETA-DISABLED'. Revoke, seal and hold remain available.")
