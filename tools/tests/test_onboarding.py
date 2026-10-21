"""1.7.0-beta.1 onboarding safety tests: run with python -m pytest -q tools/tests"""
import os, re, subprocess, sys
import yaml
T=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.dirname(os.path.dirname(T))
LINT=os.path.join(ROOT,"tools","rules_lint.py"); SKILL=os.path.join(ROOT,"template-team","skills","getting-started-platforms.md")
def lint(d):
    r=subprocess.run([sys.executable,LINT,"--rules",d],capture_output=True,text=True); return r.returncode,r.stdout
def company():
    t=open(os.path.join(ROOT,"rules","company.md")).read()
    return {e["id"]:e for e in yaml.safe_load(re.search(r"```yaml\n(.*?)```",t,re.S).group(1))["rules"]}
REF="https://fomo.family/?r=Raypotts"
DISC="Disclosure: This is a referral link from Umbrella\'s founder. If you sign up through it, the founder may earn rewards from FOMO. Using it is optional. You can also sign up directly at fomo.family without a referral."
DIRECT="https://fomo.family/"
skill=lambda: open(SKILL).read()

def test_real_rules_lint_clean():
    rc,o=lint(os.path.join(ROOT,"rules")); assert rc==0, o
def test_no_password_in_chat():
    assert company()["ONBOARD-CREDS-1"]["secrets_in_chat"]=="never"
    rc,o=lint(os.path.join(T,"fixtures","onboard_password_in_chat")); assert rc==1 and "ONBOARD-UNSAFE secret-in-chat" in o
    s=skill().lower(); assert "never ask for, accept or store a password, seed phrase, private key" in s and "never log out" in s
def test_read_only_default():
    e=company()["ONBOARD-READONLY-1"]; assert e["default_mode"]=="read_only" and e["auto_trade_default"]=="off" and e["limits_set_by"]=="user"
    rc,o=lint(os.path.join(T,"fixtures","onboard_not_readonly")); assert rc==1 and "ONBOARD-UNSAFE default_mode" in o
    assert "READ-ONLY by default" in skill() and "No auto-trading" in skill()
def test_leaderboard_opt_in_default_off():
    e=company()["ONBOARD-LEADERBOARD-1"]; assert e["leaderboard_default"]=="off" and e["opt_in"] is True and e["revocable"] is True
    rc,o=lint(os.path.join(T,"fixtures","onboard_leaderboard_on")); assert rc==1 and "ONBOARD-UNSAFE leaderboard_default" in o
    assert "leaderboard is OFF" in skill() and "stop sharing" in skill()
def test_per_user_isolation():
    assert company()["ONBOARD-ISOLATION-1"]["cross_user_read"]=="never"
    rc,o=lint(os.path.join(T,"fixtures","onboard_cross_user")); assert rc==1 and "ONBOARD-UNSAFE cross_user_read" in o
    assert "per-user store" in skill() and "Never read, copy or report another user's data" in skill()
def test_missing_onboard_rule_flagged():
    rc,o=lint(os.path.join(T,"fixtures","stale")); assert "ONBOARD-MISSING ONBOARD-CREDS-1" in o
def test_no_owner_personal_data_or_secrets():
    for p in [SKILL,os.path.join(ROOT,"rules","company.md")]:
        s=open(p).read().replace(REF,""); assert not any(n in s for n in os.environ.get("UMBRELLA_OWNER_NAMES","Alex Example").split(",")); assert not re.search(r"gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN",s)

HQ=os.path.join(ROOT,"template-team","skills","getting-started-hq.md")
hq=lambda: open(HQ).read()
def test_hq_create_only_with_yes():
    s=hq(); assert "Create it ONLY after this user's explicit YES for that bot" in s and "No yes = not created" in s and "generic role profile" in s
def test_hq_locks_kept():
    s=hq(); assert "Money, signing, trading, keys and payments" in s and "unless the owner typed YES" in s
    assert "never ask for, accept or store a password, seed phrase, private key" in s.lower() and "Never take secrets in chat" in s
def test_hq_leaderboard_opt_in_off():
    s=hq(); assert "leaderboard is OFF unless the user types YES" in s and "stop sharing" in s and "READ-ONLY by default" in s and "getting-started-platforms" in s
DENY=[n.strip() for n in os.environ.get("UMBRELLA_DENY_TERMS","").split(",") if n.strip()]
def test_hq_no_owner_names_or_personal():
    s=hq().replace(REF,""); names=[n for n in os.environ.get("UMBRELLA_OWNER_NAMES","Alex Example").split(",") if n.strip()]
    assert not any(n.lower() in s.lower() for n in names+DENY); assert not re.search(r"gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN",s)
    assert len(s.encode())<=6000

def test_fomo_referral_disclosed_before_link():
    for p in [SKILL,HQ]:
        s=open(p).read(); L=s.splitlines(); assert s.count(REF)==1 and s.count(DISC)==1, p
        r=[i for i,l in enumerate(L) if REF in l][0]; d=[i for i,l in enumerate(L) if DISC in l][0]
        assert d==r-1 and s.index(DISC)<s.index(REF), p
        assert any(l.strip().endswith(DIRECT) and REF not in l for l in L), p
        assert "[LAWYER CHECK] before public release: confirm FOMO's terms allow referral links in a public template; tax reporting of the rewards (tax/bookkeeping role)." in s
        assert "pending legal" not in s.lower() and not re.search(r"tooltip|expander|footer",L[d]+L[r],re.I)
        assert not re.search(r"\b(free|bonus|no fees?|discount)\b",(L[d]+L[r]).lower()), p
