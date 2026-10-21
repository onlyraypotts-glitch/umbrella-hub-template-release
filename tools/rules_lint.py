#!/usr/bin/env python3
"""rules_lint.py - READ-ONLY. Flags superseded rule text and backup/superseded files in bot read paths.
Ignores _archive/ and lines marked superseded/historical. Exit 1 if hits."""
import re, json, glob, os, sys
STALE={
 "SIZE-1 fixed $ size": r"\$\d+\s*[-–]\s*\$?\d+\s*(team cash|at most|per trade|a trade|at a time)|\$\d+\s*(per trade|at a time|/\s*position)|\$\d+-\d+ at most|up to about \d+% of team cash|:\s*\$\d+\s*[-–]\s*\$?\d+\.?\s*$|\$1[05]-\$?(1[25]|20)\b",
 "SIZE-1 old % caps": r"(max|default)[^.]{0,20}10% per position|40% total|25%[- ]of[- ](the )?balance",
 "GATE-CLEAR-1 approves every trade": r"(\w+ )?approves? every trade",
 "STOP-DAY-1 old -20% day": r"-20% (daily|day|equity)|daily stop[^.]{0,20}-?20%",
 "LIQ-1 fixed liquidity floor": r"\$?\d{2,3}\s?[kK]\b[^.\n]{0,40}(liquidity|liq\b|pool)|(liquidity|liq\b|pool)[^.\n]{0,40}(>=?|at least|min(imum)?|floor|over|above)\s*\$?\d{2,3}\s?[kK]\b|(liquidity|pool)[^.\n]{0,30}\$\d{2,3},000",
 "SIZE-1 fixed per-trade $": r"\$\d+(\.\d+)?\s*(per|each|every)\s*(trade|entry)|(per|each)[- ]trade[^.\n]{0,15}\$\d+",
 "STATE in rule text": r"(currently|is|already) tripped|so paper only|\(paper only\)|already tripped \(paper|\[OWNER-SET\] deposited \(|Live FOMO cash: ~",
}
DEFAULTS={"roots":["protocols/**/*","playbooks/**/*","sources/**/*","brain/*.md","loop/**/*","routines/*.md","routines/**/*.txt"],
          "archive":"_archive/","profiles":"agents/*/profile.json","automations":"agents/*/automations/**/*"}
def _cfg():
    c=dict(DEFAULTS); cp=os.environ.get("RULES_LINT_CONFIG",os.path.join(os.path.dirname(os.path.abspath(__file__)),"rules_lint.config.json"))
    if os.path.exists(cp): c.update(json.load(open(cp)))
    if os.environ.get("RULES_LINT_ROOTS"): c["roots"]=[g for g in os.environ["RULES_LINT_ROOTS"].split(os.pathsep) if g]
    for k,e in (("archive","RULES_LINT_ARCHIVE"),("profiles","RULES_LINT_PROFILES"),("automations","RULES_LINT_AUTOMATIONS")):
        if os.environ.get(e): c[k]=os.environ[e]
    return c
CFG=_cfg(); ROOTS=CFG["roots"]; ARCHIVE=CFG["archive"]
BACKUP=re.compile(r"(\.bak|-old\b|_old\b|/backups?/|backup-\d{4}|\.orig$)",re.I)
TEXT=(".md",".txt",".yaml",".yml",".py",".sh","SKILL.md")

# ---- rules/ mode (added in 1.6.0-beta.1): python3 rules_lint.py --rules DIR ----
def lint_rules(d):
    import yaml
    REQ=["id","value","date","source_type","source","supersedes","owner"]
    ST={"owner_ruling","team_setting","derived","pending"}
    H1="company.md wins"; H2="When helping another bot with a job, also read rules/<that-bot>.md."
    out=[]
    def load(p):
        t=open(p).read(); m=re.search(r"```yaml\n(.*?)```",t,re.S)
        return t,(yaml.safe_load(m.group(1)) or {}).get("rules",[]) if m else []
    cp=os.path.join(d,"company.md")
    if not os.path.exists(cp): return [f"{d}: [MISSING company.md]"]
    ct,comp=load(cp); cids={e.get("id") for e in comp}
    nums=lambda v: set(re.findall(r"[-+]?\$?\d+(?:\.\d+)?%?",str(v)))
    cnums=set().union(*[nums(e.get("value","")) for e in comp]) if comp else set()
    cnums={n for n in cnums if re.search(r"[$%]",n) or len(n.strip("-+"))>=3}
    climit={e["id"]:e["limit"] for e in comp if "limit" in e}
    seen_id={}; seen_val={}
    files=sorted(f for f in os.listdir(d) if f.endswith(".md"))
    for f in files:
        p=os.path.join(d,f); t,es=load(p); bot=f!="company.md"
        if H2 not in t: out.append(f"{p}: [MISSING-HEADER helper line]")
        if "## Changelog" not in t: out.append(f"{p}: [MISSING-FIELD changelog section]")
        if bot and H1 not in t: out.append(f"{p}: [MISSING-HEADER company.md wins]")
        if not es: out.append(f"{p}: [MISSING-FIELD no rules block]")
        for e in es:
            rid=e.get("id","?")
            for k in REQ:
                if k not in e or e[k] in (None,""): out.append(f"{p}: {rid} [MISSING-FIELD {k}]")
            if e.get("source_type") not in ST: out.append(f"{p}: {rid} [BAD source_type {e.get('source_type')}]")
            v=str(e.get("value",""))
            for rn,pat in STALE.items():
                if re.search(pat,v,re.I) and e.get("source_type")!="pending": out.append(f"{p}: {rid} [STALE {rn}] {v[:80]}")
            if not bot: continue
            if rid in cids: out.append(f"{p}: {rid} [RESTATES company id]")
            for c in comp:
                if len(v)>20 and (v==c.get("value") or c.get("value","")[:40] in v): out.append(f"{p}: {rid} [RESTATES company text of {c['id']}]")
            dup=nums(v)&cnums
            if dup: out.append(f"{p}: {rid} [RESTATES company number {sorted(dup)} - reference the id]")
            tid=e.get("tightens")
            if tid and "limit" in e and tid in climit:
                cl,bl=climit[tid],e["limit"]
                if (cl<0 and bl<cl) or (cl>=0 and bl>cl): out.append(f"{p}: {rid} [LOOSENS {tid}: {bl} vs company {cl}]")
            if rid in seen_id: out.append(f"{p}: {rid} [DUP-ID also in {seen_id[rid]}]")
            seen_id[rid]=f
            if v in seen_val: out.append(f"{p}: {rid} [DUP-VALUE also in {seen_val[v]}]")
            seen_val[v]=f
    # ---- onboarding safety (added in 1.7.0-beta.1) ----
    SAFE={"secrets_in_chat":"never","logout":"never","default_mode":"read_only","auto_trade_default":"off",
          "limits_set_by":"user","leaderboard_default":"off","opt_in":True,"revocable":True,"cross_user_read":"never"}
    NEED={"ONBOARD-CREDS-1":["secrets_in_chat","logout"],"ONBOARD-READONLY-1":["default_mode","auto_trade_default","limits_set_by"],
          "ONBOARD-LEADERBOARD-1":["leaderboard_default","opt_in","revocable"],"ONBOARD-ISOLATION-1":["cross_user_read"]}
    ASK=re.compile(r"\b(ask|paste|send|type|share|give|enter|provide|collect|request)\w*\b[^.\n]{0,40}\b(password|passphrase|seed phrase|private key|recovery phrase|2fa code)",re.I)
    NEG=re.compile(r"\b(never|not|no|don't|do not|refuse)\b",re.I)
    for f in files:
        p=os.path.join(d,f); _,es=load(p)
        for e in es:
            rid=e.get("id","?"); v=str(e.get("value",""))
            for k,want in SAFE.items():
                if k in e and e[k]!=want: out.append(f"{p}: {rid} [ONBOARD-UNSAFE {k}={e[k]!r} want {want!r}]")
            if ASK.search(v) and not NEG.search(v[:ASK.search(v).start()+1] or ""): out.append(f"{p}: {rid} [ONBOARD-UNSAFE secret-in-chat] {v[:80]}")
    for rid,keys in NEED.items():
        e=next((x for x in comp if x.get("id")==rid),None)
        if e is None: out.append(f"{cp}: [ONBOARD-MISSING {rid}]"); continue
        for k in keys:
            if k not in e: out.append(f"{cp}: {rid} [ONBOARD-MISSING {k}]")
    # earlier-run conflicts must be resolved or marked pending in company.md
    for need in ["SIZE-1","STOP-DAY-1","RING-RIDE-SIZE-1"]:
        if need not in cids: out.append(f"{cp}: [CONFLICT-UNTRACKED {need}]")
    return out
if "--rules" in sys.argv:
    d=sys.argv[sys.argv.index("--rules")+1]; r=lint_rules(d)
    print("\n".join(r)); print(f"\nSUMMARY rules_dir={d} files={len([f for f in os.listdir(d) if f.endswith('.md')])} rule_hits={len(r)}")
    sys.exit(1 if r else 0)

hits=[];files=[]
def scan(name,text):
    for i,l in enumerate(text.splitlines(),1):
        if re.search(r"supersed|historical|tightened from|change log|replaced|replaces|no fixed|\bnot\b.{0,15}fixed",l,re.I): continue
        for rid,p in STALE.items():
            if re.search(p,l,re.I): hits.append(f"{name}:{i}: [{rid}] {l.strip()[:150]}")
seen=set()
for g in ROOTS:
    for f in glob.glob(g,recursive=True):
        if f in seen or not os.path.isfile(f) or f.startswith(ARCHIVE) : continue
        seen.add(f)
        if BACKUP.search(f): files.append(f"{f}: [READ-PATH BACKUP] move to {ARCHIVE}"); continue
        if "/drafts/" in f or "/gates/tests/" in f or not f.endswith(TEXT): continue
        scan(f,open(f,errors="ignore").read())
for f in sorted(glob.glob(CFG["profiles"])):
    d=json.load(open(f)); desc=d.get("description","") or ""
    scan(f"{f} [{d.get('name')}] description(sentence#)",re.sub(r"(?<=[.;])\s+","\n",desc))
for f in glob.glob(CFG["automations"],recursive=True):
    if os.path.isfile(f): scan(f,open(f,errors="ignore").read())
print("\n".join(hits)); print("\n".join(files))
print(f"\nSUMMARY content_hits={len(hits)} backup_files_in_read_paths={len(files)} files_scanned={len(seen)}")
sys.exit(1 if hits or files else 0)
