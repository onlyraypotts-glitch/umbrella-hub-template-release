"""Personal-data scanner for templates. Outputs file:line:category, value REDACTED."""
import re, sys, json
from .secret_scan import iter_files
RULES = {
 "owner_name": r"(?!x)x",   # set via set_owner_names() / DEVBRIDGE_OWNER_NAMES; no default real name
 "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
 "phone": r"(?<!\d)(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)",
 "evm_wallet": r"\b0x[a-fA-F0-9]{40}\b",
 "sol_wallet_like": r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{32,44}(?![A-Za-z0-9])",
 "handle": r"(?<![\w@.])@[A-Za-z0-9_]{3,15}\b",
}
import os
OWNER_NAMES = []
def set_owner_names(names):
    """Configure the owner's name(s) for redaction/scan. Empty list = rule matches nothing."""
    global OWNER_NAMES
    OWNER_NAMES = [n.strip() for n in names if n and n.strip()]
    alts = [r"\s*".join(map(re.escape, n.split())) for n in OWNER_NAMES] + [re.escape(n.replace(" ", "")) for n in OWNER_NAMES if " " in n]
    RULES["owner_name"] = r"(?i)\b(?:" + "|".join(alts) + r")\b" if alts else r"(?!x)x"
set_owner_names(os.environ.get("DEVBRIDGE_OWNER_NAMES", "").split(","))
def scan_text(text, path="<mem>"):
    out=[]
    for i,line in enumerate(text.splitlines(),1):
        for k,p in RULES.items():
            n=len(re.findall(p,line))
            if k=="sol_wallet_like":  # require a digit and mixed case to cut false positives
                n=sum(1 for m in re.findall(p,line) if re.search(r"\d",m) and re.search(r"[a-z]",m) and re.search(r"[A-Z]",m))
            if n: out.append({"file":path,"line":i,"category":k,"count":n,"value":"REDACTED"})
    return out
if __name__=="__main__":
    from .secret_scan import scan_paths
    r=scan_paths(sys.argv[1:],scan_text); print(json.dumps(r,indent=1)); print(f"# findings: {len(r)}",file=sys.stderr)
