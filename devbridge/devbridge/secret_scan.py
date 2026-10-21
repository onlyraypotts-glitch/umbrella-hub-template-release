"""Read-only secret scanner: regex + Shannon entropy. Never prints values."""
import math, os, re, sys, json
PATTERNS = {
 "aws_key": r"AKIA[0-9A-Z]{16}",
 "private_key_block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
 "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}",
 "slack_token": r"xox[abpr]-[A-Za-z0-9-]{10,}",
 "openai_like": r"sk-[A-Za-z0-9_-]{20,}",
 "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
 "hex64_private_key": r"(?i)(priv(ate)?[_ -]?key|secret|seed)\W{0,5}(0x)?[0-9a-f]{64}\b",
 "hex64_candidate": r"(?i)(?<![0-9a-f])(0x)?[0-9a-f]{64}(?![0-9a-f])",  # also matches sha256 hashes; triage needed
 "base58_private_key": r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{87,88}(?![1-9A-HJ-NP-Za-km-z])|\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b",
 "discord_webhook": r"https://(ptb\.|canary\.)?discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
 "google_oauth_access": r"ya29\.[A-Za-z0-9_-]{20,}",
 "google_oauth_refresh": r"(?<![A-Za-z0-9])1//[A-Za-z0-9_-]{20,}",
 "assign_secret": r"(?i)(api[_-]?key|secret|token|passw(or)?d)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+]{12,}",
}
TEXT_EXT = {".md",".json",".txt",".py",".html",".js",".yml",".yaml",".tpl",".env",".toml",".cfg",".ini",".pdf",""}
TOK = re.compile(r"[A-Za-z0-9_\-+/=]{32,}")
import hashlib as _hl, os as _os
BIP39_FILE=_os.path.join(_os.path.dirname(__file__),"bip39_english.txt")
BIP39_SHA256="2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
BIP39=open(BIP39_FILE).read().split() if _os.path.exists(BIP39_FILE) else []
BIP39_IDX={w:i for i,w in enumerate(BIP39)}
SEED_SIZES=(24,21,18,15,12)
def bip39_checksum_ok(words):
    n=len(words); bits="".join(format(BIP39_IDX[w],"011b") for w in words)
    cs=n//3; ent=bits[:-cs]; data=int(ent,2).to_bytes(len(ent)//8,"big")
    return format(_hl.sha256(data).digest()[0],"08b")[:cs]==bits[-cs:]
def seed_phrases(line):
    """Runs of consecutive whitespace-separated tokens that are ALL BIP39 words (surrounding quotes/punctuation stripped).
    Returns [(n_words, checksum_valid)] for each run of >=12 words. The largest valid size is reported per run."""
    toks=[t.strip("\"'`,;:.()[]{}").lower() for t in line.split()]
    out=[]; run=[]
    for t in toks+[None]:
        if t is not None and t in BIP39_IDX: run.append(t); continue
        if len(run)>=12:
            best=None
            for n in SEED_SIZES:
                if n<=len(run):
                    wins=[run[i:i+n] for i in range(len(run)-n+1)]
                    ok=any(bip39_checksum_ok(w) for w in wins)
                    if best is None or (ok and not best[1]): best=(n,ok)
                    if ok: break
            out.append(best)
        run=[]
    return out
def seed_phrase(line): return bool(seed_phrases(line))
def entropy(s):
    if not s: return 0.0
    return -sum((s.count(c)/len(s))*math.log2(s.count(c)/len(s)) for c in set(s))
def scan_text(text, path="<mem>", ent_thresh=4.5):
    out=[]
    for i,line in enumerate(text.splitlines(),1):
        for name,p in PATTERNS.items():
            if re.search(p,line): out.append({"file":path,"line":i,"rule":name,"value":"REDACTED"})
        for n,ok in seed_phrases(line): out.append({"file":path,"line":i,"rule":"seed_phrase","words":n,"checksum_valid":ok,"value":"REDACTED"})
        for t in TOK.findall(line):
            if entropy(t)>=ent_thresh and not re.fullmatch(r"[A-Za-z]+",t):
                out.append({"file":path,"line":i,"rule":"high_entropy","value":"REDACTED","len":len(t)})
    return out
def iter_files(roots, max_bytes=2_000_000):
    for r in roots:
        if os.path.isfile(r): yield r; continue
        for d,dirs,fs in os.walk(r):
            dirs[:]=[x for x in dirs if x not in {".git","__pycache__","node_modules",".venv"}]
            for f in fs:
                p=os.path.join(d,f)
                if os.path.splitext(f)[1].lower() in TEXT_EXT and (f.lower().endswith(".pdf") or os.path.getsize(p)<=max_bytes): yield p
def pdf_text(p):
    import subprocess
    r=subprocess.run(["pdftotext","-layout",p,"-"],capture_output=True,timeout=120)
    return r.stdout.decode("utf-8","ignore")
def read_any(p):
    if p.lower().endswith(".pdf"): return pdf_text(p)
    return open(p,encoding="utf-8",errors="ignore").read()
def scan_paths(roots, fn=scan_text):
    res=[]
    for p in iter_files(roots):
        try: txt=read_any(p)
        except OSError: continue
        res+=fn(txt,p)
    return res
if __name__=="__main__":
    r=scan_paths(sys.argv[1:]); print(json.dumps(r,indent=1)); print(f"# findings: {len(r)}",file=sys.stderr)
