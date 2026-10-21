#!/usr/bin/env python3
"""leak_check.py - READ-ONLY. Fails (exit 1) if template files contain internal bot names,
internal absolute paths (/workspace/..., /home/box/...), 7-40 char hex commit ids, EVM addresses,
full UUIDs, 'onlyfans', or any term in env UMBRELLA_DENY_TERMS (comma-separated; matched case-insensitively, never printed).
Allowed: SHA256SUMS hash lines; 'ed25519'; lines marked 'leakcheck: synthetic' (test data);
pinned public release SHAs listed in tools/leak_check_allow.txt.
Usage: python3 tools/leak_check.py [ROOT]   (default: repo root)"""
import os, re, sys
NAMES = ["Rhodes","Rock","Randy","Ronan","Reina","Rio","RIVET","Rivet","RELAY","RAMPART","RIGOR","RIGHTS","Alfred","Reid",
         "Robin","Ranger","Remy","RENOVA","Renova","REVERIE","Reverie","Rex","RHEA","Rhea","Rhett","Riven","Rowan","Ruby"]
NAME_RE = re.compile(r"\b(" + "|".join(NAMES) + r")\b|\b(" + "|".join(n.upper() for n in NAMES) + r")-\d|rules/(" + "|".join(n.lower() for n in NAMES) + r")\.md|test_rock_")
PATH_RE = re.compile(r"/workspace\b|/home/box\b")
EVM_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
def deny_re():
    terms = ["onlyfans"] + [x.strip() for x in os.environ.get("UMBRELLA_DENY_TERMS", "").split(",") if x.strip()]
    return re.compile("|".join(re.escape(x) for x in terms), re.I)
HEX_RE = re.compile(r"\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*[0-9])[0-9a-f]{7,40}\b")
SHA_LINE = re.compile(r"^[0-9a-f]{64}  \S")
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}
SKIP_FILES = {"bip39_english.txt", "leak_check.py"}
def scan(root):
    allow = set()
    ap = os.path.join(root, "tools", "leak_check_allow.txt")
    if os.path.exists(ap):
        allow = {l.split("#")[0].strip() for l in open(ap) if l.split("#")[0].strip()}
    hits = []; DENY = deny_re()
    for d, ds, fs in os.walk(root):
        ds[:] = [x for x in ds if x not in SKIP_DIRS]
        for f in fs:
            if f in SKIP_FILES or f.endswith((".pyc", ".png", ".jpg")): continue
            p = os.path.join(d, f); rel = os.path.relpath(p, root)
            try: lines = open(p, encoding="utf-8").read().splitlines()
            except (UnicodeDecodeError, OSError): continue
            for i, l in enumerate(lines, 1):
                if f == "SHA256SUMS" and SHA_LINE.match(l): continue
                for m in NAME_RE.finditer(l): hits.append(f"{rel}:{i}: [INTERNAL-NAME] {m.group(0)}")
                for m in PATH_RE.finditer(l): hits.append(f"{rel}:{i}: [INTERNAL-PATH] {m.group(0)}")
                if "leakcheck: synthetic" in l: continue
                for m in DENY.finditer(l): hits.append(f"{rel}:{i}: [DENY-TERM] (term #{len(m.group(0))}ch)")
                for m in EVM_RE.finditer(l): hits.append(f"{rel}:{i}: [EVM-ADDRESS] {m.group(0)[:6]}...")
                for m in UUID_RE.finditer(l): hits.append(f"{rel}:{i}: [UUID] {m.group(0)[:8]}...")
                for m in HEX_RE.finditer(l):
                    h = m.group(0)
                    if h == "ed25519" or h in allow: continue
                    hits.append(f"{rel}:{i}: [COMMIT-ID] {h}")
    return hits
if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    h = scan(root); print("\n".join(h)); print(f"\nSUMMARY leak_hits={len(h)} root={root}")
    sys.exit(1 if h else 0)
