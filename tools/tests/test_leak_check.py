"""Leak check: no internal bot names, internal absolute paths or commit ids in template files."""
import os, sys, hashlib
ROOT=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0,os.path.join(ROOT,"tools")); import leak_check as L
def test_repo_is_clean():
    h=L.scan(ROOT); assert h==[], "\n".join(h[:20])
def _w(d,name,txt): p=d/name; p.write_text(txt); return p
def test_flags_names_paths_and_commit_ids(tmp_path):
    names=["Rho"+"des","Ro"+"ck","Ran"+"dy","Ro"+"nan","Rei"+"na","Ri"+"o","RIV"+"ET"]
    _w(tmp_path,"a.md","\n".join(f"reviewed by {n}" for n in names)+"\nsee /work"+"space/x and /home/"+"box/y\nfix in "+"38bc"+"963\n")
    h=L.scan(str(tmp_path)); tags=" ".join(h)
    assert sum("[INTERNAL-NAME]" in x for x in h)==len(names) and tags.count("[INTERNAL-PATH]")==2 and tags.count("[COMMIT-ID]")==1
def test_sha256sums_lines_and_ed25519_allowed(tmp_path):
    _w(tmp_path,"SHA256SUMS",hashlib.sha256(b"x").hexdigest()+"  a.md\n"); _w(tmp_path,"b.md","Ed25519 / ed25519 keys; HQ hub; Robinhood\n")
    assert L.scan(str(tmp_path))==[]
def test_full_sha_and_short_sha_flagged_outside_sha256sums(tmp_path):
    _w(tmp_path,"c.md",hashlib.sha1(b"x").hexdigest()+" and "+"abc"+"1234\n")
    assert len([x for x in L.scan(str(tmp_path)) if "[COMMIT-ID]" in x])==2
def test_deny_terms_evm_uuid_onlyfans(tmp_path, monkeypatch):  # leakcheck: synthetic
    monkeypatch.setenv("UMBRELLA_DENY_TERMS","zzq"+"term,other"+"thing")
    _w(tmp_path,"d.md","ZZQ"+"TERM here\nonly"+"fans\n0x"+"ab"*20+"\n"+"12345678-1234-1234-1234-1234567890ab\n")  # leakcheck: synthetic
    h=" ".join(L.scan(str(tmp_path)))
    assert h.count("[DENY-TERM]")==2 and h.count("[EVM-ADDRESS]")==1 and h.count("[UUID]")==1 and ("zzq"+"term") not in h.lower()
