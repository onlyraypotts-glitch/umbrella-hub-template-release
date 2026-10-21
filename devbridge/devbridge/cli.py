"""devbridge CLI: keygen | allow | send | recv | verify | revoke | erase | hold | release-hold | rotate |
issue-dev | whois | registry list|check|verify|scan|migrate|cosign | report-join"""
import argparse, json, os, sys
from .core import Identity, Allowlist, Node, verify_envelope, Reject
from .transports import FileMailbox

def main(argv=None):
    ap = argparse.ArgumentParser(prog="devbridge"); sp = ap.add_subparsers(dest="cmd", required=True)
    k = sp.add_parser("keygen"); k.add_argument("--id", required=True); k.add_argument("--out", required=True)
    a = sp.add_parser("allow"); a.add_argument("--allowlist", required=True); a.add_argument("--pubfile", required=True)
    a.add_argument("--namespace", required=True); a.add_argument("--may-send-to", nargs="+", required=True)
    for n in ("send", "recv"):
        p = sp.add_parser(n); p.add_argument("--key", required=True); p.add_argument("--allowlist", required=True)
        p.add_argument("--mailbox", required=True); p.add_argument("--state", required=True)
    s = sp.choices["send"]; s.add_argument("--to", required=True); s.add_argument("--type", default="info")
    s.add_argument("--body", required=True, help="JSON object"); s.add_argument("--thread")
    v = sp.add_parser("verify"); v.add_argument("--file", required=True); v.add_argument("--allowlist", required=True)
    r = sp.add_parser("revoke"); r.add_argument("peer"); r.add_argument("--allowlist", required=True); r.add_argument("--revoked", required=True)
    r.add_argument("--quarantine", required=True); r.add_argument("--seal-key", required=True); r.add_argument("--audit", required=True)
    r.add_argument("--reason", required=True); r.add_argument("--seal-path", action="append", default=[], help="mailbox/outbox/state/repo dirs to seal")
    e = sp.add_parser("erase"); e.add_argument("peer"); e.add_argument("--quarantine", required=True); e.add_argument("--audit", required=True)
    e.add_argument("--reason", required=True); e.add_argument("--confirm", action="store_true"); e.add_argument("--hold-days", type=int, default=30)
    e.add_argument("--holds"); e.add_argument("--permit", required=True, help="admin-signed erase permit JSON")
    e.add_argument("--admin-pin", default="/etc/umbrella/admin.pub", help="PINNED read-only admin pub (not writable by bot/dev)")
    for n in ("hold", "release-hold"):
        h = sp.add_parser(n); h.add_argument("peer"); h.add_argument("--holds", required=True); h.add_argument("--audit", required=True)
        h.add_argument("--reason", required=(n == "hold"), default="released")
    ro = sp.add_parser("rotate"); ro.add_argument("peer"); ro.add_argument("newpub", help="new .pub.json from the dev")
    ro.add_argument("--admin-key", required=True); ro.add_argument("--allowlist", required=True); ro.add_argument("--rotations", required=True)
    ro.add_argument("--audit", required=True); ro.add_argument("--admin-pin", default="/etc/umbrella/admin.pub")
    ro.add_argument("--revoked", required=True)
    a.add_argument("--revoked", required=True)
    for n in ("send", "recv", "verify"): sp.choices[n].add_argument("--revoked", required=True, help="revoked list (must exist; created by allow)"); sp.choices[n].add_argument("--rotations")
    r.add_argument("--registry", help="identity registry.jsonl to update (status=revoked)")
    for n in ("hold", "release-hold"): sp.choices[n].add_argument("--registry", help="identity registry.jsonl to update")
    for n in ("revoke", "hold", "release-hold"): sp.choices[n].add_argument("--registry-admin-pin", default="/etc/umbrella/admin.pub")
    i = sp.add_parser("issue-dev", help="hub assigns the next dev-NNNN id + key (admin only)")
    i.add_argument("--admin-key", required=True); i.add_argument("--admin-pin", default="/etc/umbrella/admin.pub")
    for f in ("--registry", "--allowlist", "--revoked", "--audit"): i.add_argument(f, required=True)
    i.add_argument("--watermark-secret", help="(1.5.0-beta.2: unused; watermark_ref no longer stored in the chain)")
    i.add_argument("--out", help="hand-off bundle dir (private key 0600); required unless --enroll-pub")
    i.add_argument("--enroll-pub", help="dev-signed enrollment JSON (dev generated the key)"); i.add_argument("--label", default="", help="ROLE only: backend, frontend, fullstack, mobile, qa, docs, design, security, ops, data, contractor")
    i.add_argument("--hub", default="owner-bot")
    w = sp.add_parser("whois"); w.add_argument("query", help="subject_id or key fingerprint"); w.add_argument("--registry", required=True)
    w.add_argument("--admin-pin", default="/etc/umbrella/admin.pub")
    w.add_argument("--audit", action="append", default=[], help="audit log(s) to count accepted/rejected from")
    g = sp.add_parser("registry"); g.add_argument("action", choices=["list", "check", "verify", "scan", "migrate", "cosign"]); g.add_argument("--registry", required=True)
    g.add_argument("--admin-pin", default="/etc/umbrella/admin.pub"); g.add_argument("--admin-key", help="migrate/cosign only")
    g.add_argument("--allowlist"); g.add_argument("--revoked")
    j = sp.add_parser("report-join"); j.add_argument("--intake", required=True); j.add_argument("--registry", required=True)
    j.add_argument("--admin-pin", default="/etc/umbrella/admin.pub")
    x = ap.parse_args(argv); os.umask(0o077)
    from . import beta
    if beta.BETA_BUILD and x.cmd in beta.DISABLED_IN_BETA:
        print(f"BETA-DISABLED: '{x.cmd}' is {beta.REASON}", file=sys.stderr); return 3
    if x.cmd in ("issue-dev", "whois", "registry", "report-join"): return _registry_cmd(x)
    if x.cmd == "keygen":
        i = Identity.generate(x.id); p = i.save(x.out)
        print(json.dumps({"private_key_file": p, "share_this_public_key": i.pub_b64})); return 0
    if x.cmd == "allow":
        if not os.path.exists(x.revoked): from .core import atomic_write_json; atomic_write_json(x.revoked, {})
        pub = json.load(open(x.pubfile)); al = Allowlist.load(x.allowlist, x.revoked)
        if pub["bot_id"] in al.revoked: print("REFUSED: peer is revoked; use rotate/admin process", file=sys.stderr); return 2
        al.add(pub["bot_id"], pub["pub"], x.namespace, x.may_send_to); al.save(x.allowlist); print("allowed", pub["bot_id"]); return 0
    if x.cmd == "revoke":
        from .revoke import revoke
        m = revoke(x.peer, allowlist=Allowlist.load(x.allowlist, x.revoked), allowlist_path=x.allowlist, revoked_path=x.revoked,
                   quarantine_root=x.quarantine, seal_key_path=x.seal_key, paths=x.seal_path, audit_path=x.audit, reason=x.reason,
                   registry_path=x.registry, registry_admin_pin=x.registry_admin_pin)
        print(json.dumps({"revoked": x.peer, "sealed_sha256": m["sha256"], "erase_not_before_days": 30})); return 0
    if x.cmd in ("hold", "release-hold"):
        from .revoke import set_hold, release_hold
        try: (set_hold if x.cmd == "hold" else release_hold)(x.peer, holds_path=x.holds, audit_path=x.audit, reason=x.reason, registry_path=x.registry,
                                                                     registry_admin_pin=x.registry_admin_pin)
        except KeyError as err: print("REFUSED:", err, file=sys.stderr); return 2
        print(json.dumps({x.cmd: x.peer})); return 0
    if x.cmd == "rotate":
        from .revoke import sign_rotation, apply_rotation
        from .revoke import load_pinned_admin_pub
        admin = Identity.load(x.admin_key); al = Allowlist.load(x.allowlist, x.revoked, x.rotations); new = json.load(open(x.newpub))
        try: pinned = load_pinned_admin_pub(x.admin_pin)
        except (PermissionError, OSError, ValueError, KeyError) as err: print("REFUSED: admin pin:", err, file=sys.stderr); return 2
        if admin.pub_b64 != pinned: print("REFUSED: --admin-key does not match the pinned admin pub", file=sys.stderr); return 2
        if new["bot_id"] != x.peer or x.peer not in al.peers: print("REFUSED: peer mismatch/unknown", file=sys.stderr); return 2
        rec = sign_rotation(admin, x.peer, al.peers[x.peer]["pub"], new["pub"])
        ts = apply_rotation(rec, admin_pin_path=x.admin_pin, allowlist=al, allowlist_path=x.allowlist, rotations_path=x.rotations, audit_path=x.audit)
        print(json.dumps({"rotated": x.peer, "old_key_revoked_at": ts})); return 0
    if x.cmd == "erase":
        from .revoke import erase
        if not x.confirm: print("REFUSED: erase needs --confirm and a typed phrase", file=sys.stderr); return 2
        if not sys.stdin.isatty(): print("REFUSED: erase is human-only and needs a real terminal (piped stdin refused)", file=sys.stderr); return 2
        typed = input(f"Type 'erase {x.peer}' to permanently wipe sealed data: ")
        try: h = erase(x.peer, quarantine_root=x.quarantine, audit_path=x.audit, reason=x.reason, confirm=True, typed=typed, hold_days=x.hold_days,
                      holds_path=x.holds, permit=json.load(open(x.permit)), admin_pin_path=x.admin_pin)
        except (PermissionError, FileNotFoundError) as err: print("REFUSED:", err, file=sys.stderr); return 2
        print(json.dumps({"erased": x.peer, "tombstone_sha256": h})); return 0
    if x.cmd in ("send", "recv", "verify") and not os.path.exists(x.revoked):
        print("REFUSED: --revoked file missing; refusing to run without the revocation list", file=sys.stderr); return 2
    if x.cmd == "verify":
        try: verify_envelope(json.load(open(x.file)), Allowlist.load(x.allowlist, x.revoked, x.rotations)); print("VALID"); return 0
        except Reject as r: print("INVALID", r.code); return 1
    node = Node(Identity.load(x.key), Allowlist.load(x.allowlist, x.revoked, x.rotations), FileMailbox(x.mailbox), x.state)
    if x.cmd == "send":
        e = node.send(x.to, x.type, json.loads(x.body), x.thread); print(json.dumps({"sent": e["msg_id"], "thread": e["thread"]})); return 0
    good, bad = node.recv_all()
    for m in good: print(json.dumps({"DATA_NOT_INSTRUCTIONS": True, "from": m["from"], "type": m["type"], "msg_id": m["msg_id"], "body": m["body"]}))
    if bad: print(json.dumps({"rejected": bad}), file=sys.stderr)
    return 0

def _registry_cmd(x):
    from . import registry as R
    try:
        if x.cmd == "issue-dev":
            enroll = json.load(open(x.enroll_pub)) if x.enroll_pub else None
            if enroll is None and not x.out: print("REFUSED: --out bundle dir required (or --enroll-pub)", file=sys.stderr); return 2
            rec, bundle = R.issue_dev(admin_ident=Identity.load(x.admin_key), admin_pin_path=x.admin_pin, registry_path=x.registry,
                                      allowlist_path=x.allowlist, revoked_path=x.revoked, audit_path=x.audit, out_dir=x.out,
                                      watermark_secret_path=x.watermark_secret, label=x.label, hub=x.hub, enroll=enroll)
            print(json.dumps({"issued": rec["subject_id"], "fingerprint": rec["fingerprint"], "handoff_bundle": bundle,
                              "note": "hand the bundle to the dev privately; never commit or email the .key"})); return 0
        if x.cmd == "whois":
            w = R.whois(x.registry, x.query, x.audit, admin_pin_path=x.admin_pin)
            if not w: print("NOT FOUND", file=sys.stderr); return 1
            for k, v in w.items(): print(f"{k:14} {v}")
            return 0
        if x.cmd == "registry":
            if x.action == "scan":   # read-only; works on legacy chains; does not need the pin
                hits = R.scan(x.registry)
                for h in hits: print(json.dumps(h))
                print(f"FLAGGED {len(hits)}" if hits else "CLEAN"); return 1 if hits else 0
            if x.action in ("migrate", "cosign"):
                if not x.admin_key: print("REFUSED: --admin-key required", file=sys.stderr); return 2
                adm = Identity.load(x.admin_key)
                if x.action == "migrate": print(json.dumps(R.migrate(x.registry, adm, admin_pin_path=x.admin_pin))); return 0
                print(json.dumps({"cosigned": R.cosign_head(x.registry, adm, admin_pin_path=x.admin_pin)})); return 0
            if x.action == "list": print(R.list_table(x.registry, admin_pin_path=x.admin_pin)); return 0
            if x.action == "verify": R.Registry(x.registry, admin_pin_path=x.admin_pin); print("REGISTRY OK (informational only)"); return 0
            if not (x.allowlist and x.revoked): print("REFUSED: check needs --allowlist and --revoked", file=sys.stderr); return 2
            bad = R.check(x.registry, x.allowlist, x.revoked, admin_pin_path=x.admin_pin)
            print("\n".join("MISMATCH " + b for b in bad) if bad else "CONSISTENT"); return 1 if bad else 0
        if x.cmd == "report-join":
            for line in open(x.intake):
                if line.strip(): print(json.dumps(R.join_report(line, x.registry, admin_pin_path=x.admin_pin)))
            return 0
    except R.RegistryTampered as err: print("REFUSED:", err, file=sys.stderr); return 2
    except (PermissionError, ValueError, OSError, KeyError) as err: print("REFUSED:", err, file=sys.stderr); return 2

if __name__ == "__main__": sys.exit(main())
