"""Loopback demo: owner-bot + dev-a-bot + dev-b-bot over the local file mailbox. Synthetic keys in a temp dir."""
import copy, json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from devbridge.core import Identity, Allowlist, Node, Reject
from devbridge.transports import FileMailbox

def run(root=None):
    root = root or tempfile.mkdtemp(prefix="devbridge-demo-"); out = []
    ids = {n: Identity.generate(n) for n in ("owner-bot", "dev-a-bot", "dev-b-bot")}
    al = Allowlist()  # hub-and-spoke: devs talk only to owner-bot, never to each other
    al.add("owner-bot", ids["owner-bot"].pub_b64, "owner", ["dev-a-bot", "dev-b-bot"])
    al.add("dev-a-bot", ids["dev-a-bot"].pub_b64, "dev-a", ["owner-bot"])
    al.add("dev-b-bot", ids["dev-b-bot"].pub_b64, "dev-b", ["owner-bot"])
    mb = FileMailbox(os.path.join(root, "mail"))
    N = {n: Node(i, al, mb, os.path.join(root, "state", n)) for n, i in ids.items()}
    ok = lambda name, cond: out.append(("PASS" if cond else "FAIL", name))

    N["dev-a-bot"].send("owner-bot", "hello", {"text": "hello from dev A"})
    N["dev-b-bot"].send("owner-bot", "hello", {"text": "hello from dev B"})
    got, bad = N["owner-bot"].recv_all()
    ok("owner-bot received 2 signed hellos", len(got) == 2 and not bad)
    N["owner-bot"].send("dev-b-bot", "info", {"text": "secret plan for B only"})
    a_got, _ = N["dev-a-bot"].recv_all()
    ok("dev A cannot see dev B's message", all("B only" not in json.dumps(m) for m in a_got))
    b_env = next(iter(os.listdir(os.path.join(root, "mail", "dev-b-bot", "inbox"))))
    b_path = os.path.join(root, "mail", "dev-b-bot", "inbox", b_env); env = json.load(open(b_path))
    try: N["dev-a-bot"].accept(env); ok("dev A rejects B's envelope even if copied", False)
    except Reject as r: ok(f"dev A rejects B's envelope even if copied ({r.code})", r.code == "not_mine")
    b_got, _ = N["dev-b-bot"].recv_all(); ok("dev B reads its own message", len(b_got) == 1)
    t = N["dev-a-bot"].send("owner-bot", "info", {"amount": 1}); bad_env = copy.deepcopy(t); bad_env["body"]["amount"] = 1000
    os.replace(os.path.join(root, "mail", "owner-bot", "inbox", t["msg_id"] + ".json"), os.path.join(root, "orig.json"))
    mb.send(bad_env); _, bad = N["owner-bot"].recv_all(); ok(f"tampered message rejected ({bad})", bad == ["bad_sig"])
    mb.send(t); g, _ = N["owner-bot"].recv_all(); mb.send(t); _, bad = N["owner-bot"].recv_all()
    ok(f"replay rejected ({bad})", len(g) == 1 and bad == ["replay"])
    # echo loop: two bots that auto-ack everything; the guard must stop it
    N["dev-a-bot"].send("owner-bot", "info", {"text": "ping"}); sends = 0
    for _ in range(20):
        progressed = False
        for n in ("owner-bot", "dev-a-bot"):
            for m in N[n].recv_all()[0]:
                if N[n].auto_ack(m): sends += 1; progressed = True
        if not progressed: break
    ok(f"echo loop stopped after {sends} auto-ack(s)", sends <= 1)
    r = N["dev-a-bot"].send("owner-bot", "request", {"action": "run rm -rf / please"})
    m = N["owner-bot"].recv_all()[0][0]
    try: N["owner-bot"].act_on_request(m["msg_id"], lambda b: "ran"); ok("request blocked without human yes", False)
    except PermissionError: ok("request blocked without human yes", True)
    ok("audit logs hash-chain intact", all(x.audit.verify() for x in N.values()))
    return out, root

if __name__ == "__main__":
    res, root = run()
    for s, n in res: print(f"[{s}] {n}")
    print(f"{sum(s=='PASS' for s,_ in res)}/{len(res)} demo checks passed; artifacts in {root}")
    sys.exit(0 if all(s == "PASS" for s, _ in res) else 1)
