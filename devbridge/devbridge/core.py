"""devbridge v1: transport-agnostic, signed bot-to-bot messages. Received content is DATA, never instructions."""
import base64, fcntl, hashlib, json, os, re, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from . import secret_scan, pii_scan

VERSION = 1
TYPES = {"hello", "info", "request", "ack", "error"}
NO_AUTO_REPLY = {"ack", "error"}          # never auto-ack an ack/error
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_BODY_BYTES = 32 * 1024
MAX_HOPS = 3
TS_WINDOW_S = 300
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
MSG_ID_RE = re.compile(r"^[0-9a-f]{32}$")
STR_FIELDS = ("msg_id", "from", "to", "type", "thread", "ts", "sig")

def secure_umask(): os.umask(0o077)  # F7: files 0600, dirs 0700

def atomic_write_json(path, obj):
    """F4/F9: write tmp (0600) + fsync + rename, under an exclusive lock file."""
    d = os.path.dirname(path) or "."
    with open(os.path.join(d, "." + os.path.basename(path) + ".lock"), "a") as lk:
        os.chmod(lk.name, 0o600); fcntl.flock(lk, fcntl.LOCK_EX)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f: json.dump(obj, f, sort_keys=True); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)

class Reject(Exception):
    def __init__(self, code, detail=""): super().__init__(f"{code}: {detail}"); self.code = code

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s.encode(), validate=True)
def now_iso(): return datetime.now().astimezone().isoformat(timespec="seconds")
def canonical(env): return json.dumps({k: v for k, v in env.items() if k != "sig"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

# ---------- identity ----------
class Identity:
    def __init__(self, bot_id, priv): self.bot_id, self.priv = bot_id, priv
    @property
    def pub_b64(self):
        from cryptography.hazmat.primitives import serialization as s
        return b64e(self.priv.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw))
    @classmethod
    def generate(cls, bot_id):
        if not ID_RE.match(bot_id): raise ValueError("bad bot id")
        return cls(bot_id, Ed25519PrivateKey.generate())
    def save(self, d):
        from cryptography.hazmat.primitives import serialization as s
        os.makedirs(d, mode=0o700, exist_ok=True)
        p = os.path.join(d, f"{self.bot_id}.key")
        if os.path.exists(p): raise FileExistsError(p)  # never overwrite a key
        raw = self.priv.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f: json.dump({"bot_id": self.bot_id, "ed25519_raw": b64e(raw)}, f)
        atomic_write_json(os.path.join(d, f"{self.bot_id}.pub.json"), {"bot_id": self.bot_id, "pub": self.pub_b64, "alg": "ed25519"})
        return p
    @classmethod
    def load(cls, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        st = os.fstat(fd)
        if st.st_mode & 0o077: os.close(fd); raise PermissionError(f"private key {path} is group/world accessible; chmod 600")
        if st.st_uid != os.getuid(): os.close(fd); raise PermissionError(f"private key {path} not owned by this user")
        with os.fdopen(fd) as f: d = json.load(f)
        return cls(d["bot_id"], Ed25519PrivateKey.from_private_bytes(b64d(d["ed25519_raw"])))

# ---------- allowlist / policy ----------
class Allowlist:
    """{bot_id: {"pub": b64, "namespace": "owner"|"dev-<name>", "may_send_to": [bot_id,...]}}"""
    def __init__(self, peers=None, revoked=None, rotated=None):
        self.peers, self.revoked, self.rotated = dict(peers or {}), dict(revoked or {}), dict(rotated or {})
    @classmethod
    def load(cls, path, revoked_path=None, rotations_path=None):
        rd = lambda p: json.load(open(p)) if p and os.path.exists(p) else {}
        return cls(rd(path), rd(revoked_path), rd(rotations_path))
    def save(self, path): atomic_write_json(path, self.peers)
    def add(self, bot_id, pub, namespace, may_send_to):
        if not ID_RE.match(bot_id): raise ValueError("bad bot id")
        Ed25519PublicKey.from_public_bytes(b64d(pub))
        if self.is_retired(pub): raise ValueError("key is revoked/retired and cannot be re-added")
        self.peers[bot_id] = {"pub": pub, "namespace": namespace, "may_send_to": list(may_send_to)}
    def pub(self, bot_id):
        if bot_id in self.revoked: raise Reject("revoked", bot_id)
        p = self.peers.get(bot_id)
        if not p: raise Reject("unknown_peer", bot_id)
        if self.is_retired(p["pub"]): raise Reject("key_retired", bot_id)
        return Ed25519PublicKey.from_public_bytes(b64d(p["pub"]))
    def is_retired(self, pub):
        """K2: rotated-out or revoked keys are retired forever."""
        return pub in self.rotated or any(isinstance(v, dict) and v.get("pub") == pub for v in self.revoked.values())
    def revoke(self, bot_id, info=None):
        self.revoked[bot_id] = info or {"pub": self.peers.get(bot_id, {}).get("pub")}; self.peers.pop(bot_id, None)
        for p in self.peers.values(): p["may_send_to"] = [x for x in p.get("may_send_to", []) if x != bot_id]
    def route_ok(self, frm, to):
        if frm in self.revoked or to in self.revoked: return False
        return to in self.peers.get(frm, {}).get("may_send_to", [])

# ---------- redaction ----------
def redact_text(s):
    pats = [("split_key", r"\b[sprk]k[-_](live|test|proj)[-_][A-Za-z0-9 _-]{3,}")] + list(secret_scan.PATTERNS.items()) + list(pii_scan.RULES.items())
    for name, p in pats:
        if name == "hex64_candidate": continue  # sha256 hashes are legit message content
        s = re.sub(p, f"[REDACTED:{name}]", s)
    for t in secret_scan.TOK.findall(s):
        if secret_scan.entropy(t) >= 4.5 and not re.fullmatch(r"[A-Za-z]+", t): s = s.replace(t, "[REDACTED:high_entropy]")
    if secret_scan.seed_phrase(s): s = "[REDACTED:seed_phrase]"
    return s
def redact(obj):
    if isinstance(obj, str): return redact_text(obj)
    if isinstance(obj, list): return [redact(x) for x in obj]
    if isinstance(obj, dict): return {redact_text(str(k)): redact(v) for k, v in obj.items()}
    return obj

# ---------- audit ----------
# N1 (security re-review): structural audit fields are NEVER run through redaction (pii_scan's sol_wallet_like rule
# matched ~14.5% of hex msg_ids). They are validated by format instead; a value that fails validation is replaced by a
# marker, never stored raw. Only free-text / unknown fields are redacted.
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
APPROVER_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{0,63}$")
# Legal Chief (b): reserved usr-/bot- subject ids never enter the audit log as ids (kind refused), even though they match ID_RE.
_RESERVED_SUBJECT_RE = re.compile(r"^(usr|bot)-[0-9]{4,}$")
_ID_FIELDS = ("thread", "frm", "from", "to", "peer", "admin", "code")
# Legal Chief (d) + HQ: best-effort personal-name redaction in FREE-TEXT audit fields only (not structural fields, not approver).
# Catches capitalised "First Last" / "First M. Last" pairs and the owner's name in any case (pii_scan owner_name).
# LIMITS: misses single names ("Jane"), lowercase names, non-Latin scripts; may over-redact capitalised word pairs
# ("Synthetic Test"). It is a safety net, not a guarantee: don't put people's names in reasons.
_NAME_TOKEN = r"(?:[A-Z]'[A-Z][a-z]+|[A-Z][a-z]+(?:-[A-Z][a-z]+)?)"
PERSON_NAME_RE = re.compile(rf"\b{_NAME_TOKEN}(?:\s+[A-Z]\.)?\s+{_NAME_TOKEN}\b")
def redact_names(obj):
    if isinstance(obj, str): return PERSON_NAME_RE.sub("[REDACTED:person_name]", obj)
    if isinstance(obj, list): return [redact_names(x) for x in obj]
    if isinstance(obj, dict): return {k: redact_names(v) for k, v in obj.items()}
    return obj
def _iso_ok(v):
    try: datetime.fromisoformat(v); return True
    except Exception: return False
_STRUCT = {
    "msg_id": lambda v: isinstance(v, str) and bool(MSG_ID_RE.match(v)),
    **{k: (lambda v: isinstance(v, str) and bool(ID_RE.match(v))) for k in ("thread", "frm", "from", "to", "peer", "admin", "code")},
    # N3: approver is a human display name ("Alex"), its own structural format: letters, space, . ' - ; 1..64 chars, no digits/@/newline.
    "approver": lambda v: isinstance(v, str) and bool(APPROVER_RE.match(v)),
    "type": lambda v: v in TYPES,
    **{k: (lambda v: isinstance(v, str) and bool(_HEX64_RE.match(v))) for k in ("sealed_sha256", "old_pub_sha256", "fingerprint")},
    **{k: (lambda v: isinstance(v, int) and not isinstance(v, bool)) for k in ("hops", "sources")},
    "echo": lambda v: isinstance(v, bool), "enrolled": lambda v: isinstance(v, bool),
    **{k: (lambda v: isinstance(v, str) and _iso_ok(v)) for k in ("ts", "revoked_at", "sealed_at", "erased_at")},
    "sig": lambda v: isinstance(v, str) and bool(re.fullmatch(r"[A-Za-z0-9+/=_-]{1,256}", v)),
}
def audit_fields(kw):
    out = {}
    for k, v in kw.items():
        if k in _STRUCT:
            if k in _ID_FIELDS and isinstance(v, str) and _RESERVED_SUBJECT_RE.match(v): out[k] = f"[REFUSED:{k}:reserved-kind]"; continue
            out[k] = v if (v is None or _STRUCT[k](v)) else f"[INVALID:{k}]"
        else:
            out[redact_text(str(k))] = redact_names(redact(v))
    return out

class AuditLog:
    """Append-only JSONL, flock-locked, hash-chained. F6: head hash + line count anchored in a separate <log>.head file
    (put it on a path the bot's peers cannot write; on a shared UNIX user nothing is tamper-proof)."""
    def __init__(self, path, head_path=None): self.path, self.head_path = path, head_path or path + ".head"
    def _head(self):
        try: return json.load(open(self.head_path))
        except (OSError, ValueError): return None
    def append(self, event, **kw):
        """N4: ts / prev / event are set here and can NOT be supplied or overridden by callers."""
        if "ts" in kw or "prev" in kw or "event" in kw: raise ValueError("audit: ts/prev/event are set by AuditLog, not the caller")
        os.makedirs(os.path.dirname(self.path) or ".", mode=0o700, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a+b") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                h = self._head() or {"count": 0, "head": "0" * 64}
                rec = {**audit_fields(kw), "ts": now_iso(), "event": event, "prev": h["head"]}
                line = json.dumps(rec, sort_keys=True).encode()
                f.write(line + b"\n"); f.flush(); os.fsync(f.fileno())
                atomic_write_json(self.head_path, {"count": h["count"] + 1, "head": hashlib.sha256(line).hexdigest()})
            finally: fcntl.flock(f, fcntl.LOCK_UN)
    def verify(self):
        """True only if every line parses, the chain links, and the final hash + count match the anchor."""
        try:
            prev, n = "0" * 64, 0
            data = open(self.path, "rb").read() if os.path.exists(self.path) else b""
            if data and not data.endswith(b"\n"): return False
            for line in data.splitlines():
                rec = json.loads(line)
                if not isinstance(rec, dict) or rec.get("prev") != prev: return False
                prev, n = hashlib.sha256(line).hexdigest(), n + 1
            h = self._head()
            if h is None: return n == 0
            return h.get("count") == n and h.get("head") == prev
        except Exception: return False
    def events(self):
        out = []
        if os.path.exists(self.path):
            for l in open(self.path):
                try: out.append(json.loads(l))
                except ValueError: pass
        return out

# ---------- envelope ----------
def make_envelope(ident, to, type_, body, thread=None, hops=0, ts=None):
    if type_ not in TYPES: raise ValueError("bad type")
    if thread is not None and not ID_RE.match(thread): raise ValueError("bad thread id")
    if not isinstance(body, dict): raise ValueError("body must be a JSON object")
    body = redact(body)  # redact BEFORE signing so secrets never leave
    if type_ == "request": body = {**body, "requires_human_approval": True}
    env = {"v": VERSION, "msg_id": uuid.uuid4().hex, "from": ident.bot_id, "to": to, "type": type_,
           "thread": thread or uuid.uuid4().hex, "ts": ts or now_iso(), "hops": hops, "body": body}
    if len(json.dumps(body).encode()) > MAX_BODY_BYTES: raise Reject("too_large", "body")
    env["sig"] = b64e(ident.priv.sign(canonical(env)))
    if len(json.dumps(env).encode()) > MAX_ENVELOPE_BYTES: raise Reject("too_large", "envelope")
    return env

def verify_envelope(env, allow, now=None):
    try: return _verify(env, allow, now)
    except Reject: raise
    except Exception as x: raise Reject("schema", type(x).__name__)  # F1: never let malformed input crash

def _verify(env, allow, now=None):
    """Stateless checks: schema, size, ts window, hop cap, signature. Raises Reject."""
    if not isinstance(env, dict): raise Reject("schema", "not object")
    if len(json.dumps(env).encode()) > MAX_ENVELOPE_BYTES: raise Reject("too_large", "envelope")
    need = {"v", "msg_id", "from", "to", "type", "thread", "ts", "hops", "body", "sig"}
    if set(env) != need: raise Reject("schema", f"fields {sorted(set(env) ^ need)}")
    for k in STR_FIELDS:
        if not isinstance(env[k], str): raise Reject("schema", f"{k} must be str")
    if type(env["v"]) is not int or type(env["hops"]) is not int: raise Reject("schema", "v/hops must be int")
    if not MSG_ID_RE.match(env["msg_id"]) or not ID_RE.match(env["thread"]): raise Reject("schema", "msg_id/thread format")
    if not ID_RE.match(env["from"]) or not ID_RE.match(env["to"]): raise Reject("schema", "bot id format")
    if env["v"] != VERSION: raise Reject("version", str(env["v"]))
    if env["type"] not in TYPES or not isinstance(env["body"], dict): raise Reject("schema", "type/body")
    if not (isinstance(env["hops"], int) and 0 <= env["hops"]): raise Reject("schema", "hops")
    if env["hops"] > MAX_HOPS: raise Reject("loop", "hop limit")
    if len(json.dumps(env["body"]).encode()) > MAX_BODY_BYTES: raise Reject("too_large", "body")
    try: ts = datetime.fromisoformat(env["ts"])
    except Exception: raise Reject("schema", "ts")
    if ts.tzinfo is None: raise Reject("schema", "ts needs offset")
    now = now or datetime.now().astimezone()
    if abs((now - ts).total_seconds()) > TS_WINDOW_S: raise Reject("stale", env["ts"])
    try: allow.pub(env["from"]).verify(b64d(env["sig"]), canonical(env))
    except (InvalidSignature, ValueError):
        for old, info in allow.rotated.items():  # F14: explicit reason if a rotated-out key signed it
            if info.get("peer") != env["from"]: continue
            try: Ed25519PublicKey.from_public_bytes(b64d(old)).verify(b64d(env["sig"]), canonical(env))
            except (InvalidSignature, ValueError): continue
            raise Reject("key_rotated", f'{env["from"]} key revoked at {info.get("revoked_at")}')
        raise Reject("bad_sig", env["msg_id"])
    if not allow.route_ok(env["from"], env["to"]): raise Reject("route", f'{env["from"]}->{env["to"]}')
    return True

# ---------- node ----------
class Node:
    """One bot. Owns exactly one mailbox namespace; reads only its own inbox.
    F5/F8: rate, echo, thread-budget and new-thread counters persist in state.json (0600, atomic, locked)."""
    def __init__(self, ident, allow, transport, state_dir, rate_per_min=30, thread_reply_budget=5, new_threads_per_min=30):
        secure_umask()
        self.id, self.allow, self.t, self.state = ident, allow, transport, state_dir
        os.makedirs(state_dir, mode=0o700, exist_ok=True)
        self.audit = AuditLog(os.path.join(state_dir, "audit.jsonl"))
        self.seen_path = os.path.join(state_dir, "seen.jsonl")
        self.state_path = os.path.join(state_dir, "state.json")
        self.warnings = []
        if os.path.exists(self.audit.path) and not self.audit.verify():
            raise RuntimeError(f"audit log {self.audit.path} fails verification; refusing to start (fail closed)")
        self.seen = self._load_seen()
        self.rate_per_min, self.thread_reply_budget, self.new_threads_per_min = rate_per_min, thread_reply_budget, new_threads_per_min
        st = self._load_state() or self._rebuild_state_from_audit()
        self.rate = defaultdict(list, st.get("rate", {}))                 # peer -> [epoch seconds]
        self.new_threads = defaultdict(list, st.get("new_threads", {}))   # peer -> [epoch seconds]
        self.thread_replies = defaultdict(int, st.get("thread_replies", {}))
        self.thread_bodies = defaultdict(set, {k: set(v) for k, v in st.get("thread_bodies", {}).items()})
        self.thread_owner = dict(st.get("thread_owner", {}))              # thread -> first peer
        self.pending, self.approvals = {}, {}

    def _load_seen(self):
        """F4: skip corrupt lines (warn); F7 defence: also rebuild from audit 'accepted' events."""
        seen = set()
        if os.path.exists(self.seen_path):
            for i, l in enumerate(open(self.seen_path, errors="replace"), 1):
                try: seen.add(json.loads(l)["msg_id"])
                except Exception: self.warnings.append(f"seen.jsonl line {i} corrupt, skipped")
        seen |= {e["msg_id"] for e in self.audit.events() if e.get("event") == "accepted" and isinstance(e.get("msg_id"), str)}
        return seen

    def _load_state(self):
        try: st = json.load(open(self.state_path)); return st if isinstance(st, dict) else {}
        except FileNotFoundError: return {}
        except Exception: self.warnings.append("state.json corrupt; rebuilding from audit"); return {}

    def _rebuild_state_from_audit(self):
        """state.json missing/corrupt: rebuild rate, new-thread and thread-owner state from the anchored audit (no fail-open)."""
        rate, nt, owner = defaultdict(list), defaultdict(list), {}
        for e in self.audit.events():
            if e.get("event") != "accepted": continue
            try: t = datetime.fromisoformat(e["ts"]).timestamp()
            except Exception: continue
            rate[e.get("frm")].append(t)
            if e.get("thread") not in owner: owner[e.get("thread")] = e.get("frm"); nt[e.get("frm")].append(t)
        if owner: self.warnings.append("state rebuilt from audit")
        return {"rate": dict(rate), "new_threads": dict(nt), "thread_owner": owner}

    def _save_state(self):
        atomic_write_json(self.state_path, {"rate": self.rate, "new_threads": self.new_threads, "thread_replies": self.thread_replies,
                                            "thread_bodies": {k: sorted(v) for k, v in self.thread_bodies.items()},
                                            "thread_owner": self.thread_owner})

    def _append_seen(self, env):
        fd = os.open(self.seen_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps({"msg_id": env["msg_id"], "ts": env["ts"]}) + "\n"); f.flush(); os.fsync(f.fileno())
            fcntl.flock(f, fcntl.LOCK_UN)

    def send(self, to, type_, body, thread=None, hops=0):
        if to in self.allow.revoked: raise Reject("revoked", to)
        env = make_envelope(self.id, to, type_, body, thread, hops)
        self.t.send(env)
        self.audit.append("sent", msg_id=env["msg_id"], to=to, type=type_, thread=env["thread"], hops=hops)
        return env

    @staticmethod
    def _window(lst, now): lst[:] = [t for t in lst if now - t < 60]; return lst

    def accept(self, env, now=None):
        """Verify + dedupe + store as DATA. Returns the (redacted) envelope or raises Reject. Never raises anything else."""
        try:
            try:
                if not isinstance(env, dict): raise Reject("schema", "not object")
                if "_transport_reject" in env: raise Reject(str(env["_transport_reject"]), str(env.get("file")))
                if env.get("to") != self.id.bot_id: raise Reject("not_mine", str(env.get("to"))[:64])
                if env.get("from") in self.allow.revoked: raise Reject("revoked", str(env.get("from"))[:64])
                verify_envelope(env, self.allow, now)
                if env["msg_id"] in self.seen: raise Reject("replay", env["msg_id"])
                t, frm, th = time.time(), env["from"], env["thread"]
                if len(self._window(self.rate[frm], t)) >= self.rate_per_min: raise Reject("rate_limited", frm)
                if th not in self.thread_owner:
                    if len(self._window(self.new_threads[frm], t)) >= self.new_threads_per_min: raise Reject("thread_rate", frm)
            except Reject: raise
            except Exception as x: raise Reject("schema", type(x).__name__)
        except Reject as r:
            self.audit.append("rejected", code=r.code, msg_id=str(env.get("msg_id"))[:64] if isinstance(env, dict) else None,
                              frm=str(env.get("from"))[:64] if isinstance(env, dict) else None)
            raise
        self.rate[frm].append(t)
        if th not in self.thread_owner: self.thread_owner[th] = frm; self.new_threads[frm].append(t)
        h = hashlib.sha256(json.dumps(env["body"], sort_keys=True).encode()).hexdigest()
        echo = h in self.thread_bodies[th]; self.thread_bodies[th].add(h)
        self.seen.add(env["msg_id"]); self._append_seen(env); self._save_state()
        data = {**env, "body": redact(env["body"]), "_data_only": True, "_echo": echo}
        if env["type"] == "request": self.pending[env["msg_id"]] = data
        self.audit.append("accepted", msg_id=env["msg_id"], frm=frm, type=env["type"], thread=th, echo=echo)
        return data

    def recv_all(self, now=None):
        good, bad = [], []
        for env in self.t.recv(self.id.bot_id):
            try: good.append(self.accept(env, now))
            except Reject as r: bad.append(r.code)
            except Exception as x: bad.append("internal:" + type(x).__name__)  # F1: one bad message never stops the loop
        return good, bad

    def may_auto_reply(self, msg):
        """Loop guard: no reply to ack/error, none past hop cap, none to echoes, persisted per-thread budget
        (F8: hops are sender-chosen and advisory; the receiver-side budget is the real guard)."""
        if msg["type"] in NO_AUTO_REPLY or msg["_echo"] or msg["hops"] + 1 > MAX_HOPS: return False
        if self.thread_replies[msg["thread"]] >= self.thread_reply_budget: return False
        return True

    def auto_ack(self, msg):
        if not self.may_auto_reply(msg):
            self.audit.append("loop_stopped", msg_id=msg["msg_id"], thread=msg["thread"]); return None
        self.thread_replies[msg["thread"]] += 1; self._save_state()
        return self.send(msg["from"], "ack", {"ack_of": msg["msg_id"]}, msg["thread"], msg["hops"] + 1)

    def approve(self, msg_id, approver, typed_yes):
        """Only a human typing 'yes' flips the approval flag. Nothing in the message can set it."""
        if msg_id not in self.pending: raise KeyError(msg_id)
        if typed_yes.strip().lower() != "yes" or not approver: raise PermissionError("needs a human typed yes")
        self.approvals[msg_id] = approver
        self.audit.append("approved", msg_id=msg_id, approver=approver)

    def act_on_request(self, msg_id, handler):
        """Run a LOCAL, pre-registered handler on request data only after human approval."""
        if msg_id not in self.approvals:
            self.audit.append("action_blocked", msg_id=msg_id); raise PermissionError("not approved by a human")
        self.audit.append("action_run", msg_id=msg_id)
        return handler(self.pending[msg_id]["body"])
