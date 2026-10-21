import json, os, re, stat
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
MSG_ID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_FILE_BYTES = 64 * 1024

class FileMailbox:
    """Local transport: <root>/<bot_id>/inbox/<msg_id>.json. Root and inboxes 0700, message files 0600.
    Isolation is only real when each bot runs as its own OS user (or host)."""
    def __init__(self, root):
        os.umask(0o077)
        self.root = os.path.abspath(root); os.makedirs(self.root, mode=0o700, exist_ok=True)
        if os.stat(self.root).st_uid == os.getuid(): os.chmod(self.root, 0o700)
    def _dir(self, bot_id, sub):
        if not isinstance(bot_id, str) or not ID_RE.match(bot_id): raise ValueError("bad bot id")
        p = os.path.realpath(os.path.join(self.root, bot_id, sub))
        if not p.startswith(self.root + os.sep): raise ValueError("path escape")
        os.makedirs(p, mode=0o700, exist_ok=True); return p
    def _inbox(self, bot_id): return self._dir(bot_id, "inbox")
    def send(self, env):
        if not isinstance(env.get("msg_id"), str) or not MSG_ID_RE.match(env["msg_id"]): raise ValueError("bad msg_id")  # F11
        d = self._inbox(env["to"]); tmp = os.path.join(d, f".{env['msg_id']}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f: json.dump(env, f)
        os.replace(tmp, os.path.join(d, f"{env['msg_id']}.json"))
    def _read(self, p):
        """F2/F3: no symlinks, regular file only, owned by us, size checked via fstat BEFORE reading."""
        try: fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError: return {"_transport_reject": "not_regular_file"}
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode): return {"_transport_reject": "not_regular_file"}
            if st.st_uid != os.getuid(): return {"_transport_reject": "bad_owner"}
            if st.st_size > MAX_FILE_BYTES: return {"_transport_reject": "too_large"}
            raw = f.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES: return {"_transport_reject": "too_large"}
        try: return json.loads(raw)
        except Exception: return {"_transport_reject": "unparseable"}
    def recv(self, bot_id):
        """Yields only this bot's inbox. Good files -> processed/, rejected files -> quarantine/ (kept, never deleted)."""
        d = self._inbox(bot_id); done, quar = self._dir(bot_id, "processed"), self._dir(bot_id, "quarantine")
        for n in sorted(os.listdir(d)):
            if not n.endswith(".json"): continue
            p = os.path.join(d, n); env = self._read(p)
            if isinstance(env, dict) and "_transport_reject" in env: env["file"] = n
            os.replace(p, os.path.join(quar if isinstance(env, dict) and "_transport_reject" in env else done, n)); yield env

class NotDeployed(RuntimeError): pass

class HttpTransport:
    """STUB for a future Cloudflare relay (POST /v1/send, GET /v1/inbox/<bot_id>). NOT deployed; makes no network calls.
    prepare_* returns the request that WOULD be sent so it can be reviewed/tested."""
    def __init__(self, base_url, enabled=False): self.base_url, self.enabled = base_url.rstrip("/"), enabled
    def prepare_send(self, env):
        return {"method": "POST", "url": f"{self.base_url}/v1/send", "headers": {"content-type": "application/json"}, "json": env}
    def prepare_recv(self, bot_id): return {"method": "GET", "url": f"{self.base_url}/v1/inbox/{bot_id}"}
    def send(self, env): raise NotDeployed("HTTP relay not deployed; needs the owner's typed yes + security review")
    def recv(self, bot_id): raise NotDeployed("HTTP relay not deployed; needs the owner's typed yes + security review")
