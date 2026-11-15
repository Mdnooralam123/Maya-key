"""
Maya accounts + key generator for VERCEL (Python function, all /api/* routes).
Data is stored in Upstash Redis (Vercel Storage). Only the standard library is used.

Environment variables (Vercel dashboard me set karo):
  ADMIN_TOKEN                 admin ka lamba random token
  UPSTASH_REDIS_REST_URL      Upstash REST url
  UPSTASH_REDIS_REST_TOKEN    Upstash REST token
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.request
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

UPSTASH_URL = os.environ.get("UPSTASH_REDIS_REST_URL", "")
UPSTASH_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

DAY = 86_400_000
UNIT_MS = {"minutes": 60_000, "hours": 3_600_000, "days": 86_400_000}
USER_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
KEY_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


# ---------- Upstash (Redis over REST) ----------
def redis_cmd(args):
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        raise RuntimeError("UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN set nahi hain")
    req = urllib.request.Request(
        UPSTASH_URL,
        data=json.dumps(args).encode("utf-8"),
        headers={"Authorization": "Bearer " + UPSTASH_TOKEN, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        j = json.loads(r.read().decode("utf-8"))
    if j.get("error"):
        raise RuntimeError(j["error"])
    return j.get("result")


def get_json(key):
    v = redis_cmd(["GET", key])
    return json.loads(v) if v else None


def set_json(key, obj):
    redis_cmd(["SET", key, json.dumps(obj)])


# ---------- helpers ----------
def now_ms():
    return int(time.time() * 1000)


def now_ms_plus(value, unit):
    return now_ms() + value * UNIT_MS[unit]


def hash_password(password, salt_hex):
    # same parameters as the Node version (scrypt N=16384 r=8 p=1, 64 bytes, salt = utf-8 of the hex string)
    return hashlib.scrypt(password.encode("utf-8"), salt=salt_hex.encode("utf-8"),
                          n=16384, r=8, p=1, dklen=64).hex()


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def make_key():
    part = lambda: "".join(secrets.choice(KEY_CHARS) for _ in range(4))
    return "MAYA-" + part() + "-" + part() + "-" + part()


def create_account(username, password, expires):
    salt = secrets.token_hex(16)
    set_json("acc:" + username, {
        "hash": hash_password(password, salt), "salt": salt, "expires_at": expires,
        "disabled": False, "used": False, "created_at": now_ms(),
    })
    redis_cmd(["SADD", "accounts", username])


def expiry_from(kind, value):
    if kind == "lifetime":
        return now_ms() + 100 * 365 * DAY
    if kind in UNIT_MS and value > 0:
        return now_ms_plus(value, kind)
    return None


# ---------- request handler (Vercel Python runtime) ----------
class handler(BaseHTTPRequestHandler):

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, x-admin-token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _is_admin(self):
        if not ADMIN_TOKEN:
            return False
        given = self.headers.get("x-admin-token", "")
        return hmac.compare_digest(given.encode("utf-8"), ADMIN_TOKEN.encode("utf-8"))

    def log_message(self, fmt, *args):
        return  # token wali request line log me kabhi nahi jayegi

    def do_OPTIONS(self):
        self._send(200, {"ok": True})

    def do_GET(self):
        try:
            self._get(urlparse(self.path).path)
        except Exception as e:
            self._send(500, {"ok": False, "message": str(e)})

    def do_POST(self):
        try:
            self._post(urlparse(self.path).path, self._body())
        except Exception as e:
            self._send(500, {"ok": False, "message": str(e)})

    def _get(self, path):
        if path == "/api/health":
            return self._send(200, {"ok": True, "service": "maya-accounts-vercel"})
        if path == "/api/update":
            return self._send(200, get_json("cfg:update") or {"version": 0, "apk_url": "", "notes": ""})
        if path == "/api/admin/accounts":
            if not self._is_admin():
                return self._send(401, {"ok": False, "message": "admin token galat"})
            out = []
            for u in sorted(redis_cmd(["SMEMBERS", "accounts"]) or []):
                r = get_json("acc:" + u) or {}
                exp = r.get("expires_at", 0)
                out.append({"username": u, "expires_at": exp, "disabled": bool(r.get("disabled")),
                            "used": bool(r.get("used")), "left_min": max(0, int((exp - now_ms()) / 60000))})
            return self._send(200, {"ok": True, "accounts": out})
        return self._send(404, {"ok": False, "message": "Not Found"})

    def _post(self, path, b):
        if path in ("/api/admin/gen", "/api/admin/key"):
            if not self._is_admin():
                return self._send(401, {"ok": False, "message": "admin token galat"})
            kind = str(b.get("type", "days"))
            value = int(b.get("value") or 0)
            expires = expiry_from(kind, value)
            if expires is None:
                return self._send(400, {"ok": False, "message": "type lifetime/minutes/hours/days aur value > 0 do"})
            username = "u" + secrets.token_hex(4)
            password = secrets.token_urlsafe(8)
            create_account(username, password, expires)
            key = make_key()
            set_json("gkey:" + sha(key), {"username": username})
            return self._send(200, {"ok": True, "key": key, "username": username, "password": password,
                                    "type": kind, "expires_at": expires})

        if path == "/api/login_key":
            key = str(b.get("key", "")).strip().upper()
            link = get_json("gkey:" + sha(key)) if key else None
            acc = get_json("acc:" + link["username"]) if link else None
            if not acc:
                return self._send(200, {"ok": False, "message": "Key galat hai"})
            if acc.get("disabled"):
                return self._send(200, {"ok": False, "message": "Ye key band hai"})
            if acc.get("used"):
                return self._send(200, {"ok": False, "message": "Ye key pehle hi use ho chuki hai"})
            if now_ms() > acc["expires_at"]:
                return self._send(200, {"ok": False, "message": "Key ki time khatam ho gayi"})
            acc["used"] = True
            set_json("acc:" + link["username"], acc)
            return self._send(200, {"ok": True, "username": link["username"], "expires_at": acc["expires_at"],
                                    "message": "Key se login ho gaya"})

        if path == "/api/login":
            username = str(b.get("username", "")).strip().lower()
            password = str(b.get("password", ""))
            bad = {"ok": False, "message": "Username ya password galat"}
            acc = get_json("acc:" + username) if USER_RE.match(username) else None
            if not acc:
                return self._send(200, bad)
            if not hmac.compare_digest(hash_password(password, acc["salt"]), acc["hash"]):
                return self._send(200, bad)
            if acc.get("disabled"):
                return self._send(200, {"ok": False, "message": "Ye account band hai. Admin se baat karo"})
            if now_ms() > acc["expires_at"]:
                return self._send(200, {"ok": False, "message": "Account ki time khatam ho gayi. Admin se baat karo"})
            if acc.get("used"):
                return self._send(200, {"ok": False, "message": "Ye username/password pehle hi use ho chuka hai. Admin se naya account lo"})
            acc["used"] = True
            set_json("acc:" + username, acc)
            return self._send(200, {"ok": True, "username": username, "expires_at": acc["expires_at"], "message": "Login ho gaya"})

        if path == "/api/admin/account":
            if not self._is_admin():
                return self._send(401, {"ok": False, "message": "admin token galat"})
            username = str(b.get("username", "")).strip().lower()
            password = str(b.get("password", ""))
            if not USER_RE.match(username) or len(password) < 6:
                return self._send(400, {"ok": False, "message": "username 3-32 (a-z, 0-9, _ . -) aur password 6+ chahiye"})
            value = int(b.get("duration_value") or 0)
            unit = b.get("duration_unit") if b.get("duration_unit") in UNIT_MS else "days"
            if value <= 0:
                return self._send(400, {"ok": False, "message": "duration galat"})
            expires = now_ms_plus(value, unit)
            create_account(username, password, expires)
            return self._send(200, {"ok": True, "username": username, "expires_at": expires})

        if path == "/api/admin/account_action":
            if not self._is_admin():
                return self._send(401, {"ok": False, "message": "admin token galat"})
            username = str(b.get("username", "")).strip().lower()
            action = str(b.get("action", ""))
            if action == "delete":
                redis_cmd(["DEL", "acc:" + username])
                redis_cmd(["SREM", "accounts", username])
                return self._send(200, {"ok": True})
            acc = get_json("acc:" + username)
            if not acc:
                return self._send(404, {"ok": False, "message": "account nahi mila"})
            if action == "disable":
                acc["disabled"] = True
            elif action == "enable":
                acc["disabled"] = False
            elif action in ("reset_use", "reset_device"):
                acc["used"] = False
            elif action == "extend":
                value = int(b.get("duration_value") or 0)
                unit = b.get("duration_unit") if b.get("duration_unit") in UNIT_MS else "days"
                if value <= 0:
                    return self._send(400, {"ok": False, "message": "duration galat"})
                acc["expires_at"] = max(now_ms(), acc["expires_at"]) + value * UNIT_MS[unit]
            else:
                return self._send(400, {"ok": False, "message": "action galat"})
            set_json("acc:" + username, acc)
            return self._send(200, {"ok": True, "expires_at": acc["expires_at"], "disabled": bool(acc.get("disabled"))})

        if path == "/api/admin/update":
            if not self._is_admin():
                return self._send(401, {"ok": False, "message": "admin token galat"})
            u = {"version": int(b.get("version") or 0), "apk_url": str(b.get("apk_url", "")), "notes": str(b.get("notes", ""))}
            set_json("cfg:update", u)
            return self._send(200, {"ok": True, "update": u})

        return self._send(404, {"ok": False, "message": "Not Found"})
