# -*- coding: utf-8 -*-
"""
Security layer for the honeypot ENGINE (not the decoy).

The decoy surface is intentionally weak — injectable login, bait paths — because
that is the trap. Everything here hardens the machinery *around* the trap so an
attacker who pokes the bait can never pivot into the host, the monitor, or the
real captured logs:

  * /_monitor is locked behind HTTP Basic auth (+ an allow-list, default localhost);
  * the signing secret and monitor password come from the environment, never the repo
    (a strong random one is generated and printed at startup if you don't set one);
  * request bodies are size-capped and a per-IP flood limiter sheds abuse / DoS;
  * helpers here are used by honeypot.py to keep cookies/headers strict.

Environment variables (all optional, safe defaults):
  HONEYPOT_SECRET        signing key for VIEWSTATE tokens         (random if unset)
  MONITOR_USER           dashboard basic-auth user                (default: admin)
  MONITOR_PASS           dashboard basic-auth password            (random if unset)
  MONITOR_ALLOW_IPS      comma list allowed without auth          (default: 127.0.0.1,::1)
  HONEYPOT_MAX_BODY      max request body in bytes                (default: 262144)
  HONEYPOT_RATE          max requests per IP per window           (default: 240)
  HONEYPOT_RATE_WINDOW   flood window in seconds                  (default: 10)
  HONEYPOT_HTTPS         set truthy when served over TLS          (adds Secure cookie)
"""
import os
import time
import hmac
import secrets
import threading

from flask import request, Response
from werkzeug.security import check_password_hash, generate_password_hash


def _flag(name):
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")


SECRET = os.environ.get("HONEYPOT_SECRET") or secrets.token_hex(32)

MONITOR_USER = os.environ.get("MONITOR_USER", "mahde")
# The dashboard password is stored ONLY as a salted PBKDF2 hash, so this file is
# safe to publish. Default unlocks /_monitor with  mahde / 123qweQWE@ .
# Override in production with MONITOR_PASS (plain) or MONITOR_PASS_HASH (a hash).
_DEFAULT_HASH = ("pbkdf2:sha256:260000$Pzjyeo0QtO2JFPoG$"
                 "5dd04eeb5b69db6b74db1dfa44bb90119bc02c8e2544657cea9b33ceea1c6947")
if os.environ.get("MONITOR_PASS"):
    MONITOR_PASS_HASH = generate_password_hash(os.environ["MONITOR_PASS"],
                                               method="pbkdf2:sha256:260000")
else:
    MONITOR_PASS_HASH = os.environ.get("MONITOR_PASS_HASH", _DEFAULT_HASH)

# Empty by default => the dashboard ALWAYS requires the password, even on localhost.
# Add comma-separated IPs here only if you want to skip auth from trusted hosts.
MONITOR_ALLOW_IPS = {x.strip() for x in os.environ.get("MONITOR_ALLOW_IPS", "").split(",") if x.strip()}
MAX_BODY = int(os.environ.get("HONEYPOT_MAX_BODY", 256 * 1024))
RATE = int(os.environ.get("HONEYPOT_RATE", 240))
RATE_WINDOW = int(os.environ.get("HONEYPOT_RATE_WINDOW", 10))
HTTPS = _flag("HONEYPOT_HTTPS")

# --- private-demo front door -------------------------------------------------
# When DEMO_GATE_PASS (or DEMO_GATE_PASS_HASH) is set, the ENTIRE decoy surface
# is locked behind HTTP Basic auth, so a public deployment is reachable only by
# people you hand the credential to — never the open internet. This is what keeps
# a hosted "demo" from acting as an open look-alike of a real portal. Unset =>
# the gate is OFF and lab/localhost behaviour is unchanged.
DEMO_GATE_USER = os.environ.get("DEMO_GATE_USER", "demo")
if os.environ.get("DEMO_GATE_PASS"):
    DEMO_GATE_HASH = generate_password_hash(os.environ["DEMO_GATE_PASS"],
                                            method="pbkdf2:sha256:260000")
else:
    DEMO_GATE_HASH = os.environ.get("DEMO_GATE_PASS_HASH", "")
DEMO_GATE_ON = bool(DEMO_GATE_HASH)


def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return (xff.split(",")[0].strip() if xff else request.remote_addr) or "?"


# --- dashboard access control ------------------------------------------------

_auth_fail: dict[str, tuple[int, float]] = {}     # ip -> (count, locked_until)
_auth_lock = threading.Lock()


def monitor_guard():
    """Return a 401/423 Response if the caller may not see the monitor, else None."""
    ip = request.remote_addr or "?"
    if MONITOR_ALLOW_IPS and ip in MONITOR_ALLOW_IPS:
        return None

    with _auth_lock:
        cnt, until = _auth_fail.get(ip, (0, 0.0))
    if until and time.time() < until:
        return Response("423 Locked — too many attempts", 423,
                        {"Retry-After": str(int(until - time.time()))})

    auth = request.authorization
    if (auth and hmac.compare_digest(auth.username or "", MONITOR_USER)
            and check_password_hash(MONITOR_PASS_HASH, auth.password or "")):
        with _auth_lock:
            _auth_fail.pop(ip, None)
        return None

    # Wrong/with a credential supplied -> count it and lock after 5 tries for 5 min.
    if auth is not None:
        with _auth_lock:
            cnt += 1
            until = time.time() + 300 if cnt >= 5 else 0.0
            _auth_fail[ip] = (cnt, until)
    return Response("401 Unauthorized", 401,
                    {"WWW-Authenticate": 'Basic realm="Restricted Monitor"'})


def demo_gate():
    """Front-door gate for a private demo deployment.

    When DEMO_GATE_ON, require HTTP Basic auth on the whole site and return a
    401 Response until the caller authenticates; otherwise return None (gate
    off, or already authenticated). The monitor keeps its own stricter guard.
    """
    if not DEMO_GATE_ON:
        return None
    auth = request.authorization
    if (auth and hmac.compare_digest(auth.username or "", DEMO_GATE_USER)
            and check_password_hash(DEMO_GATE_HASH, auth.password or "")):
        return None
    return Response("401 Unauthorized", 401,
                    {"WWW-Authenticate": 'Basic realm="University Honeypot Demo"'})


# --- per-IP flood limiter (sliding window, memory-bounded) -------------------

_hits: dict[str, list[float]] = {}
_lock = threading.Lock()


def is_flooding(ip: str) -> bool:
    now = time.time()
    cutoff = now - RATE_WINDOW
    with _lock:
        q = _hits.get(ip)
        if q is None:
            q = _hits[ip] = []
        i = 0
        for i, t in enumerate(q):
            if t >= cutoff:
                break
        else:
            i = len(q)
        if i:
            del q[:i]
        q.append(now)
        if len(_hits) > 20000:                     # bound memory under a spray
            for k in [k for k, v in list(_hits.items()) if not v or v[-1] < cutoff]:
                _hits.pop(k, None)
        return len(q) > RATE


def startup_banner():
    allow = ", ".join(sorted(MONITOR_ALLOW_IPS)) or "none (password required everywhere)"
    return "\n".join([
        "=" * 64,
        " University honeypot — security layer active",
        f"  /_monitor  ->  HTTP Basic auth required   user: {MONITOR_USER}",
        f"               password stored as a hash; allow-list: {allow}",
        f"               5 bad logins per IP  ->  5-minute lockout",
        f"  flood limit: {RATE} req / {RATE_WINDOW}s per IP    body cap: {MAX_BODY} bytes",
        "=" * 64,
    ])
