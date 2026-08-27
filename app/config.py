# -*- coding: utf-8 -*-
"""
Central configuration + secret loading.

One resolver for the whole project, checked in this order:

  1. process environment            NAME=...          (a real deployment)
  2. a secret file reference        NAME_FILE=/run/secrets/x
  3. the .env file at the repo root (gitignored, hidden dotfile)
  4. app/local_config.py            (legacy, still honoured if present)
  5. the supplied default

Order matters. The environment wins so a container, systemd unit or Render
service can override anything without touching the tree. NAME_FILE exists
because Docker/Kubernetes/Swarm mount secrets as files rather than variables:
pointing at the path keeps the value out of `docker inspect`, out of the process
environment, and out of any crash dump that prints os.environ.

.env is never committed (.gitignore) so pushing the repo cannot leak it, and it
is a dotfile so it stays out of casual directory listings.

Honest limit, stated once: anything the app can read at runtime, a person with
shell access on that host can read too. What this design actually buys you is
protection against the realistic leak paths — a git push, a zip of the folder, a
screenshot of the source. It is not, and cannot be, protection against someone
who already owns the server.
"""

import os
import threading

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(_ROOT, ".env")

_env_cache = None
_lock = threading.Lock()


def _parse_env(path):
    """Minimal, dependency-free .env parser.

    Supports  KEY=value, export KEY=value, # comments, blank lines, and single or
    double quoted values. Inline comments are only stripped from unquoted values,
    so a '#' inside a quoted secret survives intact.
    """
    data = {}
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return data
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key, val = key.strip(), val.strip()
        if not key:
            continue
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        else:
            cut = val.find(" #")
            if cut != -1:
                val = val[:cut].rstrip()
        data[key] = val
    return data


def env_file():
    global _env_cache
    with _lock:
        if _env_cache is None:
            _env_cache = _parse_env(ENV_PATH)
        return _env_cache


def reload():
    """Drop the cached .env so the next lookup re-reads it from disk."""
    global _env_cache
    with _lock:
        _env_cache = None


def _from_file(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def get(name, default=""):
    """Resolve one configuration value. Never raises."""
    val = os.environ.get(name)
    if val:
        return val

    ref = os.environ.get(name + "_FILE")
    if ref:
        val = _from_file(ref)
        if val:
            return val

    data = env_file()
    val = data.get(name)
    if val:
        return val

    ref = data.get(name + "_FILE")
    if ref:
        val = _from_file(ref)
        if val:
            return val

    try:
        from . import local_config
        val = getattr(local_config, name, "")
        if val:
            return val
    except ImportError:
        pass

    return default


def flag(name, default="0"):
    return str(get(name, default)).lower() in ("1", "true", "yes", "on")


def num(name, default):
    try:
        return int(get(name, default))
    except (TypeError, ValueError):
        return int(default)


def sources():
    """Where configuration is currently coming from — for diagnostics only.

    Reports presence and origin, never a value.
    """
    return {
        "env_file": ENV_PATH,
        "env_file_exists": os.path.exists(ENV_PATH),
        "env_file_keys": sorted(env_file().keys()),
        "local_config_present": os.path.exists(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_config.py")),
    }
