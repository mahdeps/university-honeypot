"""
Structured event logger for the honeypot.

Two outputs:
  1. logs/events.jsonl  — one JSON object per line, the authoritative record.
                          Easy to load into pandas / Kibana / a Jupyter notebook
                          for the final report.
  2. console            — a short human-readable line so you can watch live.

We log EVERYTHING: every request, whether or not a detector fired. The boring
requests matter too — they show the attacker mapping the site before striking.

Nothing real is ever stored here. All credentials/data the attacker sees are
decoy, so capturing what they submit is safe and is exactly the research output.
"""

import json
import os
import threading
from datetime import datetime, timezone

_LOCK = threading.Lock()
_LOG_DIR = os.environ.get("HONEYPOT_LOG_DIR", os.path.join(os.path.dirname(__file__), "..", "logs"))
_EVENTS_FILE = os.path.join(_LOG_DIR, "events.jsonl")
_ARCHIVE_DIR = os.path.join(_LOG_DIR, "archive")

# Auto-rotate the live log once it passes this size, so a flood (or just a long
# run) can never grow one file until the dashboard chokes on it. 0 disables.
try:
    _MAX_MB = float(os.environ.get("HONEYPOT_LOG_MAX_MB", 50))
except ValueError:
    _MAX_MB = 50.0

os.makedirs(_LOG_DIR, exist_ok=True)


def events_path() -> str:
    """Absolute path of the live event log (used for cache invalidation)."""
    return _EVENTS_FILE


# Subscribers notified about every event as it is written. This is how the
# Telegram notifier watches the stream without logger importing it (which would
# be a cycle). A hook MUST return immediately and must never raise: it runs on
# the request thread, so anything slow here would stall the honeypot itself.
_HOOKS = []


def add_hook(fn) -> None:
    if fn not in _HOOKS:
        _HOOKS.append(fn)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _client_ip(headers: dict[str, str], remote_addr: str) -> str:
    # Honour X-Forwarded-For if present (the attacker may set it themselves — we
    # record both so the dashboard can show spoofing attempts).
    xff = headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return remote_addr


def log_event(
    *,
    remote_addr: str,
    method: str,
    path: str,
    query: dict,
    form: dict,
    headers: dict,
    findings: list[dict],
    event_type: str = "request",
    extra: dict | None = None,
    ts: str | None = None,
    quiet: bool = False,
) -> dict:
    """Persist one event and echo a summary to the console. Returns the record.

    `ts` overrides the event time — needed when replaying a sensor log (e.g. a
    Suricata capture), where the alert's own timestamp must be kept instead of
    the import time, or the timeline would collapse onto "now". `quiet` skips
    the console echo so a bulk import does not scroll the terminal away.
    """
    record = {
        "ts": ts or _now(),
        "event_type": event_type,           # request | login_attempt | shell_probe ...
        "src_ip": _client_ip(headers, remote_addr),
        "remote_addr": remote_addr,
        "method": method,
        "path": path,
        "query": query,
        "form": _redact_nothing(form),       # decoy data — safe to keep verbatim
        "user_agent": headers.get("User-Agent", ""),
        "referer": headers.get("Referer", ""),
        "headers": headers,
        "findings": findings,
        "attack": bool(findings),
    }
    if extra:
        record["extra"] = extra

    line = json.dumps(record, ensure_ascii=False)
    with _LOCK:
        with open(_EVENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        _rotate_if_needed()

    for hook in _HOOKS:
        try:
            hook(record)
        except Exception:
            pass                 # a broken subscriber must never break logging
    if not quiet:
        _console(record)
    return record


def _redact_nothing(form: dict) -> dict:
    # Explicit: in a honeypot the submitted "passwords" are attacker-chosen and
    # the accounts are fake, so there is nothing real to redact. Kept as a named
    # function so the intent is obvious in review.
    return dict(form)


def _console(record: dict) -> None:
    flag = ""
    if record["findings"]:
        cats = ",".join(sorted({f["category"] for f in record["findings"]}))
        flag = f"  [!] {cats}"
    print(
        f"{record['ts']}  {record['src_ip']:<15}  "
        f"{record['method']:<4} {record['path']}{flag}",
        flush=True,
    )


def _tail_lines(path: str, limit: int | None) -> list[bytes]:
    """Return the last `limit` raw lines without loading the whole file.

    The log is append-only, so we walk backwards in 64 KB blocks and stop as
    soon as we have enough newlines. With `limit=None` this still reads the
    whole file — callers that poll should always pass a limit.
    """
    size = os.path.getsize(path)
    if size == 0:
        return []
    block, pos, data = 1 << 16, size, b""
    with open(path, "rb") as fh:
        while pos > 0:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            data = fh.read(step) + data
            if limit is not None and data.count(b"\n") > limit:
                break
    lines = data.split(b"\n")
    if pos > 0:                     # stopped early -> first fragment is partial
        lines = lines[1:]
    lines = [ln for ln in lines if ln.strip()]
    return lines[-limit:] if limit is not None else lines


def read_events(limit: int | None = None) -> list[dict]:
    """Load events back (newest first) for the dashboard."""
    if not os.path.exists(_EVENTS_FILE):
        return []
    events = []
    for ln in reversed(_tail_lines(_EVENTS_FILE, limit)):
        try:
            events.append(json.loads(ln.decode("utf-8")))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if limit and len(events) >= limit:
            break
    return events


# --- log management (exposed on the monitor as archive / clear) --------------

def _count_lines(path: str) -> int:
    n = 0
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                n += chunk.count(b"\n")
    except OSError:
        return 0
    return n


def _do_rotate() -> str | None:
    """Move the live log into archive/ and start fresh. Caller must hold _LOCK."""
    if not os.path.exists(_EVENTS_FILE) or os.path.getsize(_EVENTS_FILE) == 0:
        return None
    os.makedirs(_ARCHIVE_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(_ARCHIVE_DIR, f"events-{stamp}.jsonl")
    i = 1
    while os.path.exists(dest):                     # same-second rotations
        dest = os.path.join(_ARCHIVE_DIR, f"events-{stamp}-{i}.jsonl")
        i += 1
    os.replace(_EVENTS_FILE, dest)
    return dest


def _rotate_if_needed() -> None:
    """Size-triggered rotation. Called from log_event with _LOCK already held."""
    if _MAX_MB <= 0:
        return
    try:
        if os.path.getsize(_EVENTS_FILE) >= _MAX_MB * 1024 * 1024:
            dest = _do_rotate()
            if dest:
                print(f" * log rotated -> {os.path.basename(dest)}", flush=True)
    except OSError:
        pass


def rotate_events() -> str | None:
    """Archive the current log and begin a new one. Returns the archive name."""
    with _LOCK:
        dest = _do_rotate()
    return os.path.basename(dest) if dest else None


def clear_events(archive: bool = True) -> str | None:
    """Wipe the live log. With archive=True the old one is kept under archive/."""
    with _LOCK:
        dest = _do_rotate() if archive else None
        if not archive:
            try:
                os.remove(_EVENTS_FILE)
            except OSError:
                pass
        open(_EVENTS_FILE, "w", encoding="utf-8").close()
    return os.path.basename(dest) if dest else None


def list_archives() -> list[dict]:
    """Archived logs, newest first."""
    if not os.path.isdir(_ARCHIVE_DIR):
        return []
    out = []
    for name in os.listdir(_ARCHIVE_DIR):
        if not name.endswith(".jsonl"):
            continue
        full = os.path.join(_ARCHIVE_DIR, name)
        try:
            st = os.stat(full)
        except OSError:
            continue
        out.append({"name": name, "bytes": st.st_size,
                    "events": _count_lines(full),
                    "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()})
    out.sort(key=lambda a: a["name"], reverse=True)
    return out


def archive_path(name: str) -> str | None:
    """Resolve an archive file name safely (no traversal out of archive/)."""
    if not name.endswith(".jsonl") or "/" in name or "\\" in name or name.startswith("."):
        return None
    full = os.path.abspath(os.path.join(_ARCHIVE_DIR, name))
    if os.path.dirname(full) != os.path.abspath(_ARCHIVE_DIR) or not os.path.exists(full):
        return None
    return full


def delete_archive(name: str) -> bool:
    full = archive_path(name)
    if not full:
        return False
    try:
        os.remove(full)
        return True
    except OSError:
        return False


def log_stats() -> dict:
    """Size / event count of the live log plus the archive listing."""
    try:
        size = os.path.getsize(_EVENTS_FILE)
    except OSError:
        size = 0
    archives = list_archives()
    return {
        "bytes": size,
        "events": _count_lines(_EVENTS_FILE),
        "max_mb": _MAX_MB,
        "archives": archives,
        "archive_bytes": sum(a["bytes"] for a in archives),
    }
