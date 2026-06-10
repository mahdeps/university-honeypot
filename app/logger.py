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

os.makedirs(_LOG_DIR, exist_ok=True)


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
) -> dict:
    """Persist one event and echo a summary to the console. Returns the record."""
    record = {
        "ts": _now(),
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


def read_events(limit: int | None = None) -> list[dict]:
    """Load events back (newest first) for the dashboard."""
    if not os.path.exists(_EVENTS_FILE):
        return []
    with open(_EVENTS_FILE, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    events = []
    for ln in reversed(lines):
        ln = ln.strip()
        if not ln:
            continue
        try:
            events.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
        if limit and len(events) >= limit:
            break
    return events
