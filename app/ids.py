# -*- coding: utf-8 -*-
"""
Suricata EVE ingestion — fuses network-layer IDS alerts into the honeypot log.

Suricata writes newline-delimited JSON to eve.json. Every record carries a
`src_ip`, and so does every honeypot event, which is the whole trick: normalise
an alert into the honeypot's own event shape and dashboard.aggregate() groups it
under the same attacker automatically. One row then shows what the network
sensor saw AND what the application saw, under a single threat score.

Two front-ends, one normaliser:

  * import_file()  — replay an existing capture (keeps each alert's own
                     timestamp, so the timeline stays truthful);
  * start_tailer() — follow a live eve.json from a background thread.

DIRECTION MATTERS. A sensor logs the box it runs on too: `apt update` from the
honeypot VM trips "ET INFO GNU/Linux APT User-Agent Outbound", and ingesting
that blindly makes your own host the top-scoring attacker. SURICATA_HOME_NET
lists the addresses that are *us*; alerts sourced from there are skipped.

Config (env, then NAME_FILE, then .env — see app/config.py):
  SURICATA_EVE        path to eve.json                 (enables the live tailer)
  SURICATA_HOME_NET   comma list of IPs/CIDRs that are the honeypot itself
  SURICATA_INGEST_ALL 1 = keep self-sourced alerts too (noisy; off by default)
  SURICATA_MIN_SEV    drop alerts weaker than this Suricata severity (1 = worst)

CLI:
  python -m app.ids --stats  eve.json      # what is in there, and what gets cut
  python -m app.ids --import eve.json      # replay it into the honeypot log
  python -m app.ids --tail   eve.json      # follow it live
"""

import ipaddress
import json
import os
import threading
import time

from . import config, logger

def cfg(name, default=""):
    """Resolve one setting via the central loader (env, NAME_FILE, .env)."""
    return config.get(name, default)


EVE_PATH = cfg("SURICATA_EVE")
_OFFSET_FILE = os.path.join(os.path.dirname(logger.events_path()), ".suricata_offset.json")

# Suricata severity is inverted: 1 is the most severe.
_SEV = {1: "high", 2: "medium", 3: "low"}

# Map a signature onto the honeypot's own taxonomy when it is unambiguous, so a
# Suricata SQLi hit and a detectors.py SQLi hit land in the same bucket. Anything
# else stays a plain "ids" finding rather than being force-fitted.
_SIG_MAP = [
    (("sql injection", "sqli", "union select"), "sqli"),
    (("cross site scripting", "cross-site scripting", "xss"), "xss"),
    (("directory traversal", "path traversal", "file inclusion", "lfi"), "lfi"),
    (("command injection", "shellshock", "remote code execution"), "cmdi"),
    (("nmap", "nikto", "sqlmap", "masscan", "dirbuster", "gobuster",
      "port scan", "portscan", "scan"), "scanner"),
    (("web shell", "webshell", "backdoor"), "lfi_rce_upload"),
]


def _flag(name):
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")


def _parse_nets(raw):
    nets = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass
    return nets


HOME_NET = _parse_nets(cfg("SURICATA_HOME_NET"))
INGEST_ALL = str(cfg("SURICATA_INGEST_ALL", "0")).lower() in ("1", "true", "yes", "on")
try:
    MIN_SEV = int(cfg("SURICATA_MIN_SEV", 3))
except ValueError:
    MIN_SEV = 3


def _in_nets(ip, nets):
    if not ip or not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _norm_ts(ts):
    """Suricata writes +0000; the honeypot log uses +00:00. Align them so the
    dashboard can sort and bucket both streams as plain strings."""
    if not ts:
        return None
    if len(ts) >= 5 and ts[-5] in "+-" and ts[-3] != ":":
        return ts[:-2] + ":" + ts[-2:]
    return ts


def _category_for(signature):
    low = (signature or "").lower()
    for needles, cat in _SIG_MAP:
        if any(nd in low for nd in needles):
            return cat
    return "ids"


def normalize_alert(rec, home_net=None, ingest_all=None, min_sev=None):
    """Turn one EVE alert record into log_event(**kwargs), or None to skip it."""
    if rec.get("event_type") != "alert":
        return None
    alert = rec.get("alert") or {}
    sig = alert.get("signature") or "IDS alert"
    sev_num = alert.get("severity", 3)
    home_net = HOME_NET if home_net is None else home_net
    ingest_all = INGEST_ALL if ingest_all is None else ingest_all
    min_sev = MIN_SEV if min_sev is None else min_sev

    if isinstance(sev_num, int) and sev_num > min_sev:
        return None

    src = rec.get("src_ip") or "?"
    dst = rec.get("dest_ip") or ""
    # Self-sourced traffic is the sensor host talking, not an attacker.
    if not ingest_all and _in_nets(src, home_net):
        return None
    if src in ("0.0.0.0", "::"):
        return None

    severity = _SEV.get(sev_num, "low")
    category = _category_for(sig)
    http = rec.get("http") or {}
    proto = rec.get("proto") or "IDS"
    port = rec.get("dest_port")

    if http.get("url"):
        path = http["url"]
    elif port:
        path = "%s:%s" % (dst, port)
    else:
        path = dst or "-"

    headers = {}
    if http.get("http_user_agent"):
        headers["User-Agent"] = http["http_user_agent"]
    if http.get("hostname"):
        headers["Host"] = http["hostname"]

    finding = {
        "category": category,
        "field": "suricata:" + (alert.get("category") or "uncategorised"),
        "payload": sig,
        "severity": severity,
    }
    extra = {
        "ids": "suricata",
        "signature": sig,
        "signature_id": alert.get("signature_id"),
        "rev": alert.get("rev"),
        "suricata_category": alert.get("category") or "",
        "suricata_severity": sev_num,
        "action": alert.get("action"),
        "proto": proto,
        "src_port": rec.get("src_port"),
        "dest_ip": dst,
        "dest_port": port,
        "in_iface": rec.get("in_iface"),
        "flow_id": rec.get("flow_id"),
        "app_proto": rec.get("app_proto"),
        "direction": rec.get("direction"),
    }
    for key in ("http", "ssh", "tls", "dns"):
        if rec.get(key):
            extra[key] = rec[key]

    return {
        "remote_addr": src,
        "method": http.get("http_method") or proto,
        "path": path,
        "query": {},
        "form": {},
        "headers": headers,
        "findings": [finding],
        "event_type": "ids_alert",
        "extra": extra,
        "ts": _norm_ts(rec.get("timestamp")),
    }


# --- offset bookkeeping (so a re-import does not duplicate events) -----------

def _load_offsets():
    try:
        with open(_OFFSET_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_offset(path, offset, size):
    data = _load_offsets()
    data[os.path.abspath(path)] = {"offset": offset, "size": size}
    tmp = _OFFSET_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, _OFFSET_FILE)
    except OSError:
        pass


def _get_offset(path):
    rec = _load_offsets().get(os.path.abspath(path))
    if not rec:
        return 0
    try:
        if os.path.getsize(path) < rec.get("size", 0):
            return 0                      # file shrank -> rotated, start over
    except OSError:
        return 0
    return rec.get("offset", 0)


# --- ingestion ---------------------------------------------------------------

def ingest_stream(fh, **opts):
    """Read EVE lines from an open file object and log every kept alert."""
    kept = skipped = broken = 0
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            broken += 1
            continue
        if rec.get("event_type") != "alert":
            continue
        kwargs = normalize_alert(rec, **opts)
        if kwargs is None:
            skipped += 1
            continue
        logger.log_event(quiet=True, **kwargs)
        kept += 1
    return {"kept": kept, "skipped": skipped, "unparseable": broken}


def import_file(path, resume=True, **opts):
    """Replay a capture into the honeypot log, once. Returns a count summary."""
    start = _get_offset(path) if resume else 0
    size = os.path.getsize(path)
    if start >= size:
        return {"kept": 0, "skipped": 0, "unparseable": 0, "note": "already imported"}
    with open(path, encoding="utf-8", errors="replace") as fh:
        fh.seek(start)
        stats = ingest_stream(fh, **opts)
        end = fh.tell()
    _save_offset(path, end, size)
    stats["from_offset"] = start
    stats["to_offset"] = end
    return stats


def tail_eve(path, poll=2.0, stop=None, **opts):
    """Follow a live eve.json forever, logging alerts as they appear."""
    offset = _get_offset(path)
    while stop is None or not stop.is_set():
        try:
            size = os.path.getsize(path)
            if size < offset:                     # rotated
                offset = 0
            if size > offset:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    ingest_stream(fh, **opts)
                    offset = fh.tell()
                _save_offset(path, offset, size)
        except OSError:
            pass
        time.sleep(poll)


_tailer = None


def start_tailer():
    """Start the live tailer if SURICATA_EVE points at a readable file.

    Call this AFTER any fork (gunicorn --preload imports the app in the master
    and then forks; a thread started at import time would not survive that).
    """
    global _tailer
    if _tailer is not None or not EVE_PATH or not os.path.exists(EVE_PATH):
        return False
    _tailer = threading.Thread(target=tail_eve, args=(EVE_PATH,),
                               daemon=True, name="suricata-tail")
    _tailer.start()
    print(" * Suricata tailer following %s" % EVE_PATH, flush=True)
    return True


# --- CLI ---------------------------------------------------------------------

def _stats(path):
    from collections import Counter
    sig, cat, sev = Counter(), Counter(), Counter()
    src, dst = Counter(), Counter()
    total = broken = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                broken += 1
                continue
            if rec.get("event_type") != "alert":
                continue
            total += 1
            a = rec.get("alert") or {}
            sig[a.get("signature")] += 1
            cat[a.get("category") or "(none)"] += 1
            sev[a.get("severity")] += 1
            src[rec.get("src_ip")] += 1
            dst[rec.get("dest_ip")] += 1
    print("alerts: %d   (unparseable lines: %d)" % (total, broken))
    print()
    print("severity : " + ", ".join("%s=%s (%s)" % (k, v, _SEV.get(k, "low"))
                                    for k, v in sorted(sev.items())))
    print()
    print("top sources (candidate attackers):")
    for ip, n in src.most_common(8):
        print("   %-18s %5d" % (ip, n))
    print()
    print("top destinations (the watched box is usually the top one):")
    for ip, n in dst.most_common(8):
        print("   %-18s %5d" % (ip, n))
    print()
    print("top signatures:")
    for s, n in sig.most_common(10):
        print("   %5d  %s" % (n, s))
    top_dst = dst.most_common(1)
    if top_dst:
        print()
        print("suggested:  SURICATA_HOME_NET=%s" % top_dst[0][0])
        print("            (alerts SOURCED from there are the sensor host itself)")


def main(argv=None):
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    mode = "--stats"
    for m in ("--stats", "--import", "--tail"):
        if m in argv:
            mode = m
            argv.remove(m)
    home = None
    for arg in list(argv):
        if arg.startswith("--home-net="):
            home = _parse_nets(arg.split("=", 1)[1])
            argv.remove(arg)
    fresh = "--no-resume" in argv
    if fresh:
        argv.remove("--no-resume")
    path = argv[0] if argv else EVE_PATH
    if not path or not os.path.exists(path):
        print("usage: python -m app.ids [--stats|--import|--tail] "
              "[--home-net=IP/CIDR] [--no-resume] eve.json")
        return 2
    opts = {} if home is None else {"home_net": home}
    if mode == "--stats":
        _stats(path)
    elif mode == "--import":
        print("importing %s ..." % path)
        st = import_file(path, resume=not fresh, **opts)
        print("  kept        %s" % st["kept"])
        print("  skipped     %s   (self-sourced / below min severity)" % st["skipped"])
        print("  unparseable %s" % st["unparseable"])
        if st.get("note"):
            print("  note: %s" % st["note"])
    else:
        print("tailing %s (ctrl-c to stop)" % path)
        tail_eve(path, **opts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
