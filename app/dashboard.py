# -*- coding: utf-8 -*-
"""
Monitoring dashboard (Blueprint mounted at /_monitor) — the defender's SOC view.

Locked behind HTTP Basic auth (see security.monitor_guard). It fuses two streams
per source IP:
  * request telemetry  — hits, attacks, techniques, timeline, payloads;
  * device intelligence — the /_collect browser fingerprint (OS, browser, GPU,
    screen, timezone, private IPs, bot markers, optional GPS).

On top of the raw streams it derives three things a SOC analyst actually wants:
  * a per-attacker THREAT SCORE (0-100) with human-readable reasons;
  * ACTOR CORRELATION — the same device fingerprint seen from several IPs, which
    is how you catch one operator rotating through a VPN / proxy pool;
  * a KILL-CHAIN — the ordered sequence of everything one IP did, reconstructed
    from the event log (great material for the final report).

APIs (all auth-gated):
  /_monitor/api/stats  ·  /_monitor/api/events  ·  /_monitor/api/intel  ·
  /_monitor/api/session?ip=…  ·  /_monitor/api/export.csv
"""

import csv
import hashlib
import hmac
import io
import os
import threading
from collections import Counter, defaultdict

from flask import (Blueprint, render_template, jsonify, request, Response,
                   send_file)

from . import logger, security

# Cap how many recent events the aggregation walks. Beyond this the dashboard
# would spend all its time re-parsing history it already summarised, and the
# page polls every 5s. Raise it if you need a longer window in one view.
try:
    STATS_MAX_EVENTS = int(os.environ.get("HONEYPOT_STATS_MAX", 20000))
except ValueError:
    STATS_MAX_EVENTS = 20000

dashboard_bp = Blueprint("dashboard", __name__, template_folder="templates")


@dashboard_bp.before_request
def _require_auth():
    return security.monitor_guard()


@dashboard_bp.after_request
def _no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp


# --- user-agent parsing + bot scoring ----------------------------------------

_OS = [("Windows NT 10.0", "Windows 10/11"), ("Windows NT 6.3", "Windows 8.1"),
       ("Windows NT 6.1", "Windows 7"), ("Windows", "Windows"), ("Android", "Android"),
       ("iPhone", "iOS"), ("iPad", "iPadOS"), ("Mac OS X", "macOS"),
       ("CrOS", "ChromeOS"), ("Linux", "Linux")]
_BR = [("Edg/", "Edge"), ("OPR/", "Opera"), ("SamsungBrowser", "Samsung"),
       ("Chrome/", "Chrome"), ("Firefox/", "Firefox"), ("Version/", "Safari"),
       ("curl/", "curl"), ("Wget", "wget"), ("python-requests", "python-requests"),
       ("python", "python"), ("sqlmap", "sqlmap"), ("Nmap", "Nmap"),
       ("Nikto", "Nikto"), ("masscan", "masscan"), ("Go-http", "Go-http"),
       ("Java/", "Java"), ("HeadlessChrome", "HeadlessChrome")]
_TOOLS = ("sqlmap", "nikto", "nmap", "masscan", "curl", "wget", "python", "go-http",
          "java/", "headless", "scrapy", "httpclient", "zgrab")

# Which event types count as active reconnaissance / probing of the trap.
_PROBE_EVENTS = {"admin_probe", "secret_probe", "path_probe", "error_page",
                 "viewstate_tamper"}

# Severity -> numeric weight used by the threat score.
_SEVW = {"low": 1, "medium": 2, "high": 4}
_SEV_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}

# Defensive context for each technique (shown in the UI / report).
TECH_INFO = {
    "sqli": "SQL Injection — حقن قاعدة البيانات",
    "xss": "Cross-Site Scripting — حقن سكربت",
    "lfi": "Local File Inclusion / Path Traversal — قراءة ملفات",
    "cmdi": "Command Injection — تنفيذ أوامر نظام",
    "ssti": "Server-Side Template Injection",
    "lfi_rce_upload": "Web-shell / رفع ملف خبيث",
    "scanner": "أداة فحص آلية (sqlmap / nikto / curl …)",
    "ids": "تنبيه Suricata — كشف على طبقة الشبكة",
    "brute_force": "تخمين بيانات الدخول (SSH / FTP / HTTP)",
}


def _pick(ua, table):
    for pat, name in table:
        if pat.lower() in ua.lower():
            return name
    return "Unknown"


def parse_ua(ua):
    return _pick(ua, _OS), _pick(ua, _BR)


# The ORDER and SET of HTTP headers a client sends is characteristic of the
# browser/library that built the request, and page JavaScript cannot forge it.
# It is therefore an independent cross-check on the JS fingerprint: a client
# claiming to be Chrome while sending python-requests' header order is caught
# here even if every navigator.* property was spoofed.
_HDR_IGNORE = {"cookie", "content-length", "authorization", "referer"}


def header_signature(headers):
    if not headers:
        return None, []
    names = [k.lower() for k in headers.keys() if k.lower() not in _HDR_IGNORE]
    return hashlib.sha256("|".join(names).encode()).hexdigest()[:12], names


def _looks_like_tool(ua):
    u = (ua or "").lower()
    return any(t in u for t in _TOOLS) or u.strip() == ""


# --- threat scoring ----------------------------------------------------------

def _threat(rec, is_bot, multi_ip):
    """Turn one aggregated attacker record into a 0-100 score + reasons.

    Deliberately simple and explainable: every point added is justified by one
    line below, so the score can be defended in a viva and read in the report.
    """
    score, why = 0, []

    sw = rec["sev_weight"]
    if sw:
        pts = min(45, sw * 3)
        score += pts
        why.append(f"{rec['attacks']} محاولة هجوم (وزن خطورة {sw})")

    nh = len(rec["high_techs"])
    if nh:
        score += min(20, nh * 7)
        why.append(f"{nh} تقنية عالية الخطورة: " + "، ".join(sorted(rec["high_techs"])))

    if is_bot:
        score += 12
        why.append("أدوات/أتمتة مكتشفة (بوت)")

    breadth = len(rec["paths"])
    if breadth >= 8:
        score += min(10, breadth // 3)
        why.append(f"استطلاع واسع — {breadth} مسار مختلف")

    probes = sum(rec["event_types"].get(e, 0) for e in _PROBE_EVENTS)
    if probes >= 3:
        score += min(8, probes // 3)
        why.append(f"{probes} محاولة على مسارات الطُعم/الأخطاء")

    ids_alerts = rec["event_types"].get("ids_alert", 0)
    if ids_alerts:
        info = rec["ids_info"]
        real = ids_alerts - info
        score += min(10, 2 + ids_alerts // 4)
        if real:
            why.append(f"{real} تنبيه Suricata مؤثّر"
                       + (f" و{info} معلوماتي" if info else ""))
        else:
            why.append(f"{info} تنبيه Suricata معلوماتي (وزن مخفّض)")
    # Two independent sensors agreeing is a far stronger signal than either one
    # alone: the network saw it on the wire AND the app saw the payload.
    if ids_alerts and (rec["attacks"] - ids_alerts) > 0:
        score += 10
        why.append("تأكيد مزدوج — كشف شبكي (Suricata) + كشف تطبيقي لنفس العنوان")

    if rec["event_types"].get("viewstate_tamper"):
        score += 6
        why.append("تجاوز نموذج الدخول (تلاعب __VIEWSTATE)")

    if multi_ip:
        score += 12
        why.append("نفس بصمة الجهاز من عدة عناوين IP (تدوير/VPN/بروكسي)")

    score = min(100, score)
    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 15:
        level = "medium"
    else:
        level = "low"
    return score, level, why


# --- aggregation -------------------------------------------------------------

def aggregate(events):
    by_ip = defaultdict(lambda: {
        "hits": 0, "attacks": 0, "categories": Counter(), "event_types": Counter(),
        "first_seen": None, "last_seen": None, "user_agents": set(),
        "paths": Counter(), "payloads": [], "intel": None, "geo": None,
        "sev_weight": 0, "high_techs": set(), "max_sev": "none", "ids_info": 0,
        "header_sigs": set(), "header_names": None, "creds": [], "sqls": [],
        "ids_sigs": Counter(), "methods": Counter(), "statuses": Counter(),
        "breach": False, "cmds": []})
    cat_tot, etype_tot, timeline = Counter(), Counter(), Counter()
    sev_timeline = defaultdict(lambda: Counter())
    creds_all, sql_all = Counter(), []
    paths_all, ids_sig_all = Counter(), Counter()
    os_dist, br_dist, tz_dist, country_dist = Counter(), Counter(), Counter(), Counter()
    hw_to_ips = defaultdict(set)

    for ev in events:
        ip = ev.get("src_ip", "?")
        r = by_ip[ip]
        r["hits"] += 1
        ts = ev.get("ts")
        if ts:
            r["first_seen"] = ts if not r["first_seen"] else min(r["first_seen"], ts)
            r["last_seen"] = ts if not r["last_seen"] else max(r["last_seen"], ts)
            timeline[ts[:16]] += 1                      # per-minute bucket
        ua = ev.get("user_agent", "")
        if ua:
            r["user_agents"].add(ua)
        et = ev.get("event_type", "request")
        r["event_types"][et] += 1
        etype_tot[et] += 1
        if ev.get("path"):
            r["paths"][ev["path"]] += 1
            paths_all[ev["path"]] += 1
        if ev.get("method"):
            r["methods"][ev["method"]] += 1
        hsig, hnames = header_signature(ev.get("headers"))
        if hsig:
            r["header_sigs"].add(hsig)
            if r["header_names"] is None:
                r["header_names"] = hnames
        if ev.get("findings"):
            r["attacks"] += 1
            for f in ev["findings"]:
                cat, sev = f["category"], f.get("severity", "low")
                r["categories"][cat] += 1
                cat_tot[cat] += 1
                # Informational IDS chatter (Suricata severity 3) is volume, not
                # intent: 60 "SSH connection detected" lines are not 60 attacks.
                # Counting them like app-layer payloads pushed harmless hosts to
                # "critical". They are scored separately, and capped, below.
                if cat == "ids" and sev == "low":
                    r["ids_info"] += 1
                else:
                    r["sev_weight"] += _SEVW.get(sev, 1)
                if sev == "high":
                    r["high_techs"].add(cat)
                if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(r["max_sev"], 0):
                    r["max_sev"] = sev
                r["payloads"].append({"cat": cat, "field": f.get("field"),
                                      "payload": f.get("payload"), "sev": sev, "ts": ts})
                if ts:
                    sev_timeline[ts[:16]][sev] += 1
        ex = ev.get("extra") or {}
        if et == "login_attempt":
            u, pw = ex.get("username"), ex.get("password")
            if u is not None:
                creds_all[(str(u)[:80], str(pw or "")[:80])] += 1
                r["creds"].append({"u": str(u)[:80], "p": str(pw or "")[:80], "ts": ts})
            if ex.get("executed_sql") and len(r["sqls"]) < 25:
                r["sqls"].append({"sql": str(ex["executed_sql"])[:400], "ts": ts,
                                  "rows": ex.get("rows_returned"), "err": ex.get("db_error")})
            if ex.get("executed_sql") and len(sql_all) < 200:
                sql_all.append({"ip": ip, "sql": str(ex["executed_sql"])[:400], "ts": ts,
                                "rows": ex.get("rows_returned")})
        if et == "weak_cred_success":
            r["breach"] = True
            r["creds"].append({"u": str(ex.get("username"))[:80],
                               "p": str(ex.get("password") or "")[:80], "ts": ts,
                               "svc": "http", "ok": True})
        if et in ("ssh_login", "ftp_login") and ex.get("username") is not None:
            creds_all[(str(ex.get("username"))[:80], str(ex.get("password") or "")[:80])] += 1
            r["creds"].append({"u": str(ex.get("username"))[:80],
                               "p": str(ex.get("password") or "")[:80], "ts": ts,
                               "svc": ex.get("service"), "ok": ex.get("success")})
            if ex.get("success"):
                r["breach"] = True
        if et == "ssh_command" and ex.get("command"):
            r.setdefault("cmds", []).append({"cmd": str(ex["command"])[:200], "ts": ts})
        if et == "ids_alert" and ex.get("signature"):
            r["ids_sigs"][ex["signature"]] += 1
            ids_sig_all[ex["signature"]] += 1
        if et == "client_intel":
            if ex.get("geo"):
                r["geo"] = ex["geo"]
            if ex.get("ua") or ex.get("fpId"):          # the full fingerprint beacon
                r["intel"] = ex

    # Actor correlation, two ways. fpId catches the same browser on a new
    # network. The hardware component hash (canvas + GPU + audio + screen)
    # survives a browser change or a fresh profile, so it also catches the same
    # machine deliberately switching browsers to look like a different visitor.
    fp_to_ips = defaultdict(set)
    for ip, r in by_ip.items():
        intel = r["intel"] or {}
        fp = intel.get("fpId")
        if fp:
            fp_to_ips[fp].add(ip)
        hw = (intel.get("components") or {}).get("hw")
        if hw:
            hw_to_ips[hw].add(ip)

    attackers = []
    for ip, r in by_ip.items():
        ua_main = sorted(r["user_agents"])[0] if r["user_agents"] else ""
        intel = r["intel"] or {}
        os_, br = parse_ua(intel.get("ua", ua_main))
        bot_marks = list(intel.get("botMarks") or [])
        # A source known only from IDS alerts never sent us an HTTP request, so
        # it has no User-Agent to judge. Treating that absence as the "empty UA"
        # bot marker labelled every network-only host a bot.
        app_hits = r["hits"] - r["event_types"].get("ids_alert", 0)
        if ua_main:
            if _looks_like_tool(ua_main):
                bot_marks.append("tool-ua")
        elif app_hits:
            bot_marks.append("tool-ua")        # spoke HTTP but sent no UA at all
        is_bot = bool(bot_marks)
        gpu = (intel.get("webgl") or {}).get("renderer")

        fp = intel.get("fpId")
        comps = intel.get("components") or {}
        also_seen = sorted(fp_to_ips.get(fp, set()) - {ip}) if fp else []
        hw_siblings = sorted(hw_to_ips.get(comps.get("hw"), set()) - {ip}) if comps.get("hw") else []
        multi_ip = bool(also_seen or hw_siblings)
        threat, level, factors = _threat(r, is_bot, multi_ip)

        spoof = [m[6:] for m in bot_marks if m.startswith("spoof:")]
        os_dist[os_] += 1
        br_dist[br] += 1
        if intel.get("timezone"):
            tz_dist[intel["timezone"]] += 1
            country_dist[str(intel["timezone"]).split("/")[0]] += 1

        attackers.append({
            "ip": ip, "hits": r["hits"], "attacks": r["attacks"],
            "categories": dict(r["categories"]), "event_types": dict(r["event_types"]),
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "user_agents": sorted(r["user_agents"]),
            "top_paths": r["paths"].most_common(6),
            "payloads": r["payloads"][:12],
            "max_sev": r["max_sev"],
            "threat": threat, "threat_level": level, "threat_factors": factors,
            "also_seen_ips": also_seen,
            "os": os_, "browser": br, "gpu": gpu,
            "is_bot": is_bot, "bot_marks": sorted(set(bot_marks)),
            "fpId": fp,
            "timezone": intel.get("timezone"), "locale": intel.get("locale"),
            "localIPs": intel.get("localIPs") or [],
            "screen": intel.get("screen"), "cores": intel.get("cores"),
            "memory": intel.get("memory"), "platform": intel.get("platform"),
            "languages": intel.get("languages"), "connection": intel.get("connection"),
            "canvas": intel.get("canvas"), "fonts": intel.get("fonts"),
            "battery": intel.get("battery"), "geo": r["geo"],
            # --- deeper fingerprint surface ---
            "components": comps,
            "hw_siblings": hw_siblings,
            "spoof_marks": spoof,
            "audio": (intel.get("audio") or {}).get("hash"),
            "webgpu": intel.get("webgpu"),
            "webgl_full": intel.get("webgl"),
            "math": intel.get("math"),
            "codecs": (intel.get("codecs") or {}).get("matrix"),
            "voices": intel.get("voices"),
            "media_devices": intel.get("mediaDevices"),
            "permissions": intel.get("permissions"),
            "storage": intel.get("storage"),
            "css_prefs": intel.get("css"),
            "ua_hints": intel.get("uaHints"),
            "tz_dst": intel.get("tzDst"),
            "window": intel.get("window"),
            "touch": intel.get("touch"),
            "plugins": intel.get("plugins"),
            "header_sig": sorted(r["header_sigs"])[0] if r["header_sigs"] else None,
            "header_names": r["header_names"] or [],
            "header_sig_count": len(r["header_sigs"]),
            "methods": dict(r["methods"]),
            "creds": r["creds"][:20],
            "sqls": r["sqls"][:10],
            "ids_sigs": dict(r["ids_sigs"].most_common(8)),
            "breach": r["breach"],
            "shell_cmds": r["cmds"][:40],
            "intel": intel,
        })
    attackers.sort(key=lambda a: (a["threat"], a["attacks"], a["hits"]), reverse=True)

    correlated = [{"fpId": fp, "ips": sorted(ips)}
                  for fp, ips in fp_to_ips.items() if len(ips) > 1]
    hw_correlated = [{"hw": hw, "ips": sorted(ips)}
                     for hw, ips in hw_to_ips.items() if len(ips) > 1]

    return {
        "total_events": len(events),
        "total_attackers": len(by_ip),
        "total_attacks": sum(a["attacks"] for a in attackers),
        "category_totals": dict(cat_tot),
        "event_type_totals": dict(etype_tot),
        "bots_detected": sum(1 for a in attackers if a["is_bot"]),
        "devices_fingerprinted": sum(1 for a in attackers if a["fpId"]),
        "critical_threats": sum(1 for a in attackers if a["threat_level"] in ("critical", "high")),
        "correlated_actors": correlated,
        "hw_correlated": hw_correlated,
        "spoofers": sum(1 for a in attackers if a["spoof_marks"]),
        "breaches": sum(1 for a in attackers if a.get("breach")),
        "brute_force_sources": sum(1 for a in attackers if "brute_force" in a["categories"]),
        "tech_info": TECH_INFO,
        "timeline": dict(sorted(timeline.items())),
        "sev_timeline": {k: dict(v) for k, v in sorted(sev_timeline.items())},
        "top_paths": paths_all.most_common(15),
        "credentials": [{"user": u, "pass": p, "count": c}
                        for (u, p), c in creds_all.most_common(25)],
        "sql_payloads": sql_all[-25:],
        "ids_signatures": ids_sig_all.most_common(12),
        "os_distribution": dict(os_dist.most_common(8)),
        "browser_distribution": dict(br_dist.most_common(8)),
        "timezone_distribution": dict(tz_dist.most_common(12)),
        "region_distribution": dict(country_dist.most_common(10)),
        "attackers": attackers,
    }


# --- aggregation cache -------------------------------------------------------
# The log is append-only, so (size, mtime) is a sound cache key: if neither
# moved, nothing was written and the previous roll-up is still exact. Without
# this the dashboard re-parsed the whole log twice every 5 seconds.

_CACHE = {"key": None, "data": None}
_CACHE_LOCK = threading.Lock()


def _log_key():
    try:
        st = os.stat(logger.events_path())
        return (st.st_size, st.st_mtime_ns)
    except OSError:
        return (0, 0)


def cached_aggregate():
    key = _log_key()
    with _CACHE_LOCK:
        if _CACHE["key"] == key and _CACHE["data"] is not None:
            return _CACHE["data"]
    data = aggregate(logger.read_events(limit=STATS_MAX_EVENTS))
    with _CACHE_LOCK:
        _CACHE["key"], _CACHE["data"] = key, data
    return data


def _bust_cache():
    with _CACHE_LOCK:
        _CACHE["key"], _CACHE["data"] = None, None


# --- destructive-action guard -------------------------------------------------
# Basic-auth credentials ride along automatically on cross-site requests, so
# auth alone would let a page the attacker controls trigger a log wipe (CSRF).
# Every destructive call therefore needs POST plus a token that is only readable
# by someone who actually rendered the dashboard.

def admin_token() -> str:
    return hmac.new(security.SECRET.encode(), b"monitor-admin-v1",
                    hashlib.sha256).hexdigest()[:32]


def _bad_token():
    if not hmac.compare_digest(request.headers.get("X-Admin-Token", ""), admin_token()):
        return jsonify({"error": "missing or invalid admin token"}), 403
    return None


@dashboard_bp.route("/")
def home():
    return render_template("dashboard.html", admin_token=admin_token())


@dashboard_bp.route("/api/stats")
def api_stats():
    return jsonify(cached_aggregate())


@dashboard_bp.route("/api/notify")
def api_notify():
    """Alerting engine state — answers "why did I not get a Telegram alert?"."""
    from . import notify
    return jsonify(notify.status())


@dashboard_bp.route("/api/services")
def api_services():
    from . import services
    return jsonify(services.status())


# --- log management ----------------------------------------------------------

@dashboard_bp.route("/api/logs")
def api_logs():
    """Live-log size / event count plus the archive listing."""
    return jsonify(logger.log_stats())


@dashboard_bp.route("/api/logs/rotate", methods=["POST"])
def api_logs_rotate():
    bad = _bad_token()
    if bad:
        return bad
    name = logger.rotate_events()
    _bust_cache()
    return jsonify({"ok": True, "archived": name,
                    "message": "تمت الأرشفة" if name else "لا يوجد ما يُؤرشف"})


@dashboard_bp.route("/api/logs/clear", methods=["POST"])
def api_logs_clear():
    """Empty the live log. Archives it first unless archive=0 is passed."""
    bad = _bad_token()
    if bad:
        return bad
    keep = request.args.get("archive", "1") != "0"
    name = logger.clear_events(archive=keep)
    _bust_cache()
    return jsonify({"ok": True, "archived": name})


@dashboard_bp.route("/api/logs/archive/<name>")
def api_logs_download(name):
    full = logger.archive_path(name)
    if not full:
        return jsonify({"error": "not found"}), 404
    return send_file(full, as_attachment=True, download_name=name,
                     mimetype="application/x-ndjson")


@dashboard_bp.route("/api/logs/archive/<name>", methods=["DELETE"])
def api_logs_delete(name):
    bad = _bad_token()
    if bad:
        return bad
    return jsonify({"ok": logger.delete_archive(name)})


@dashboard_bp.route("/api/events")
def api_events():
    limit = request.args.get("limit", 300, type=int)
    return jsonify(logger.read_events(limit=limit))


@dashboard_bp.route("/api/intel")
def api_intel():
    data = cached_aggregate()
    return jsonify([a for a in data["attackers"] if a["fpId"] or a["geo"]])


@dashboard_bp.route("/api/session")
def api_session():
    """Kill-chain for one IP: every event it generated, in chronological order."""
    ip = request.args.get("ip", "")
    if not ip:
        return jsonify([])
    out = []
    for ev in logger.read_events():                     # newest-first
        if ev.get("src_ip") != ip:
            continue
        ex = ev.get("extra") or {}
        out.append({
            "ts": ev.get("ts"),
            "event_type": ev.get("event_type", "request"),
            "method": ev.get("method"),
            "path": ev.get("path"),
            "findings": [{"category": f["category"], "payload": f.get("payload"),
                          "severity": f.get("severity")} for f in (ev.get("findings") or [])],
            "username": ex.get("username"),
            "executed_sql": ex.get("executed_sql"),
        })
    out.reverse()                                        # -> chronological
    return jsonify(out[-400:])


@dashboard_bp.route("/api/export.csv")
def api_export_csv():
    """Flat per-attacker summary for the report / spreadsheet."""
    data = cached_aggregate()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "threat", "threat_level", "hits", "attacks", "techniques",
                "os", "browser", "gpu", "timezone", "locale", "local_ips",
                "is_bot", "bot_marks", "also_seen_ips", "first_seen", "last_seen"])
    for a in data["attackers"]:
        w.writerow([
            a["ip"], a["threat"], a["threat_level"], a["hits"], a["attacks"],
            " ".join(f"{k}:{v}" for k, v in a["categories"].items()),
            a["os"], a["browser"], a["gpu"] or "", a["timezone"] or "",
            a["locale"] or "", " ".join(a["localIPs"]), a["is_bot"],
            " ".join(a["bot_marks"]), " ".join(a["also_seen_ips"]),
            a["first_seen"] or "", a["last_seen"] or "",
        ])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=attackers.csv"})
