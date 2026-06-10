# -*- coding: utf-8 -*-
"""
Monitoring dashboard (Blueprint mounted at /_monitor) — the defender's SOC view.

Locked behind HTTP Basic auth (see security.monitor_guard). It fuses two streams
per source IP:
  * request telemetry  — hits, attacks, techniques, timeline, payloads;
  * device intelligence — the /_collect browser fingerprint (OS, browser, GPU,
    screen, timezone, private IPs, bot markers, optional GPS).

APIs (also auth-gated):  /_monitor/api/stats  ·  /_monitor/api/events  ·
                         /_monitor/api/intel
"""

import re
from collections import Counter, defaultdict

from flask import Blueprint, render_template, jsonify, request

from . import logger, security

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


def _pick(ua, table):
    for pat, name in table:
        if pat.lower() in ua.lower():
            return name
    return "Unknown"


def parse_ua(ua):
    return _pick(ua, _OS), _pick(ua, _BR)


def _looks_like_tool(ua):
    u = (ua or "").lower()
    return any(t in u for t in _TOOLS) or u.strip() == ""


# --- aggregation -------------------------------------------------------------

def aggregate(events):
    by_ip = defaultdict(lambda: {
        "hits": 0, "attacks": 0, "categories": Counter(), "event_types": Counter(),
        "first_seen": None, "last_seen": None, "user_agents": set(),
        "paths": Counter(), "payloads": [], "intel": None, "geo": None})
    cat_tot, etype_tot, timeline = Counter(), Counter(), Counter()

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
        if ev.get("findings"):
            r["attacks"] += 1
            for f in ev["findings"]:
                r["categories"][f["category"]] += 1
                cat_tot[f["category"]] += 1
                r["payloads"].append({"cat": f["category"], "field": f.get("field"),
                                      "payload": f.get("payload"), "ts": ts})
        ex = ev.get("extra") or {}
        if et == "client_intel":
            if ex.get("geo"):
                r["geo"] = ex["geo"]
            if ex.get("ua") or ex.get("fpId"):          # the full fingerprint beacon
                r["intel"] = ex

    attackers = []
    for ip, r in by_ip.items():
        ua_main = sorted(r["user_agents"])[0] if r["user_agents"] else ""
        intel = r["intel"] or {}
        os_, br = parse_ua(intel.get("ua", ua_main))
        bot_marks = list(intel.get("botMarks") or [])
        if _looks_like_tool(ua_main):
            bot_marks.append("tool-ua")
        gpu = (intel.get("webgl") or {}).get("renderer")
        attackers.append({
            "ip": ip, "hits": r["hits"], "attacks": r["attacks"],
            "categories": dict(r["categories"]), "event_types": dict(r["event_types"]),
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "user_agents": sorted(r["user_agents"]),
            "top_paths": r["paths"].most_common(6),
            "payloads": r["payloads"][-12:],
            "os": os_, "browser": br, "gpu": gpu,
            "is_bot": bool(bot_marks), "bot_marks": sorted(set(bot_marks)),
            "fpId": intel.get("fpId"),
            "timezone": intel.get("timezone"), "locale": intel.get("locale"),
            "localIPs": intel.get("localIPs") or [],
            "screen": intel.get("screen"), "cores": intel.get("cores"),
            "memory": intel.get("memory"), "platform": intel.get("platform"),
            "languages": intel.get("languages"), "connection": intel.get("connection"),
            "canvas": intel.get("canvas"), "fonts": intel.get("fonts"),
            "battery": intel.get("battery"), "geo": r["geo"],
            "intel": intel,
        })
    attackers.sort(key=lambda a: (a["attacks"], a["hits"]), reverse=True)

    return {
        "total_events": len(events),
        "total_attackers": len(by_ip),
        "total_attacks": sum(a["attacks"] for a in attackers),
        "category_totals": dict(cat_tot),
        "event_type_totals": dict(etype_tot),
        "bots_detected": sum(1 for a in attackers if a["is_bot"]),
        "devices_fingerprinted": sum(1 for a in attackers if a["fpId"]),
        "timeline": dict(sorted(timeline.items())),
        "attackers": attackers,
    }


@dashboard_bp.route("/")
def home():
    return render_template("dashboard.html")


@dashboard_bp.route("/api/stats")
def api_stats():
    return jsonify(aggregate(logger.read_events()))


@dashboard_bp.route("/api/events")
def api_events():
    limit = request.args.get("limit", 300, type=int)
    return jsonify(logger.read_events(limit=limit))


@dashboard_bp.route("/api/intel")
def api_intel():
    data = aggregate(logger.read_events())
    return jsonify([a for a in data["attackers"] if a["fpId"] or a["geo"]])
