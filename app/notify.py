# -*- coding: utf-8 -*-
"""
Telegram alerting for the honeypot — live alarms plus a periodic SOC report.

This subscribes to the honeypot's own event stream rather than tailing a sensor
log, which means one alarm path covers BOTH layers: application attacks caught
by detectors.py and network alerts ingested from Suricata by ids.py. Everything
is already keyed by src_ip, so an alert carries the attacker's full picture.

Why it is built the way it is:

  * NOTHING blocks the request path. Events are dropped on a bounded queue and a
    worker thread does the network I/O. A slow Telegram call can never delay the
    decoy or the dashboard.
  * ALERTS ARE DEDUPED AND ROLLED UP. One sqlmap run is thousands of events; sent
    naively that trips Telegram's per-chat flood limit, the API starts returning
    429, and the phone becomes unusable. Repeats of the same (ip, technique) are
    folded into one summary per cooldown window.
  * MESSAGES USE HTML, NOT MARKDOWN. Suricata signatures are full of underscores
    ("ET FILE_SHARING ...") and attacker payloads contain <, >, backticks and
    quotes. Legacy Markdown chokes on those, Telegram answers 400 and the alert
    is silently lost. HTML with html.escape() on every interpolated value is the
    only encoding that survives arbitrary attacker-controlled text.
  * REPUTATION LOOKUPS ARE CACHED AND OFF THE HOT PATH. AbuseIPDB's free tier is
    1000 checks/day; re-querying the same address per alert burns it in minutes.
  * SECRETS LIVE IN .env (gitignored dotfile) OR THE REAL ENVIRONMENT, resolved
    by app/config.py, which also supports NAME_FILE for container secrets.

Config keys (env, then NAME_FILE, then .env — see app/config.py):
  TELEGRAM_TOKEN        bot token from @BotFather              (required)
  TELEGRAM_CHAT_ID      recipient id, or a comma-separated list (required)
  TELEGRAM_CHAT_IDS     extra recipients, comma separated       (optional)
  TELEGRAM_SIGNATURE    footer line added to every message      (optional)
  ABUSEIPDB_KEY         enables IP reputation enrichment        (optional)
  TELEGRAM_MIN_SEVERITY low|medium|high  alert floor            (default: high)
  TELEGRAM_COOLDOWN     seconds before repeating an (ip,tech)   (default: 600)
  TELEGRAM_REPORT_EVERY minutes between reports, 0 = off        (default: 360)
  TELEGRAM_QUIET_IDS    1 = never alert on informational IDS    (default: 1)
  TELEGRAM_STARTUP      1 = announce start-up                   (default: 1)

CLI:
  python -m app.notify --test        send a test alert and exit
  python -m app.notify --report      send one report now and exit
  python -m app.notify --discover    list chats that have messaged the bot
  python -m app.notify --whoami      show bot identity and configured recipients
"""

import html
import ipaddress
import json
import os
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import config, logger

API = "https://api.telegram.org/bot%s/%s"


def cfg(name, default=""):
    """Resolve one setting: environment, then NAME_FILE, then .env, then default.

    See app/config.py for the full order and why it is that order.
    """
    return config.get(name, default)


def _ids(*names):
    """Collect recipient chat ids from several keys, de-duplicated, in order."""
    out = []
    for name in names:
        for part in str(cfg(name, "")).replace(";", ",").split(","):
            part = part.strip()
            if part and part not in out:
                out.append(part)
    return out


TOKEN = cfg("TELEGRAM_TOKEN")
CHAT_IDS = _ids("TELEGRAM_CHAT_ID", "TELEGRAM_CHAT_IDS")
CHAT_ID = CHAT_IDS[0] if CHAT_IDS else ""       # kept for compatibility
SIGNATURE = cfg("TELEGRAM_SIGNATURE")
ABUSE_KEY = cfg("ABUSEIPDB_KEY")


def _flag(name, default="1"):
    return config.flag(name, default)


def _num(name, default):
    return config.num(name, default)


_SEV_RANK = {"low": 1, "medium": 2, "high": 3}
MIN_SEVERITY = _SEV_RANK.get(str(cfg("TELEGRAM_MIN_SEVERITY", "high")).lower(), 3)
COOLDOWN = _num("TELEGRAM_COOLDOWN", 600)
REPORT_EVERY = _num("TELEGRAM_REPORT_EVERY", 360)
QUIET_IDS = _flag("TELEGRAM_QUIET_IDS")
ANNOUNCE = _flag("TELEGRAM_STARTUP")

# Techniques that always page, whatever the severity floor says. Automated
# tooling sweeping the trap is the single most common thing a honeypot catches
# and it is exactly what you want to hear about — but detectors.py rates it
# "medium", so a "high" floor silently swallowed every nmap and nikto run.
ALWAYS_CATEGORIES = {c.strip() for c in
                     str(cfg("TELEGRAM_ALERT_CATEGORIES", "scanner")).split(",") if c.strip()}

# Escalation: alert when a source's AGGREGATE threat score enters a new band.
# Individual events are noisy; the accumulated score is the real signal, and it
# catches a slow sweep where no single request is ever "high".
_BAND_IDX = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
ESCALATE_MIN_BAND = _BAND_IDX.get(str(cfg("TELEGRAM_ESCALATE_FROM", "medium")).upper(), 1)
ESCALATE_EVERY = _num("TELEGRAM_ESCALATE_EVERY", 20)      # seconds between checks

# Telegram tolerates roughly 20 messages/minute into one chat. Stay well under.
SEND_GAP = 3.0
MAX_MSG = 3800                      # hard API limit is 4096

ENABLED = bool(TOKEN and CHAT_IDS)

RULE = "━━━━━━━━━━━━━━━━━━━━━━━━"


# --- low-level transport ------------------------------------------------------

def _post(method, payload, timeout=12):
    """POST JSON to the Bot API. Returns (ok, parsed_or_error)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(API % (TOKEN, method), data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return False, json.loads(body)
        except ValueError:
            return False, {"error_code": exc.code, "description": body[:200]}
    except Exception as exc:
        return False, {"description": str(exc)}


def _send_one(chat_id, text, retries=3):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
               "disable_web_page_preview": True}
    res = {}
    for attempt in range(retries):
        ok, res = _post("sendMessage", payload)
        if ok:
            return True
        code = res.get("error_code")
        if code == 429:
            wait = (res.get("parameters") or {}).get("retry_after", 5)
            time.sleep(min(wait + 1, 60))
            continue
        if code == 400:
            # Malformed entities: resend as plain text rather than lose the alert.
            payload.pop("parse_mode", None)
            payload["text"] = _strip_tags(text)
            ok, _res = _post("sendMessage", payload)
            return ok
        if code in (403, 404):
            return False            # blocked the bot / bad id: no point retrying
        time.sleep(2 * (attempt + 1))
    print("[notify] %s: giving up — %s" % (chat_id, res.get("description")), flush=True)
    return False


def send_message(text, retries=3):
    """Deliver one HTML message to every configured recipient."""
    if not ENABLED:
        return False
    if SIGNATURE:
        text = text + "\n\n<i>" + html.escape(SIGNATURE) + "</i>"
    if len(text) > MAX_MSG:
        text = text[:MAX_MSG] + "\n…"
    delivered = 0
    for chat_id in CHAT_IDS:
        if _send_one(chat_id, text, retries):
            delivered += 1
    return delivered > 0


def _strip_tags(text):
    out, keep = [], True
    for ch in text:
        if ch == "<":
            keep = False
        elif ch == ">":
            keep = True
        elif keep:
            out.append(ch)
    return html.unescape("".join(out))


def send_document(filename, content, caption=""):
    """Upload a small file (the CSV report) to every recipient."""
    if not ENABLED:
        return False
    if isinstance(content, str):
        content = content.encode("utf-8")
    delivered = 0
    for chat_id in CHAT_IDS:
        boundary = "----honeypot%d" % int(time.time() * 1000000)
        parts = []
        for key, val in (("chat_id", chat_id), ("caption", caption[:1000]),
                         ("parse_mode", "HTML")):
            parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                          % (boundary, key, val)).encode("utf-8"))
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"document\"; "
                      "filename=\"%s\"\r\nContent-Type: text/csv\r\n\r\n"
                      % (boundary, filename)).encode("utf-8"))
        parts.append(content)
        parts.append(("\r\n--%s--\r\n" % boundary).encode("utf-8"))
        req = urllib.request.Request(API % (TOKEN, "sendDocument"),
                                     data=b"".join(parts), method="POST")
        req.add_header("Content-Type", "multipart/form-data; boundary=%s" % boundary)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp.read()
                delivered += 1
        except Exception as exc:
            print("[notify] %s: document upload failed: %s" % (chat_id, exc), flush=True)
    return delivered > 0


# --- chat discovery -----------------------------------------------------------

def _api_get(method, params=None):
    url = API % (TOKEN, method)
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8", "replace"))
        except ValueError:
            return {"ok": False, "description": "HTTP %s" % exc.code}
    except Exception as exc:
        return {"ok": False, "description": str(exc)}


def discover_chats():
    """Chats that have messaged the bot recently (Telegram keeps ~24h).

    Useful for onboarding: someone opens the bot, sends /start, and their id
    shows up here ready to be added to TELEGRAM_CHAT_IDS.
    """
    res = _api_get("getUpdates", {"limit": 100, "timeout": 0})
    if not res.get("ok"):
        return []
    found = {}
    for upd in res.get("result", []):
        for key in ("message", "edited_message", "channel_post", "my_chat_member"):
            msg = upd.get(key)
            if not msg:
                continue
            chat = msg.get("chat") or {}
            cid = chat.get("id")
            if cid is None:
                continue
            found[str(cid)] = {
                "id": str(cid),
                "type": chat.get("type", "?"),
                "name": (chat.get("title")
                         or " ".join(x for x in (chat.get("first_name"),
                                                 chat.get("last_name")) if x)
                         or "?"),
                "username": chat.get("username") or "",
                "configured": str(cid) in CHAT_IDS,
            }
    return list(found.values())


def bot_identity():
    res = _api_get("getMe")
    return res.get("result", {}) if res.get("ok") else {}


# --- IP reputation (AbuseIPDB), cached ---------------------------------------

_rep_cache = {}                     # ip -> (text, expires_at)
_REP_TTL = 6 * 3600
_rep_lock = threading.Lock()


def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True                 # unparseable -> do not spend a lookup on it


def check_ip_reputation(ip):
    """Return a short reputation line. Cached, never raises, never blocks long.

    The naive prefix test ("172." etc.) that this replaces also matched public
    ranges like 172.0.0.0/8; ipaddress gets RFC1918 exactly right.
    """
    if _is_private(ip):
        return "Internal address (RFC1918 / local segment)"
    if not ABUSE_KEY:
        return "External address (reputation lookup not configured)"
    now = time.time()
    with _rep_lock:
        hit = _rep_cache.get(ip)
        if hit and hit[1] > now:
            return hit[0]
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
        {"ipAddress": ip, "maxAgeInDays": "90"})
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    req.add_header("Key", ABUSE_KEY)
    text = "External address (reputation lookup failed)"
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = (json.loads(resp.read().decode("utf-8", "replace")) or {}).get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        mark = "MALICIOUS" if score >= 50 else ("SUSPECT" if score >= 10 else "CLEAN")
        text = "%s — abuse %s%% · %s · %s" % (
            mark, score, data.get("countryCode") or "??", (data.get("isp") or "unknown")[:40])
        if data.get("totalReports"):
            text += " · %s reports" % data["totalReports"]
    except Exception:
        pass
    with _rep_lock:
        if len(_rep_cache) > 2048:
            for k, (_, exp) in list(_rep_cache.items()):
                if exp < now:
                    _rep_cache.pop(k, None)
        _rep_cache[ip] = (text, now + _REP_TTL)
    return text


# --- presentation helpers -----------------------------------------------------

_BANDS = [(70, "\U0001f534", "CRITICAL"), (40, "\U0001f7e0", "HIGH"),
          (15, "\U0001f7e1", "MEDIUM"), (0, "\U0001f535", "LOW")]

# Attack technique -> (emoji, clear Arabic name). This is what makes the alert
# read at a glance: the reader sees exactly what kind of attack it is.
_AR_TECH = {
    "sqli":            ("\U0001f489", "حقن SQL"),
    "xss":             ("\U0001f4dc", "حقن سكربت (XSS)"),
    "lfi":             ("\U0001f4c2", "اجتياز مسار / قراءة ملفات"),
    "cmdi":            ("\U0001f4bb", "حقن أوامر نظام"),
    "ssti":            ("\U0001f9e9", "حقن قوالب"),
    "lfi_rce_upload":  ("\U0001f41a", "رفع ملف خبيث / web-shell"),
    "scanner":         ("\U0001f50d", "أداة فحص آلية"),
    "brute_force":     ("\U0001f511", "تخمين كلمة مرور"),
    "privesc":         ("\u2b06\ufe0f", "رفع صلاحيات"),
    "ids":             ("\U0001f310", "تنبيه شبكة (Suricata)"),
}


def _ar_tech(cat):
    return _AR_TECH.get(cat, ("\u26a0\ufe0f", cat))


def _band(score):
    for floor, dot, label in _BANDS:
        if score >= floor:
            return dot, label
    return "\U0001f535", "LOW"


def _bar(pct, width=12, min_fill=0):
    """Render a proportional bar. min_fill=1 keeps a small-but-present value
    from rounding down to an entirely empty bar, which reads as zero."""
    pct = max(0, min(100, int(pct or 0)))
    filled = int(round(pct / 100.0 * width))
    if pct > 0:
        filled = max(filled, min_fill)
    return "█" * filled + "░" * (width - filled)


def _row(label, value, width=11):
    return "<code>%s</code> %s" % (label.ljust(width), value)


def _threat_for(ip):
    """Current aggregated threat score for one source, or None."""
    try:
        from . import dashboard
        for a in dashboard.cached_aggregate().get("attackers", []):
            if a["ip"] == ip:
                return a
    except Exception:
        pass
    return None


# --- alert policy -------------------------------------------------------------

_q = queue.Queue(maxsize=5000)
_cool = {}                          # (ip, cat) -> [expires_at, suppressed, sample]
_seen_ips = set()
_state_lock = threading.Lock()
_last_send = [0.0]


def _worthy(record):
    """Decide whether one event deserves an alarm. Returns (bool, reason)."""
    findings = record.get("findings") or []
    etype = record.get("event_type", "request")
    extra = record.get("extra") or {}

    if etype == "ids_alert":
        suri = extra.get("suricata_severity", 3)
        if QUIET_IDS and isinstance(suri, int) and suri >= 3:
            return False, ""
        return True, "suricata"

    if etype == "viewstate_tamper":
        return True, "tamper"

    if {f.get("category") for f in findings} & ALWAYS_CATEGORIES:
        return True, "tooling"

    top = 0
    for f in findings:
        top = max(top, _SEV_RANK.get(f.get("severity", "low"), 1))
    if top >= MIN_SEVERITY:
        return True, "attack"
    return False, ""


def _cat_of(record):
    findings = record.get("findings") or []
    return findings[0].get("category", "?") if findings else record.get("event_type", "?")


def _enqueue(record):
    """logger hook — must return immediately and never raise."""
    if not ENABLED:
        return
    try:
        _q.put_nowait(record)
    except queue.Full:
        pass


def _format_alert(record, suppressed=0, first_time=False):
    """Build one short, clear Arabic alert. Every field is html.escape'd."""
    ip = record.get("src_ip", "?")
    etype = record.get("event_type", "request")
    extra = record.get("extra") or {}
    findings = record.get("findings") or []
    e = html.escape
    when = str(record.get("ts", ""))[:19].replace("T", " ")

    L = []

    # --- pick the headline by event type, in plain Arabic ---
    if etype == "ids_alert":
        emoji, name = _ar_tech("ids")
        L.append("%s <b>%s</b>" % (emoji, name))
        L.append("")
        L.append("• <b>التوقيع:</b> %s" % e(str(extra.get("signature", "—"))))
        L.append("• <b>المصدر:</b> <code>%s</code>" % e(ip))
        L.append("• <b>الهدف:</b> <code>%s:%s</code>" % (
            e(str(extra.get("dest_ip", "—"))), e(str(extra.get("dest_port", "—")))))

    elif etype in ("ssh_login", "ftp_login"):
        emoji, name = _ar_tech("brute_force")
        svc = "SSH" if etype == "ssh_login" else "FTP"
        ok = extra.get("success")
        L.append("%s <b>%s — %s</b>" % (emoji, name, svc))
        L.append("")
        L.append("• <b>المصدر:</b> <code>%s</code>" % e(ip))
        L.append("• <b>الحساب:</b> <code>%s : %s</code>" % (
            e(str(extra.get("username", ""))) or "—", e(str(extra.get("password", ""))) or "—"))
        L.append("• <b>النتيجة:</b> %s" % (
            "🔓 <b>نجح الدخول</b>" if ok else "❌ فشل"))

    elif etype == "weak_cred_success":
        L.append("🔓 <b>اختراق ناجح — دخول ببيانات ضعيفة</b>")
        L.append("")
        L.append("• <b>المصدر:</b> <code>%s</code>" % e(ip))
        L.append("• <b>الحساب:</b> <code>%s : %s</code>" % (
            e(str(extra.get("username", ""))) or "—", e(str(extra.get("password", ""))) or "—"))
        L.append("• <b>المسار:</b> <code>%s</code>" % e(str(record.get("path", "/login"))))

    elif etype == "privilege_escalation":
        emoji, name = _ar_tech("privesc")
        L.append("%s <b>%s</b>" % (emoji, name))
        L.append("")
        L.append("• <b>المصدر:</b> <code>%s</code>" % e(ip))
        L.append("• <b>التفاصيل:</b> من <code>student</code> إلى <code>admin</code> (تلاعب بالكوكي)")

    elif etype == "viewstate_tamper":
        L.append("🚫 <b>تجاوز نموذج الدخول</b>")
        L.append("")
        L.append("• <b>المصدر:</b> <code>%s</code>" % e(ip))
        L.append("• <b>التفاصيل:</b> طلب بدون توكن VIEWSTATE (أداة آلية)")

    else:
        # generic web attack — name it from the detector categories
        cats = sorted({f.get("category", "?") for f in findings})
        emoji, name = _ar_tech(cats[0]) if cats else ("⚠️", etype)
        L.append("%s <b>%s</b>" % (emoji, name))
        L.append("")
        L.append("• <b>المصدر:</b> <code>%s</code>" % e(ip))
        L.append("• <b>المسار:</b> <code>%s</code>" % e(str(record.get("path", ""))[:120]))
        if extra.get("username") is not None:
            L.append("• <b>محاولة دخول:</b> <code>%s : %s</code>" % (
                e(str(extra.get("username", ""))) or "—", e(str(extra.get("password", ""))) or "—"))

    # --- one payload/SQL line, the evidence, if any ---
    payload = None
    if extra.get("executed_sql"):
        payload = str(extra["executed_sql"])
    elif etype == "ssh_command" and extra.get("command"):
        payload = str(extra["command"])
    else:
        pls = [f.get("payload") for f in findings if f.get("payload")]
        if pls and etype not in ("ssh_login", "ftp_login", "ids_alert"):
            payload = str(pls[0])
    if payload:
        L.append("")
        L.append("<b>الحمولة:</b>")
        L.append("<pre>%s</pre>" % e(payload[:300]))

    # --- footer: time + first-contact note ---
    L.append("")
    L.append("🕒 %s" % e(when))
    if suppressed:
        L.append("<i>+%d محاولة مماثلة من نفس المصدر</i>" % suppressed)

    head = ("🆕 <b>أول ظهور لهذا المصدر</b>\n\n"
            if first_time else "")
    return head + "\n".join(L)


def _handle(record):
    ok, _reason = _worthy(record)
    ip = record.get("src_ip", "?")
    now = time.time()

    with _state_lock:
        first_time = ip not in _seen_ips
        if ok:
            _seen_ips.add(ip)
            if len(_seen_ips) > 20000:
                _seen_ips.clear()
    if not ok:
        return

    key = (ip, _cat_of(record))
    with _state_lock:
        entry = _cool.get(key)
        if entry and entry[0] > now:
            entry[1] += 1
            entry[2] = record            # keep the latest sample for the rollup
            return
        _cool[key] = [now + COOLDOWN, 0, None]
        if len(_cool) > 4096:
            for k, v in list(_cool.items()):
                if v[0] < now:
                    _cool.pop(k, None)

    _paced_send(_format_alert(record, first_time=first_time))


def _paced_send(msg):
    gap = SEND_GAP - (time.time() - _last_send[0])
    if gap > 0:
        time.sleep(gap)
    _last_send[0] = time.time()
    send_message(msg)


def _flush_rollups():
    """Emit one summary per (ip, technique) whose cooldown just expired."""
    now = time.time()
    due = []
    with _state_lock:
        for key, entry in list(_cool.items()):
            if entry[0] <= now:
                if entry[1] and entry[2] is not None:
                    due.append((entry[1], entry[2]))
                _cool.pop(key, None)
    for count, sample in due:
        _paced_send(_format_alert(sample, suppressed=count))


# --- threat escalation --------------------------------------------------------

_esc_last = [0.0]
_esc_band = {}                      # ip -> highest band index already announced


def _band_index(score):
    return _BAND_IDX.get(_band(score)[1], 0)


def _format_escalation(a):
    """Simple Arabic escalation notice when a source climbs a threat band."""
    e = html.escape
    L = ["📈 <b>تصاعد خطورة مصدر</b>", ""]
    L.append("• <b>المصدر:</b> <code>%s</code>" % e(a["ip"]))
    L.append("• <b>درجة التهديد:</b> %d/100" % a["threat"])
    L.append("• <b>النشاط:</b> %s طلب · %s هجوم" % (a["hits"], a["attacks"]))
    if a.get("is_bot"):
        L.append("• <b>النوع:</b> 🤖 أداة آلية")
    techs = a.get("categories") or {}
    if techs:
        names = "، ".join(_ar_tech(k)[1] for k in
                               sorted(techs, key=lambda k: -techs[k]))
        L += ["", "<b>التقنيات المرصودة:</b>", e(names)]
    if a.get("also_seen_ips"):
        L += ["", "🔗 نفس الجهاز من: <code>%s</code>"
              % e("، ".join(a["also_seen_ips"][:5]))]
    L += ["", "🕒 %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())]
    return "\n".join(L)


def _check_escalations(force=False):
    """Page when an actor climbs into a higher threat band.

    Throttled: re-aggregating on every event during a sweep would be pure waste,
    and 20s is far faster than a human reacts anyway.
    """
    now = time.time()
    if not force and now - _esc_last[0] < ESCALATE_EVERY:
        return
    _esc_last[0] = now
    try:
        from . import dashboard
        attackers = dashboard.cached_aggregate().get("attackers", [])
    except Exception:
        return
    for a in attackers:
        idx = _band_index(a["threat"])
        if idx < ESCALATE_MIN_BAND:
            continue
        with _state_lock:
            prev = _esc_band.get(a["ip"], -1)
            if idx <= prev:
                continue
            _esc_band[a["ip"]] = idx
            if len(_esc_band) > 20000:
                _esc_band.clear()
        _paced_send(_format_escalation(a))


# --- periodic report ----------------------------------------------------------

def build_report():
    """One short Arabic status report plus a CSV attachment."""
    from . import dashboard                      # imported late: avoids a cycle
    data = dashboard.cached_aggregate()
    e = html.escape
    attackers = data.get("attackers") or []

    L = ["📊 <b>تقرير المصيدة</b>", ""]
    L.append("• إجمالي الأحداث: <b>%s</b>" % data.get("total_events", 0))
    L.append("• عناوين مهاجمة: <b>%s</b>" % data.get("total_attackers", 0))
    L.append("• محاولات هجوم: <b>%s</b>" % data.get("total_attacks", 0))
    L.append("• تهديد عالٍ/حرج: <b>%s</b>" % data.get("critical_threats", 0))
    L.append("• أدوات آلية: <b>%s</b>" % data.get("bots_detected", 0))

    cats = data.get("category_totals") or {}
    if cats:
        L += ["", "<b>التقنيات المرصودة:</b>"]
        for name, count in sorted(cats.items(), key=lambda kv: -kv[1])[:8]:
            L.append("• %s: <b>%s</b>" % (e(_ar_tech(name)[1]), count))

    if attackers:
        L += ["", "<b>أعلى المهاجمين:</b>"]
        for a in attackers[:5]:
            tag = " 🤖" if a.get("is_bot") else ""
            L.append("• <code>%s</code> — تهديد %s/100%s"
                     % (e(a["ip"]), a["threat"], tag))

    L += ["", "🕒 %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())]
    return "\n".join(L), data


def send_report(force=False):
    if not ENABLED:
        return False
    text, data = build_report()
    if not force and not data.get("total_attacks"):
        return False                            # idle honeypot: stay silent
    _paced_send(text)
    try:
        import csv
        import io as _io
        buf = _io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ip", "threat", "level", "hits", "attacks", "techniques",
                    "os", "browser", "is_bot", "first_seen", "last_seen"])
        for a in (data.get("attackers") or []):
            w.writerow([a["ip"], a["threat"], a["threat_level"], a["hits"], a["attacks"],
                        " ".join("%s:%s" % kv for kv in a["categories"].items()),
                        a["os"], a["browser"], a["is_bot"],
                        a["first_seen"] or "", a["last_seen"] or ""])
        send_document("attackers-%s.csv" % time.strftime("%Y%m%d-%H%M"),
                      buf.getvalue(),
                      caption="\U0001f4ce Full attacker breakdown")
    except Exception as exc:
        print("[notify] report csv failed: %s" % exc, flush=True)
    return True


# --- threads ------------------------------------------------------------------

_started = False


def _worker():
    while True:
        try:
            record = _q.get(timeout=5.0)
        except queue.Empty:
            _flush_rollups()
            _check_escalations()
            continue
        try:
            _handle(record)
            _check_escalations()
        except Exception as exc:
            print("[notify] alert failed: %s" % exc, flush=True)


def _reporter():
    while True:
        time.sleep(max(60, REPORT_EVERY * 60))
        try:
            send_report()
        except Exception as exc:
            print("[notify] report failed: %s" % exc, flush=True)


def start():
    """Register the log hook and spin up the worker threads. Idempotent.

    Call AFTER any fork — gunicorn --preload imports the app in the master and
    then forks, and threads created at import time stay behind in the master.
    """
    global _started
    if _started or not ENABLED:
        return False
    _started = True
    logger.add_hook(_enqueue)
    threading.Thread(target=_worker, daemon=True, name="tg-alert").start()
    if REPORT_EVERY > 0:
        threading.Thread(target=_reporter, daemon=True, name="tg-report").start()
    print(" * Telegram alerts active — %d recipient(s), min severity: %s, "
          "cooldown: %ss, report: %s"
          % (len(CHAT_IDS), cfg("TELEGRAM_MIN_SEVERITY", "high"), COOLDOWN,
             ("%sm" % REPORT_EVERY) if REPORT_EVERY else "off"), flush=True)
    if ANNOUNCE:
        msg = "\n".join([
            "\U0001f6e1 <b>محرّك تنبيهات المصيدة يعمل</b>", "",
            "الرصد نشط على طبقتي التطبيق والشبكة.",
            "ستصلك تنبيهات عند أي هجوم.",
        ])
        threading.Thread(target=send_message, daemon=True, args=(msg,)).start()
    return True


def status():
    return {
        "enabled": ENABLED, "started": _started,
        "recipients": len(CHAT_IDS), "token_set": bool(TOKEN),
        "reputation": bool(ABUSE_KEY),
        "min_severity": cfg("TELEGRAM_MIN_SEVERITY", "high"),
        "cooldown_s": COOLDOWN, "report_every_min": REPORT_EVERY,
        "always_alert": sorted(ALWAYS_CATEGORIES),
        "escalate_from": str(cfg("TELEGRAM_ESCALATE_FROM", "medium")),
        "queued": _q.qsize(), "cooldowns_active": len(_cool),
        "actors_escalated": len(_esc_band),
    }


def main(argv=None):
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    if not TOKEN:
        print("TELEGRAM_TOKEN is not set (env or app/local_config.py).")
        return 2

    if "--discover" in argv or "--whoami" in argv:
        bot = bot_identity()
        print("BOT: @%s (%s) id=%s" % (bot.get("username", "?"),
                                       bot.get("first_name", "?"), bot.get("id", "?")))
        print("CONFIGURED RECIPIENTS: %s" % (", ".join(CHAT_IDS) or "(none)"))
        if "--discover" in argv:
            print()
            print("CHATS THAT MESSAGED THE BOT (last ~24h):")
            chats = discover_chats()
            if not chats:
                print("  (none — have them open the bot and send /start, then re-run)")
            for c in chats:
                print("  id=%-14s %-8s %-24s %s" % (
                    c["id"], c["type"], c["name"],
                    "ALREADY CONFIGURED" if c["configured"] else "<-- add this id"))
        return 0

    if not ENABLED:
        print("No recipients configured (TELEGRAM_CHAT_ID / TELEGRAM_CHAT_IDS).")
        return 2
    if "--report" in argv:
        print("sending report to %d recipient(s) ..." % len(CHAT_IDS), send_report(force=True))
    else:
        demo = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "src_ip": "127.0.0.1", "event_type": "login_attempt",
            "method": "POST", "path": "/login",
            "user_agent": "sqlmap/1.7.2#stable (https://sqlmap.org)",
            "findings": [{"category": "sqli", "severity": "high",
                          "payload": "' OR '1'='1' -- "}],
            "extra": {"username": "' OR '1'='1' -- ", "password": "x",
                      "executed_sql": "SELECT student_id, full_name FROM students "
                                      "WHERE username = '' OR '1'='1' -- ' AND password = 'x'"},
        }
        print("sending test alert to %d recipient(s) ..." % len(CHAT_IDS),
              send_message(_format_alert(demo)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
