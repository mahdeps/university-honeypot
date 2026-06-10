"""
University portal honeypot — main application.

A medium-interaction web honeypot that imitates the UCAS student information
system. It is a DECOY: it runs in isolation and exists only to attract, observe
and record attacker behaviour.

After a successful login it serves PIXEL-EXACT offline clones of the real portal
pages (captured into app/portal/*.html, assets under app/static/NewTemp). The
data shown there is whatever was captured; treat the whole thing as a lab decoy.

Design choices that make it useful research bait:
  * Every request (good or bad) is logged and scanned by detectors.py.
  * The login form is intentionally injectable (decoy_db.py), so SQL-injection
    attempts are captured in full.
  * "Tempting" paths (/admin, /.git/config, /backup.sql, /phpmyadmin, /.env) are
    served as believable bait and every hit is recorded.
  * A catch-all route logs directory-brute-force / scanner traffic.

IMPORTANT — deployment rule:
  Run this ONLY inside an isolated lab network or VM, or on localhost (see README +
  docker-compose). The UI mimics a real institution's portal (logo + template), so
  exposing it on a public or look-alike domain would turn this research tool into a
  phishing page — which is forbidden. Never use it to collect anyone's input.
"""

import os
import re
import json
import time
import hmac
import base64
import hashlib
import secrets
import sqlite3
from flask import (Flask, request, render_template, redirect, url_for,
                   Response, send_from_directory, abort)

from . import detectors, logger, decoy_db, dyn, security, intel
from .dashboard import dashboard_bp

# Make the dev server announce itself as IIS too (no Werkzeug banner leak).
try:
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "Microsoft-IIS/10.0"
    WSGIRequestHandler.sys_version = ""
except Exception:
    pass

app = Flask(__name__)
app.secret_key = security.SECRET                       # from env, random otherwise
app.config["MAX_CONTENT_LENGTH"] = security.MAX_BODY   # cap request bodies (DoS)
app.url_map.strict_slashes = False

app.register_blueprint(dashboard_bp, url_prefix="/_monitor")
decoy_db.init_db()

# ============================================================================
#  Security layer — mirrors the real UCAS portal (IIS / ASP.NET WebForms):
#   * ASP.NET_SessionId server-side session cookie (HttpOnly, SameSite)
#   * __VIEWSTATE / __EVENTVALIDATION anti-forgery tokens on the login form,
#     issued on GET and validated on POST (a scripted POST that skips the form
#     gets bounced to /error.aspx — and recorded as high-signal attacker noise)
#   * the same hardening response headers the real site returns
# ============================================================================

SESSION_COOKIE = "ASP.NET_SessionId"
_SESSIONS: dict[str, dict] = {}        # decoy server-side session store
_SECRET = app.secret_key.encode()
_SID_ALPHABET = "abcdefghijklmnopqrstuvwxyz012345"   # ASP.NET session-id charset


def _sess() -> dict:
    return _SESSIONS.get(request.cookies.get(SESSION_COOKIE, ""), {})


def _attach_session(resp, data):
    if len(_SESSIONS) >= 10000:                 # bound memory vs session spraying
        _SESSIONS.pop(next(iter(_SESSIONS)), None)
    sid = "".join(secrets.choice(_SID_ALPHABET) for _ in range(24))
    _SESSIONS[sid] = data
    resp.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="Lax",
                    secure=security.HTTPS, path="/")
    return resp


def _clear_session(resp):
    _SESSIONS.pop(request.cookies.get(SESSION_COOKIE, ""), None)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


def _sign(payload: bytes) -> str:
    mac = hmac.new(_SECRET, payload, hashlib.sha256).digest()
    return base64.b64encode(payload + b"||" + mac).decode()


def _issue_tokens():
    """Issue a believable, validatable __VIEWSTATE / __EVENTVALIDATION pair."""
    ts = str(int(time.time())).encode()
    vs = _sign(b"vs|" + ts + b"|" + secrets.token_bytes(220))   # ~ real length
    ev = _sign(b"ev|" + ts + b"|" + secrets.token_bytes(96))
    return vs, "805C0972", ev


def _valid_token(tok: str, kind: bytes) -> bool:
    try:
        raw = base64.b64decode(tok.encode())
        payload, mac = raw.rsplit(b"||", 1)
        good = hmac.new(_SECRET, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, good):
            return False
        parts = payload.split(b"|", 2)
        if parts[0] != kind:
            return False
        return (time.time() - int(parts[1])) < 3600       # 1h validity window
    except Exception:
        return False

PORTAL_DIR = os.path.join(os.path.dirname(__file__), "portal")

# Exact-clone pages: real portal path -> captured file served verbatim.
# One source of truth, shared with the capture/localize tooling.
with open(os.path.join(os.path.dirname(__file__), "portal_pages.json"), encoding="utf-8") as _pf:
    PORTAL_PAGES = json.load(_pf)

# Literal values baked into the captured pages (one real account). At serve time
# they are swapped for the logged-in student's own data pulled from the decoy DB,
# so the portal is a live, per-user system instead of a frozen snapshot.
_CAP_NAME = "عبدالله محمد أحمد سالم"
_CAP_SID = "200000000"
_CAP_EMAIL = "200000000@smail.ucas.edu.ps"


def _student_context(sid):
    """Pull everything the portal pages display for one student from the DB."""
    if not sid:
        return None
    conn = decoy_db._connect()
    try:
        s = conn.execute("SELECT * FROM students WHERE student_id=?", (sid,)).fetchone()
        if not s:
            return None
        adv = conn.execute("SELECT * FROM instructors WHERE instructor_id=?",
                           (s["advisor_id"],)).fetchone()
        fac = conn.execute(
            "SELECT f.name FROM majors m JOIN faculties f ON f.faculty_id=m.faculty_id "
            "WHERE m.major_id=?", (s["major_id"],)).fetchone()
        req = conn.execute("SELECT required_credits, degree FROM majors WHERE major_id=?",
                           (s["major_id"],)).fetchone()
        rows = conn.execute(
            "SELECT e.grade, c.credits FROM enrollments e JOIN courses c ON c.code=e.course_code "
            "WHERE e.student_id=?", (sid,)).fetchall()
        attempted = sum(r["credits"] for r in rows)
        passed = sum(r["credits"] for r in rows if r["grade"] != "F")
        required = req["required_credits"] if req else 132
        degree = req["degree"] if req else "بكالوريوس"
        adv_name = adv["full_name"] if adv else "غير محدد"
        adv_major = conn.execute("SELECT name FROM majors WHERE major_id=?",
                                 (adv["major_id"],)).fetchone() if adv else None
        return {
            "name": s["full_name"], "sid": s["student_id"], "email": s["email"],
            "major": s["major"], "faculty": fac["name"] if fac else "—",
            "section": f"قسم {s['major']} - {degree}", "level": str(s["level"]),
            "gpa": f"%{s['gpa']:.2f}", "attempted": str(attempted), "passed": str(passed),
            "remaining": str(max(0, required - passed)),
            "adv_name": adv_name,
            "adv_dept": adv_major["name"] if adv_major else s["major"],
            "adv_mail": adv["email"] if adv else "—",
            "adv_phone": adv["phone"] if adv else "—",
            "adv_notes": f"{adv['title']} {adv_name} – مرشد {s['major']}" if adv else "—",
        }
    finally:
        conn.close()


# ASP.NET label id  ->  context key (same ids appear on every captured page)
_ID_MAP = {
    "lblStudentName": "name", "lblStudentNo": "sid", "lblEmail": "email",
    "lblSpecial": "major", "lblDean": "faculty", "lblTaw_College": "section",
    "ADVISOR_NAME": "adv_name", "ADVISOR_DEPT_NAME": "adv_dept",
    "ADVISOR_MAIL": "adv_mail", "ADVISOR_WHATSAPP_NO": "adv_phone", "NOTES": "adv_notes",
    "ContentPlaceHolder1_lblSECTION_NAME": "section",
    "ContentPlaceHolder1_lblDEPARTMENT_NAME": "major",
    "ContentPlaceHolder1_lblSTD_LEVEL": "level",
    "ContentPlaceHolder1_lblSTD_STUDYHR": "attempted",
    "ContentPlaceHolder1_lblSUCCESSHR": "passed",
    "ContentPlaceHolder1_lblREAMIN_HR": "remaining",
    "ContentPlaceHolder1_lblSTD_AVG": "gpa",
}


def _personalize(html, ctx):
    """Replace the baked-in account's data with the logged-in student's data."""
    # literals — topbar name, advisor name/mail/phone, and any stray id/email/username
    html = (html
            .replace(_CAP_NAME, ctx["name"])
            .replace("أحمد محمد المرشد", ctx["adv_name"])
            .replace("advisor@ucas.edu.ps", ctx["adv_mail"])
            .replace("970599000000", ctx["adv_phone"])
            .replace(_CAP_EMAIL, ctx["email"])
            .replace(_CAP_SID, ctx["sid"]))
    # id-anchored labels (text-only content up to the next tag)
    for el_id, key in _ID_MAP.items():
        val = ctx.get(key, "")
        html = re.sub(r'(id="' + re.escape(el_id) + r'"[^>]*>)[^<]*',
                      lambda m, v=val: m.group(1) + v, html, count=1)
    return html


# --- Request capture ----------------------------------------------------------

def _capture(event_type: str = "request", extra: dict | None = None) -> list[dict]:
    headers = {k: v for k, v in request.headers.items()}
    query = request.args.to_dict()
    form = request.form.to_dict()
    raw_body = ""
    if not form:
        try:
            raw_body = request.get_data(as_text=True)[:2000]
        except Exception:
            raw_body = ""

    findings = detectors.scan_request(
        path=request.path, query=query, form=form, headers=headers, raw_body=raw_body,
    )
    logger.log_event(
        remote_addr=request.remote_addr or "?",
        method=request.method,
        path=request.full_path.rstrip("?"),
        query=query, form=form, headers=headers,
        findings=findings, event_type=event_type, extra=extra,
    )
    return findings


@app.before_request
def _before():
    # Don't double-log the monitor, static assets, or our own intel endpoints.
    if request.path.startswith(("/_monitor", "/static", "/_intel.js", "/_collect")):
        return
    _capture()
    # Record the attack first, then shed floods so the host can't be exhausted
    # or abused as a DoS reflector.
    if security.is_flooding(security.client_ip()):
        return Response("429 Too Many Requests", status=429,
                        headers={"Retry-After": str(security.RATE_WINDOW)})


@app.after_request
def _harden(resp: Response):
    # Same server banner + hardening headers the real UCAS portal returns.
    # (Server header itself is set by the WSGIRequestHandler patch above.)
    resp.headers["X-Powered-By"] = "ASP.NET"
    resp.headers["X-AspNet-Version"] = "4.0.30319"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers.setdefault("Cache-Control", "private")
    # Drop the intel beacon into every decoy HTML page (never the monitor).
    if ("text/html" in resp.headers.get("Content-Type", "") and resp.status_code < 400
            and not request.path.startswith(("/_monitor", "/_intel.js"))):
        try:
            body = resp.get_data(as_text=True)
            if "</body>" in body and "/_intel.js" not in body:
                resp.set_data(body.replace(
                    "</body>", '<script src="/_intel.js"></script></body>', 1))
        except Exception:
            pass
    return resp


def _logged_in() -> bool:
    return "user" in _sess()


# --- Auth ---------------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        # ASP.NET anti-forgery: reject a POST that did not come from our form.
        vs = request.form.get("__VIEWSTATE", "")
        ev = request.form.get("__EVENTVALIDATION", "")
        if not (_valid_token(vs, b"vs") and _valid_token(ev, b"ev")):
            _capture(event_type="viewstate_tamper",
                     extra={"reason": "missing/invalid __VIEWSTATE or __EVENTVALIDATION"})
            return redirect("/error.aspx?aspxerrorpath=/login")

        username = (request.form.get("ctl00$ContentPlaceHolder1$txtUsername")
                    or request.form.get("username", ""))
        password = (request.form.get("ctl00$ContentPlaceHolder1$txtPassword")
                    or request.form.get("password", ""))
        rows, executed_sql = decoy_db.vulnerable_login(username, password)
        _capture(event_type="login_attempt", extra={
            "username": username, "password": password, "executed_sql": executed_sql,
            "rows_returned": len(rows) if isinstance(rows, list) else 0,
            "db_error": rows.get("error") if isinstance(rows, dict) else None,
        })
        if isinstance(rows, list) and rows:
            resp = redirect("/home")
            return _attach_session(resp, {"sid": rows[0].get("student_id"),
                                          "user": rows[0].get("full_name") or "طالب"})
        error = "الرقم الجامعي أو كلمة المرور غير صحيحة."

    viewstate, vsgen, eventvalidation = _issue_tokens()
    return render_template("login.html", error=error, viewstate=viewstate,
                           vsgen=vsgen, eventvalidation=eventvalidation)


@app.route("/logout")
def logout():
    return _clear_session(redirect(url_for("login")))


@app.route("/error.aspx")
def error_aspx():
    _capture(event_type="error_page")
    return render_template("error_aspx.html",
                           path=request.args.get("aspxerrorpath", "/")), 500


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot():
    msg = None
    if request.method == "POST":
        _capture(event_type="password_reset", extra={
            "student_id": request.form.get("student_id", ""),
            "email": request.form.get("email", ""),
        })
        msg = "إذا كانت البيانات صحيحة، تم إرسال رابط استعادة كلمة المرور إلى بريدك."
    return render_template("forgot.html", msg=msg)


# --- Bait paths ---------------------------------------------------------------

@app.route("/admin", methods=["GET", "POST"])
@app.route("/administrator", methods=["GET", "POST"])
def admin_bait():
    _capture(event_type="admin_probe")
    return render_template("admin.html", error="مطلوب تسجيل دخول المسؤول."), 200


@app.route("/.env")
def env_bait():
    _capture(event_type="secret_probe")
    body = (
        "APP_ENV=production\n"
        "APP_KEY=base64:Zm9vYmFyZGVjb3lub3RyZWFsa2V5PT0=\n"
        "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=university\n"
        "DB_USERNAME=portal_app\nDB_PASSWORD=decoy_password_2020\n"
    )
    return Response(body, mimetype="text/plain")


@app.route("/.git/config")
def git_bait():
    _capture(event_type="secret_probe")
    body = ("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
            "\turl = https://git.internal.example/portal.git\n")
    return Response(body, mimetype="text/plain")


@app.route("/backup.zip")
@app.route("/backup.sql")
@app.route("/database.sql")
def backup_bait():
    _capture(event_type="secret_probe")
    return Response("-- MySQL dump (truncated)\n-- decoy file\n", mimetype="text/plain")


@app.route("/phpmyadmin/")
@app.route("/phpmyadmin")
def pma_bait():
    _capture(event_type="admin_probe")
    return render_template("admin.html", error="phpMyAdmin — تسجيل الدخول."), 200


@app.route("/robots.txt")
def robots():
    body = ("User-agent: *\nDisallow: /admin\nDisallow: /backup.sql\n"
            "Disallow: /.env\nDisallow: /phpmyadmin\n")
    return Response(body, mimetype="text/plain")


@app.route("/NewTemp/<path:p>")
def newtemp_alias(p):
    # Some captured markup references assets at the site-root /NewTemp/... path.
    # Serve them from the bundled static copy so nothing 404s.
    return send_from_directory(os.path.join(app.static_folder, "NewTemp"), p)


@app.route("/_intel.js")
def intel_js():
    return Response(intel.BEACON_JS, mimetype="application/javascript",
                    headers={"Cache-Control": "no-store"})


@app.route("/_collect", methods=["POST"])
def collect_intel():
    # Rich device/browser fingerprint beaconed by the page JS. Record it as
    # high-value intel against the visitor's source IP.
    if security.is_flooding(security.client_ip()):
        return Response("", status=429)
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        data = {}
    _capture(event_type="client_intel", extra=data)
    return Response("", status=204)


@app.route("/WebService.asmx/<method>", methods=["GET", "POST"])
def asmx(method):
    # AJAX endpoints the portal polls (notifications, approvals). ASMX wraps the
    # payload in "d" as a JSON *string* — the client JSON.parses it later, so an
    # empty array must be the string "[]", not [].
    return Response('{"d":"[]"}', mimetype="application/json")


# Minimal ASP.NET WebForms client shim so the captured pages run clean offline
# (WebResource.axd / ScriptResource.axd are gone, so define what they provided).
_ASPNET_SHIM = """(function(){
  window.__doPostBack = window.__doPostBack || function(t,a){var f=document.forms['form1']||document.forms[0];if(f){if(f.__EVENTTARGET)f.__EVENTTARGET.value=t;if(f.__EVENTARGUMENT)f.__EVENTARGUMENT.value=a;}return false;};
  window.WebForm_AutoFocus=window.WebForm_AutoFocus||function(id){try{var e=document.getElementById(id);if(e&&e.focus)e.focus();}catch(_){}};
  window.WebForm_FireDefaultButton=window.WebForm_FireDefaultButton||function(e,id){var k=e.keyCode||e.which;if(k==13){var b=document.getElementById(id);if(b&&b.click)b.click();return false;}return true;};
  window.WebForm_DoPostBackWithOptions=window.WebForm_DoPostBackWithOptions||function(){return false;};
  window.msgget=window.msgget||function(){return '';};
  window.Page_ClientValidate=window.Page_ClientValidate||function(){return true;};
  var S=window.Sys=window.Sys||{};
  S.Application=S.Application||{add_init:function(){},add_load:function(){},remove_load:function(){},notifyScriptLoaded:function(){},initialize:function(){},get_isCreatingComponents:function(){return false;}};
  S.WebForms=S.WebForms||{};
  S.WebForms.PageRequestManager=S.WebForms.PageRequestManager||function(){};
  var pm=S.WebForms.PageRequestManager.prototype;
  pm._initialize=pm._initialize||function(){};pm.dispose=pm.dispose||function(){};
  pm.add_beginRequest=pm.add_beginRequest||function(){};pm.add_endRequest=pm.add_endRequest||function(){};
  pm.add_pageLoaded=pm.add_pageLoaded||function(){};pm.add_pageLoading=pm.add_pageLoading||function(){};
  S.WebForms.PageRequestManager._initialize=function(){};
  S.WebForms.PageRequestManager.getInstance=function(){return new S.WebForms.PageRequestManager();};
  if(S.Application&&S.Application.notifyScriptLoaded){try{S.Application.notifyScriptLoaded();}catch(_){}}
})();"""


# --- Catch-all: serve exact portal clones, else log the probe -----------------

@app.route("/<path:unknown>", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
def catch_all(unknown):
    low = unknown.lower()
    # ASP.NET dynamic scripts / stray relative scripts — serve clean stubs so the
    # cloned pages run without console/MIME errors (these aren't attacker probes).
    if low.endswith(".axd"):
        return Response(_ASPNET_SHIM, mimetype="application/javascript")
    if low.endswith(".js"):
        return Response("", mimetype="application/javascript")

    key = "/" + unknown
    if key in PORTAL_PAGES:
        if not _logged_in():
            return redirect(url_for("login"))
        sid = _sess().get("sid")
        with open(os.path.join(PORTAL_DIR, PORTAL_PAGES[key]), encoding="utf-8") as fh:
            html = fh.read()
        ctx = _student_context(sid)
        if ctx:
            html = _personalize(html, ctx)
        html = dyn.fill(PORTAL_PAGES[key], html, sid)
        # Define the ASP.NET client shim before any inline page script runs.
        html = html.replace("<head>", "<head><script>%s</script>" % _ASPNET_SHIM, 1)
        return Response(html, mimetype="text/html")
    _capture(event_type="path_probe")
    return render_template("notfound.html", path=unknown), 404


# --- Error handlers — believable, and never leak a stack trace ----------------

@app.errorhandler(404)
def _err_404(e):
    return render_template("notfound.html", path=request.path.lstrip("/")), 404


@app.errorhandler(413)
def _err_413(e):
    return Response("413 Request Entity Too Large", status=413)


@app.errorhandler(Exception)
def _err_500(e):
    # Any unhandled error returns the generic ASP.NET error page (no traceback,
    # no Werkzeug debugger — debug is always off here).
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException) and e.code != 500:
        return e
    return render_template("error_aspx.html", path=request.path), 500


if __name__ == "__main__":
    print(security.startup_banner())
    app.run(host="0.0.0.0", port=8080, debug=False)
