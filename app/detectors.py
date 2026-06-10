"""
Attack-detection engine for the university honeypot.

Every incoming request is scanned against a set of signatures. The point is NOT
to block anything (a honeypot wants the attacker to keep going) but to *classify*
and *record* what they are attempting, so the project can report exactly which
attack techniques were observed.

Each detector returns a list of findings. A finding describes the category, the
field it was found in, and the raw payload that matched — that raw payload is what
makes the final report convincing.
"""

import re
from dataclasses import dataclass, asdict
from typing import Iterable


@dataclass
class Finding:
    category: str        # e.g. "sqli", "xss", "lfi"
    field: str           # where it was seen: "path", "query:id", "body:username", "header:User-Agent"
    payload: str         # the raw matched value
    severity: str        # "low" | "medium" | "high"

    def as_dict(self) -> dict:
        return asdict(self)


# --- Signature tables ---------------------------------------------------------
# Kept readable on purpose: a student should be able to explain every line in a
# viva. Patterns are intentionally broad because in a honeypot a false positive
# costs nothing — we are observing, not defending production traffic.

_SIGNATURES: dict[str, tuple[str, list[str]]] = {
    # category: (severity, [regex, ...])
    "sqli": (
        "high",
        [
            r"(?i)\bunion\b\s+\bselect\b",
            r"(?i)\bor\b\s+\d+\s*=\s*\d+",
            r"(?i)'\s*or\s*'?\d*'?\s*=\s*'?\d*",
            r"(?i)\b(select|insert|update|delete|drop|alter)\b.+\b(from|into|table)\b",
            r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
            r"(?i)information_schema",
            r"--\s|#\s|;--|/\*.*\*/",
            r"(?i)\bxp_cmdshell\b",
        ],
    ),
    "xss": (
        "medium",
        [
            r"(?i)<script[\s>]",
            r"(?i)on(error|load|mouseover|click|focus)\s*=",
            r"(?i)javascript:",
            r"(?i)<img[^>]+src\s*=",
            r"(?i)document\.(cookie|location)",
            r"(?i)<svg[\s/>]",
        ],
    ),
    "lfi": (
        "high",
        [
            r"\.\./",
            r"\.\.\\",
            r"(?i)/etc/passwd",
            r"(?i)/proc/self/environ",
            r"(?i)\b(boot\.ini|win\.ini)\b",
            r"(?i)php://(filter|input)",
            r"(?i)file://",
        ],
    ),
    "cmdi": (
        "high",
        [
            r"(?i);\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b",
            r"(?i)\|\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b",
            r"(?i)`[^`]+`",
            r"\$\([^)]+\)",
            r"(?i)&&\s*(cat|ls|id|whoami|ping)\b",
        ],
    ),
    "ssti": (
        "high",
        [
            r"\{\{.*\}\}",
            r"\{%.*%\}",
            r"(?i)\$\{.*\}",
        ],
    ),
    "lfi_rce_upload": (
        "high",
        [
            r"(?i)\.(php|phtml|jsp|asp|aspx|sh|py)\b.*(shell|cmd|c99|r57|b374k)",
            r"(?i)(c99|r57|b374k|wso)\.php",
        ],
    ),
}

# Tools that announce themselves in the User-Agent. Catching these tells you the
# attacker is running automated tooling, which is gold for the report.
_SCANNER_UA = re.compile(
    r"(?i)\b(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|ffuf|wfuzz|nuclei|"
    r"acunetix|nessus|openvas|hydra|wpscan|zgrab|curl|python-requests|"
    r"go-http-client|httpx|feroxbuster)\b"
)

_COMPILED: dict[str, tuple[str, list[re.Pattern]]] = {
    cat: (sev, [re.compile(p) for p in pats]) for cat, (sev, pats) in _SIGNATURES.items()
}


def _scan_value(field: str, value: str) -> list[Finding]:
    findings: list[Finding] = []
    if not value:
        return findings
    for category, (severity, patterns) in _COMPILED.items():
        for pat in patterns:
            if pat.search(value):
                findings.append(
                    Finding(category=category, field=field, payload=value[:500], severity=severity)
                )
                break  # one hit per category per field is enough
    return findings


def scan_request(
    *,
    path: str,
    query: dict[str, str],
    form: dict[str, str],
    headers: dict[str, str],
    raw_body: str = "",
) -> list[dict]:
    """Run all detectors over a request and return findings as plain dicts."""
    findings: list[Finding] = []

    findings += _scan_value("path", path)

    for key, val in query.items():
        findings += _scan_value(f"query:{key}", val)

    for key, val in form.items():
        findings += _scan_value(f"body:{key}", val)

    if raw_body and not form:
        findings += _scan_value("body:raw", raw_body)

    # A couple of headers are common injection vectors too.
    for hk in ("User-Agent", "Referer", "X-Forwarded-For", "Cookie"):
        if hk in headers:
            findings += _scan_value(f"header:{hk}", headers[hk])

    ua = headers.get("User-Agent", "")
    if _SCANNER_UA.search(ua):
        findings.append(
            Finding(category="scanner", field="header:User-Agent", payload=ua[:300], severity="medium")
        )

    return [f.as_dict() for f in findings]


def summarize(findings: Iterable[dict]) -> dict:
    """Roll findings up into counts per category — handy for the dashboard."""
    counts: dict[str, int] = {}
    top_severity = "low"
    order = {"low": 0, "medium": 1, "high": 2}
    for f in findings:
        counts[f["category"]] = counts.get(f["category"], 0) + 1
        if order[f["severity"]] > order[top_severity]:
            top_severity = f["severity"]
    return {"categories": counts, "severity": top_severity, "total": sum(counts.values())}
