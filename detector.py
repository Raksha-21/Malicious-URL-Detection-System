"""
detector.py
-----------
Heuristic-based Malicious URL feature extraction and scoring engine.

This module intentionally contains NO machine learning, NO external API
calls, and NO database access. It only performs structural / statistical
analysis of a URL string and applies a fixed set of rule-based heuristics.

Public API:
    detect_url(url: str) -> dict
"""

import re
import math
from urllib.parse import urlparse, parse_qs

# --------------------------------------------------------------------------
# Static heuristic data (do not change casually — UI depends on these)
# --------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "verify", "login", "account", "update", "secure", "banking",
    "paypal", "admin", "confirm", "credential", "signin", "password",
    "wallet",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".work", ".click", ".loans",
    ".gq", ".cf", ".tk", ".ml", ".ga",
]

SENSITIVE_QUERY_KEYS = [
    "token", "password", "secret", "api_key", "apikey", "credential",
    "auth", "session", "key",
]

IP_HOST_REGEX = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

# Point values for each heuristic rule. UI reads these indirectly through
# reason_details — do not need to hardcode point values in the UI layer.
POINTS = {
    "no_https": 1,
    "ip_host": 3,
    "at_symbol": 2,
    "double_slash_path": 2,
    "long_url": 1,
    "very_long_url": 1,
    "long_hostname": 1,
    "excess_dots": 1,
    "excess_hyphens": 1,
    "excess_slashes": 1,
    "excess_special_chars": 1,
    "high_entropy": 2,
    "suspicious_keyword_unit": 1,   # per keyword, capped
    "suspicious_keyword_cap": 3,    # max points from keywords combined
    "suspicious_tld": 2,
}

MAX_SCORE = 20


# --------------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy (bits) of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    host = host.split(":")[0]  # strip port if present
    match = IP_HOST_REGEX.match(host)
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def _normalize_url(raw_url: str) -> str:
    """Add a scheme if the user omitted one, so parsing works predictably."""
    raw_url = raw_url.strip()
    if not raw_url:
        return raw_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "http://" + raw_url
    return raw_url


def _mask_value(value: str) -> str:
    """Mask a sensitive query parameter value for display."""
    if not value:
        return "••••••"
    if len(value) <= 4:
        return "•" * len(value)
    return value[:2] + "•" * (len(value) - 2)


def _validate(url: str) -> bool:
    """Minimal structural validity check."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        host = parsed.hostname or ""
        if not host:
            return False
        # Must contain at least one dot, OR be a valid IP, OR be 'localhost'
        if "." not in host and not _is_ip_host(host) and host != "localhost":
            return False
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# Main detection function
# --------------------------------------------------------------------------

def detect_url(raw_url: str) -> dict:
    """
    Analyze a URL and return a dict containing:
        is_valid, url, score, max_score, severity, result,
        reason_details (list of {label, points, detail}),
        features (dict of extracted structural features),
        structure (protocol/host/path/query breakdown, masked),
        suspicious_keywords_found (list[str]),
        suspicious_tld_found (str or None)
    """
    original_input = raw_url or ""
    url = _normalize_url(original_input)

    if not url or not _validate(url):
        return {
            "is_valid": False,
            "url": original_input,
            "score": 0,
            "max_score": MAX_SCORE,
            "severity": None,
            "result": None,
            "reason_details": [],
            "features": {},
            "structure": {},
            "suspicious_keywords_found": [],
            "suspicious_tld_found": None,
        }

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_lower = url.lower()

    # ---- raw structural counts ----
    url_length = len(url)
    hostname_length = len(host)
    path_length = len(path)
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    slash_count = url.count("/")
    special_chars = re.findall(r"[^a-zA-Z0-9\-\.\/:_]", url)
    special_char_count = len(special_chars)
    entropy = _shannon_entropy(host + path)
    https_used = parsed.scheme == "https"
    ip_host = _is_ip_host(host)
    at_symbol_present = "@" in url
    # double slash in path (excluding the protocol's //)
    path_after_scheme = url.split("://", 1)[-1]
    double_slash_in_path = "//" in path_after_scheme.split("?")[0].split("/", 1)[-1] if "/" in path_after_scheme else False

    # ---- suspicious keywords ----
    keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_lower]

    # ---- suspicious TLD ----
    tld_found = None
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            tld_found = tld
            break

    # ----------------------------------------------------------------
    # Scoring — build reason_details as we go so UI and score always match
    # ----------------------------------------------------------------
    reason_details = []
    score = 0

    def add(label, points, detail=""):
        nonlocal score
        score += points
        reason_details.append({"label": label, "points": points, "detail": detail})

    if not https_used:
        add("No HTTPS", POINTS["no_https"], "Connection is not encrypted")

    if ip_host:
        add("Raw IP address used as host", POINTS["ip_host"], host)

    if at_symbol_present:
        add("'@' symbol present in URL", POINTS["at_symbol"],
            "Can be used to obscure the real destination")

    if double_slash_in_path:
        add("Double slash in path", POINTS["double_slash_path"],
            "Unusual redirection pattern")

    if url_length > 75:
        add("Long URL", POINTS["long_url"], f"{url_length} characters")
        if url_length > 150:
            add("Very long URL", POINTS["very_long_url"], f"{url_length} characters")

    if hostname_length > 30:
        add("Long hostname", POINTS["long_hostname"], f"{hostname_length} characters")

    if dot_count > 3:
        add("Excessive dots", POINTS["excess_dots"], f"{dot_count} dots")

    if hyphen_count > 2:
        add("Excessive hyphens", POINTS["excess_hyphens"], f"{hyphen_count} hyphens")

    if slash_count > 5:
        add("Excessive slashes", POINTS["excess_slashes"], f"{slash_count} slashes")

    if special_char_count > 5:
        add("Excessive special characters", POINTS["excess_special_chars"],
            f"{special_char_count} special characters")

    if entropy > 4.0:
        add("High character entropy", POINTS["high_entropy"], f"entropy = {entropy}")

    if keywords_found:
        kw_points = min(len(keywords_found) * POINTS["suspicious_keyword_unit"],
                         POINTS["suspicious_keyword_cap"])
        add("Suspicious keywords: " + ", ".join(keywords_found), kw_points,
            ", ".join(keywords_found))

    if tld_found:
        add(f"Suspicious TLD: {tld_found}", POINTS["suspicious_tld"], tld_found)

    score = min(score, MAX_SCORE)

    # ---- severity ----
    if score <= 2:
        severity = "LOW"
        result = "Likely Safe"
    elif score <= 4:
        severity = "MEDIUM"
        result = "Suspicious URL"
    elif score <= 6:
        severity = "HIGH"
        result = "Suspicious URL"
    else:
        severity = "CRITICAL"
        result = "Likely Malicious"

    # ---- query param breakdown (masked) ----
    query_display = "None"
    if query:
        parsed_qs = parse_qs(query, keep_blank_values=True)
        parts = []
        for key, values in parsed_qs.items():
            value = values[0] if values else ""
            if key.lower() in SENSITIVE_QUERY_KEYS:
                value = _mask_value(value)
            parts.append(f"{key}={value}")
        query_display = "&".join(parts) if parts else "None"

    structure = {
        "protocol": (parsed.scheme or "unknown").upper(),
        "host": host or "unknown",
        "path": path or "/",
        "query": query_display,
    }

    features = {
        "URL Length": url_length,
        "Hostname Length": hostname_length,
        "Path Length": path_length,
        "Dot Count": dot_count,
        "Hyphen Count": hyphen_count,
        "Slash Count": slash_count,
        "Special Character Count": special_char_count,
        "Shannon Entropy": entropy,
        "HTTPS Encryption": https_used,
        "Raw IP Host Address": ip_host,
        "@ Symbol Present": at_symbol_present,
        "Suspicious Keywords": bool(keywords_found),
        "Suspicious TLD": bool(tld_found),
        "Double Slash in Path": double_slash_in_path,
    }

    return {
        "is_valid": True,
        "url": url,
        "score": score,
        "max_score": MAX_SCORE,
        "severity": severity,
        "result": result,
        "reason_details": reason_details,
        "features": features,
        "structure": structure,
        "suspicious_keywords_found": keywords_found,
        "suspicious_tld_found": tld_found,
    }


# --------------------------------------------------------------------------
# Quick self-test when run directly
# --------------------------------------------------------------------------
if __name__ == "__main__":
    test_urls = [
        "https://www.wikipedia.org/",
        "http://secure-login-example.xyz/verify-account?token=abc123456",
        "http://192.168.1.10/paypal/login/confirm@evil.com//redirect",
    ]
    for u in test_urls:
        result = detect_url(u)
        print(u, "->", result["score"], result["severity"])
