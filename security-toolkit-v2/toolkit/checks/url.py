"""
url.py
Flags suspicious characteristics in a URL: IP-based links, URL shorteners,
'@' tricks, lookalike domains, punycode, and excessive subdomain nesting.
Used both standalone (checking one pasted link) and inside the email
analyzer (checking every link found in a message body).
"""

import re
from urllib.parse import urlparse

from checks.brand_lookalike import check_brand_lookalike

IP_URL_REGEX = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "shorturl.at", "cutt.ly"
}


def check_single_url(url: str) -> list:
    """Runs every suspicious-pattern check against one URL and returns findings."""
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if not parsed.scheme or not host:
        findings.append({
            "severity": "medium",
            "message": f"'{url}' doesn't look like a complete URL (missing http(s):// or host)."
        })
        return findings

    if IP_URL_REGEX.match(url):
        findings.append({
            "severity": "high",
            "message": f"URL uses a raw IP address instead of a domain: {url}"
        })

    if host in KNOWN_SHORTENERS:
        findings.append({
            "severity": "medium",
            "message": f"URL uses a link shortener ({host}), which hides the real destination: {url}"
        })

    # Only flag '@' if it appears BEFORE the host in the URL's authority
    # section (the real browser trick: http://real.com@evil.com/), not when
    # it's just part of a later query string like ?user=name@email.com
    authority = url.split("//", 1)[-1].split("/", 1)[0]
    if "@" in authority:
        findings.append({
            "severity": "high",
            "message": f"URL contains '@' before the host, a classic trick to hide "
                       f"the real destination: {url}"
        })

    if host.startswith("xn--") or ".xn--" in host:
        findings.append({
            "severity": "high",
            "message": f"URL uses punycode encoding (possible lookalike character attack): {url}"
        })

    if host.count(".") >= 4:
        findings.append({
            "severity": "low",
            "message": f"URL has an unusually high number of subdomains: {url}"
        })

    lookalike = check_brand_lookalike(host)
    if lookalike:
        lookalike = dict(lookalike)
        lookalike["message"] += f" (found in URL: {url})"
        findings.append(lookalike)

    return findings


def analyze_urls(urls: list) -> list:
    """Runs check_single_url across a list of URLs (e.g. from an email body)."""
    findings = []
    for url in urls:
        findings.extend(check_single_url(url))
    return findings
