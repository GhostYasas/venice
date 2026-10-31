"""
email_address.py
Checks for a standalone email address: syntax validity, domain existence,
mail server (MX) setup, and disposable-email providers.
"""

import re
import socket

from checks.brand_lookalike import check_brand_lookalike

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
    "yopmail.com", "throwawaymail.com", "trashmail.com", "getnada.com",
    "temp-mail.org", "fakeinbox.com", "maildrop.cc",
}


def check_syntax(email: str) -> dict:
    if EMAIL_REGEX.match(email):
        return None
    return {
        "severity": "high",
        "message": f"'{email}' does not look like a valid email address format."
    }


def get_domain(email: str) -> str:
    return email.split("@")[-1].lower().strip()


def check_domain_exists(domain: str) -> tuple:
    try:
        socket.getaddrinfo(domain, None)
        return True, None
    except socket.gaierror:
        return False, {
            "severity": "high",
            "message": f"Domain '{domain}' does not resolve — it may not exist, "
                       f"or you have no internet connection right now."
        }


def check_mx_records(domain: str) -> dict:
    if not DNS_AVAILABLE:
        return {
            "severity": "low",
            "message": "MX record check skipped — 'dnspython' is not installed. "
                       "Run: pip install dnspython"
        }
    try:
        answers = dns.resolver.resolve(domain, "MX")
        if len(answers) == 0:
            return {
                "severity": "high",
                "message": f"Domain '{domain}' has no MX records — it cannot receive email, "
                           f"so an address at this domain is likely fake."
            }
        return None
    except dns.resolver.NXDOMAIN:
        return {"severity": "high", "message": f"Domain '{domain}' does not exist (NXDOMAIN)."}
    except dns.resolver.NoAnswer:
        return {"severity": "high", "message": f"Domain '{domain}' has no MX records — it cannot receive email."}
    except Exception as e:
        return {"severity": "low", "message": f"Could not check MX records for '{domain}' ({e})."}


def check_disposable(domain: str) -> dict:
    if domain in DISPOSABLE_DOMAINS:
        return {
            "severity": "medium",
            "message": f"'{domain}' is a known disposable/throwaway email provider. "
                       f"Common for spam, fake signups, or avoiding traceability — "
                       f"not necessarily malicious, but worth noting."
        }
    return None


def run_all_checks(email: str) -> list:
    findings = []

    syntax_issue = check_syntax(email)
    if syntax_issue:
        findings.append(syntax_issue)
        return findings

    domain = get_domain(email)

    exists, exists_finding = check_domain_exists(domain)
    if exists_finding:
        findings.append(exists_finding)

    if exists:
        mx_finding = check_mx_records(domain)
        if mx_finding:
            findings.append(mx_finding)

    disposable_finding = check_disposable(domain)
    if disposable_finding:
        findings.append(disposable_finding)

    lookalike_finding = check_brand_lookalike(domain)
    if lookalike_finding:
        findings.append(lookalike_finding)

    return findings
