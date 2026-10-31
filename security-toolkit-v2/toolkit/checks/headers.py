"""
headers.py
Looks at email authentication headers (SPF/DKIM/DMARC) and sender-identity
fields (From / Reply-To / Return-Path) for signs of spoofing.
"""

import re
from email.utils import parseaddr


def check_auth_results(auth_header: str) -> tuple:
    results = {"spf": "not_found", "dkim": "not_found", "dmarc": "not_found"}
    findings = []

    if not auth_header:
        findings.append({
            "severity": "medium",
            "message": "No Authentication-Results header found — "
                       "SPF/DKIM/DMARC could not be verified from this header alone."
        })
        return results, findings

    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()

    for mechanism, verdict in results.items():
        if verdict == "fail":
            findings.append({
                "severity": "high",
                "message": f"{mechanism.upper()} check FAILED — strong signal of spoofing."
            })
        elif verdict == "softfail":
            findings.append({
                "severity": "medium",
                "message": f"{mechanism.upper()} returned softfail — sender may not be fully authorized."
            })
        elif verdict == "not_found":
            findings.append({
                "severity": "low",
                "message": f"{mechanism.upper()} result not present in headers."
            })

    return results, findings


def check_sender_mismatch(from_addr: str, reply_to: str, return_path: str) -> list:
    findings = []

    def domain_of(addr: str) -> str:
        _, email_addr = parseaddr(addr)
        if "@" in email_addr:
            return email_addr.split("@")[-1].lower()
        return ""

    from_domain = domain_of(from_addr)
    reply_domain = domain_of(reply_to)
    return_domain = domain_of(return_path)

    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append({
            "severity": "high",
            "message": f"Reply-To domain ('{reply_domain}') does not match "
                       f"From domain ('{from_domain}') — replies would go to a different party."
        })

    if return_domain and from_domain and return_domain != from_domain:
        findings.append({
            "severity": "medium",
            "message": f"Return-Path domain ('{return_domain}') does not match "
                       f"From domain ('{from_domain}') — possible spoofed sender."
        })

    return findings
