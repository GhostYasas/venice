"""
content.py
Scans email body text for common social-engineering language: urgency,
threats, requests for credentials, and generic greetings.
"""

import re

URGENCY_PHRASES = [
    "act now", "urgent", "immediately", "verify your account",
    "your account will be", "suspended", "unauthorized access",
    "unusual activity", "confirm your identity", "click here",
    "limited time", "failure to", "within 24 hours", "final notice",
]

CREDENTIAL_PHRASES = [
    "enter your password", "confirm your password", "update your payment",
    "ssn", "social security number", "login to verify", "re-enter your",
    "credit card number", "security code",
]

GENERIC_GREETING_REGEX = re.compile(
    r"\b(dear (customer|user|valued customer|member)|dear sir/madam)\b",
    re.IGNORECASE
)


def analyze_content(body_text: str) -> list:
    findings = []
    lowered = body_text.lower()

    urgency_hits = [p for p in URGENCY_PHRASES if p in lowered]
    if urgency_hits:
        findings.append({
            "severity": "medium",
            "message": f"Urgency/pressure language detected: {', '.join(urgency_hits[:5])}"
        })

    credential_hits = [p for p in CREDENTIAL_PHRASES if p in lowered]
    if credential_hits:
        findings.append({
            "severity": "high",
            "message": f"Direct request for sensitive credentials/info: {', '.join(credential_hits[:5])}"
        })

    if GENERIC_GREETING_REGEX.search(body_text):
        findings.append({
            "severity": "low",
            "message": "Generic greeting detected (e.g. 'Dear Customer') — "
                       "legitimate senders usually use your real name."
        })

    return findings
