"""
brand_lookalike.py
Detects when a domain impersonates a known brand — including patterns like
'paypa1-security.com' or 'amaz0n-billing.net', where the brand name is
embedded alongside extra words, not just a 1:1 typosquat of the whole domain.
"""

import re
import difflib

COMMON_BRAND_NAMES = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "bankofamerica", "chase", "facebook", "instagram", "outlook",
    "gmail", "dropbox", "docusign", "linkedin", "wellsfargo", "ebay",
]


def _strip_tld(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[:-1]) if len(parts) > 1 else domain


def _tokenize(domain_body: str) -> list:
    return [t for t in re.split(r"[^a-z0-9]+", domain_body.lower()) if t]


def check_brand_lookalike(domain: str, threshold: float = 0.75) -> dict:
    """
    Flags a domain if any token within it closely resembles a known brand
    name but isn't an exact match (e.g. 'paypa1' in 'paypa1-security.com').
    Returns a finding dict, or None if nothing suspicious is found.
    """
    domain = domain.lower().strip()
    body = _strip_tld(domain)
    tokens = _tokenize(body)

    best_brand, best_token, best_ratio = None, None, 0.0

    for token in tokens:
        for brand in COMMON_BRAND_NAMES:
            if token == brand:
                continue
            ratio = difflib.SequenceMatcher(None, token, brand).ratio()
            if ratio > best_ratio:
                best_ratio, best_brand, best_token = ratio, brand, token

    if best_ratio >= threshold:
        return {
            "severity": "high",
            "message": f"'{domain}' contains '{best_token}', which closely resembles "
                       f"the brand name '{best_brand}' — likely impersonation."
        }
    return None
