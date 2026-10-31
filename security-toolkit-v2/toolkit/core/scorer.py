"""
scorer.py
Aggregates findings from any checker into a single 0-100 risk score
and a human-readable risk label.
"""

SEVERITY_WEIGHTS = {
    "high": 55,
    "medium": 25,
    "low": 10,
}


def score_findings(all_findings: list, labels: dict = None) -> dict:
    """
    Takes a flat list of finding dicts (each with a 'severity' key) and
    returns a score (capped at 100) plus a risk label.

    `labels` lets callers customize the label text per risk tier, e.g.
    {"high": "HIGH RISK — likely phishing", ...}. Falls back to generic text.
    """
    score = 0
    for finding in all_findings:
        score += SEVERITY_WEIGHTS.get(finding.get("severity", "low"), 0)

    score = min(score, 100)
    labels = labels or {}

    if score >= 55:
        label = labels.get("high", "HIGH RISK")
    elif score >= 25:
        label = labels.get("medium", "MEDIUM RISK")
    elif score > 0:
        label = labels.get("low", "LOW RISK")
    else:
        label = labels.get("clean", "CLEAN — no indicators found")

    return {
        "score": score,
        "label": label,
        "findings": all_findings,
    }
