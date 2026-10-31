"""
secrets.py
Scans a directory of source files for hardcoded secrets: API keys,
passwords, tokens, and private key blocks. Pattern-based (regex), not a
live credential validator — flags things that LOOK like secrets so a human
can review and rotate/remove them before committing.
"""

import os
import re

# Directories we never want to crawl into (dependency folders, VCS internals)
SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "env", "dist", "build"}

# File extensions worth scanning as text. Binary files are skipped.
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml", ".env",
    ".txt", ".md", ".cfg", ".ini", ".sh", ".bash", ".ps1", ".java", ".go",
    ".rb", ".php", ".html", ".xml", ".toml", ".conf",
}

# Each pattern: (name, compiled regex, severity). The regex should capture
# the secret-like value in group(1) if possible, so we can redact it.
PATTERNS = [
    ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "high"),
    ("AWS Secret Key (assignment)",
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), "high"),
    ("Private Key Block",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high"),
    ("Slack Token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), "high"),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "high"),
    ("Generic API Key / Secret Assignment",
     re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*"
                r"['\"]([A-Za-z0-9\-_\.]{16,})['\"]"), "high"),
    ("Hardcoded Password Assignment",
     re.compile(r"(?i)password\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]"), "medium"),
    ("JWT-looking Token", re.compile(r"\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"), "medium"),
    ("Credentials in URL", re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:]+:([^/\s@]{3,})@"), "medium"),
]


def _redact(value: str) -> str:
    """Shows only the first/last couple characters so the real secret isn't printed in full."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _should_scan_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext.lower() in TEXT_EXTENSIONS or filename in {".env", "Dockerfile"}


def scan_directory(root_path: str) -> list:
    """
    Walks root_path recursively and scans every eligible text file for
    secret-like patterns. Returns a flat list of findings, each including
    the file path and line number.
    """
    findings = []

    if not os.path.isdir(root_path):
        return [{
            "severity": "high",
            "message": f"'{root_path}' is not a valid directory."
        }]

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            if not _should_scan_file(filename):
                continue

            file_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(file_path, root_path)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except (OSError, UnicodeDecodeError):
                continue

            for line_num, line in enumerate(lines, start=1):
                for name, pattern, severity in PATTERNS:
                    match = pattern.search(line)
                    if match:
                        # Use the LAST capture group as the secret value (patterns
                        # with 2 groups capture the key name first, value second).
                        groups = match.groups()
                        secret_value = groups[-1] if groups else match.group(0)
                        findings.append({
                            "severity": severity,
                            "message": f"{name} found in {rel_path}:{line_num} "
                                       f"→ {_redact(secret_value)}"
                        })

    return findings
