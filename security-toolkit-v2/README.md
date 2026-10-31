# Security Toolkit

A colorized CLI with four email/code-security checks in one tool:

1. **Email address check** — is a single address fake, disposable, or
   impersonating a known brand?
2. **Full email check** — load a `.eml` file and check SPF/DKIM/DMARC,
   sender mismatches, suspicious links, and social-engineering language.
3. **Paste a forwarded email** — same analysis as #2, but works from
   plain copy-pasted text (just hit "Forward" on the email, no export
   needed). Gracefully explains which checks couldn't run if auth headers
   aren't present.
4. **Standalone URL check** — paste any single link (text, DM, QR code)
   and check it for suspicious patterns.
5. **Secrets scanner** — scan a code folder for hardcoded API keys,
   passwords, and tokens before you commit them.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

**Interactive menu:**
```bash
cd toolkit
python main.py
```

**Direct mode:**
```bash
python main.py address someone@example.com
python main.py email path/to/file.eml
python main.py paste < forwarded_email.txt
python main.py url http://example.com/some/link
python main.py scan path/to/code/folder
```

## Project structure

```
security-toolkit/
├── README.md
├── requirements.txt
└── toolkit/
    ├── main.py                    # CLI entry point (menu + direct mode)
    ├── core/
    │   ├── ui.py                  # Colored terminal output, risk bar, banner
    │   └── scorer.py              # Shared 0-100 risk scoring logic
    ├── checks/
    │   ├── brand_lookalike.py     # Shared brand-impersonation detector
    │   ├── email_address.py       # Standalone address checks
    │   ├── headers.py             # SPF/DKIM/DMARC + sender mismatch
    │   ├── url.py                 # Suspicious URL patterns (standalone + email use)
    │   ├── content.py             # Urgency/credential-request language
    │   └── secrets.py             # Hardcoded secret pattern scanner
    └── parsers/
        └── email_parser.py        # Parses .eml files AND pasted/forwarded text
```

## Design notes

- **Risk scoring**: a single HIGH-severity finding is enough to reach the
  "high risk" tier on its own — one serious red flag (failed SPF+DKIM, a
  raw-IP phishing link, an exposed AWS key) deserves immediate attention,
  not a watered-down "medium" score just because few other checks fired.
- **Brand lookalike detection** tokenizes the domain and checks each piece
  individually, so it catches patterns like `paypa1-security.com` or
  `amaz0n-billing.net` — not just exact 1:1 typosquats of a brand's whole
  domain.
- **The `@` URL check** only flags `@` when it appears before the host
  (the actual phishing trick: `http://real.com@evil.com/`), not when it's
  part of a later query string like `?user=name@email.com`.
- **Secrets scanner** redacts matched values (shows first/last 4 chars
  only) so real secrets are never printed in full, even in your own
  terminal output or screenshots.

## Limitations

- Brand, disposable-domain, and secret-pattern lists are small curated
  samples, not production-scale/maintained lists.
- No live threat-intel API calls (VirusTotal, Safe Browsing, etc.) —
  everything runs from local parsing, regex, and DNS lookups only.
- The URL checker analyzes link *structure* only — it never visits the
  URL, so it can't tell you what's actually on the page.
- The secrets scanner is pattern-based — it can both miss creatively
  named secrets and occasionally flag non-secret strings that happen to
  match a pattern. Always review findings manually before acting on them.

## Possible future extensions

- Live reputation lookups (VirusTotal, Google Safe Browsing) with an
  optional API key
- Password breach checker (via Have I Been Pwned's k-anonymity API)
- WHOIS domain-age lookups
- JSON/CSV export of scan results for a "scan history" view
