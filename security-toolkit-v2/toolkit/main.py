#!/usr/bin/env python3
"""
Security Toolkit

Usage (interactive menu):
    python main.py

Usage (direct mode):
    python main.py address someone@example.com
    python main.py email path/to/file.eml
    python main.py paste < raw_or_forwarded_email.txt
    python main.py url http://example.com/some/link
    python main.py scan path/to/code/folder
"""

import sys

from core import ui
from core.scorer import score_findings

from checks.email_address import run_all_checks as check_address
from checks.headers import check_auth_results, check_sender_mismatch
from checks.url import analyze_urls, check_single_url
from checks.content import analyze_content
from checks.secrets import scan_directory

from parsers.email_parser import parse_eml, parse_raw_text


ADDRESS_LABELS = {
    "high": "HIGH RISK — this address looks fake or spoofed",
    "medium": "MEDIUM RISK — some flags, worth double-checking",
    "low": "LOW RISK — minor flags only",
    "clean": "LOOKS FINE — no red flags found",
}

EMAIL_LABELS = {
    "high": "HIGH RISK — likely phishing",
    "medium": "MEDIUM RISK — suspicious, review carefully",
    "low": "LOW RISK — minor flags, probably legitimate",
    "clean": "CLEAN — no indicators found",
}

URL_LABELS = {
    "high": "HIGH RISK — this link looks malicious",
    "medium": "MEDIUM RISK — suspicious, be cautious",
    "low": "LOW RISK — minor flags only",
    "clean": "LOOKS FINE — no red flags found",
}

SECRETS_LABELS = {
    "high": "SECRETS FOUND — rotate these credentials now",
    "medium": "POSSIBLE SECRETS — review before committing",
    "low": "MINOR FLAGS — likely low risk",
    "clean": "CLEAN — no obvious secrets found",
}


# ── Address check ──────────────────────────────────────────────

def run_address_check(email: str):
    findings = check_address(email)
    result = score_findings(findings, ADDRESS_LABELS)

    ui.section_title("EMAIL ADDRESS CHECK")
    ui.kv("Checked", email)
    ui.print_risk_result(result["score"], result["label"])
    ui.print_findings(result["findings"])
    ui.divider()
    ui.print_note("A clean result means the domain is technically valid —")
    ui.print_note("it does NOT prove the sender is trustworthy.")


# ── Full email check (shared by file + paste) ─────────────────

def _run_email_analysis(parsed):
    all_findings = []

    auth_results, auth_findings = check_auth_results(parsed.authentication_results)
    all_findings.extend(auth_findings)
    all_findings.extend(check_sender_mismatch(parsed.from_addr, parsed.reply_to, parsed.return_path))
    all_findings.extend(analyze_urls(parsed.urls))
    all_findings.extend(analyze_content(parsed.body_text))

    result = score_findings(all_findings, EMAIL_LABELS)

    ui.section_title("PHISHING EMAIL ANALYSIS")
    ui.kv("Subject", parsed.subject or "(none found)")
    ui.kv("From", parsed.from_addr or "(none found)")
    ui.kv("SPF/DKIM/DMARC", str(auth_results))
    ui.kv("URLs found", str(len(parsed.urls)))
    if parsed.attachments:
        ui.kv("Attachments", ", ".join(parsed.attachments))

    if parsed.limited_headers:
        ui.divider()
        ui.print_note("This looks like a forwarded email, not raw source —")
        ui.print_note("SPF/DKIM/DMARC and Reply-To/Return-Path checks could not run.")
        ui.print_note("Link and content checks below are still fully accurate.")

    ui.print_risk_result(result["score"], result["label"])
    ui.print_findings(result["findings"])


def run_email_check(file_path: str):
    try:
        parsed = parse_eml(file_path)
    except FileNotFoundError:
        ui.print_error(f"File not found — {file_path}")
        return
    _run_email_analysis(parsed)


def run_email_check_from_paste(raw_text: str):
    if not raw_text.strip():
        ui.print_error("No text was pasted.")
        return
    parsed = parse_raw_text(raw_text)
    _run_email_analysis(parsed)


# ── Standalone URL check ───────────────────────────────────────

def run_url_check(url: str):
    findings = check_single_url(url)
    result = score_findings(findings, URL_LABELS)

    ui.section_title("URL CHECK")
    ui.kv("Checked", url)
    ui.print_risk_result(result["score"], result["label"])
    ui.print_findings(result["findings"])
    ui.divider()
    ui.print_note("This checks the URL's structure only — it does not visit")
    ui.print_note("the site. A clean result doesn't guarantee the page is safe.")


# ── Secrets scanner ─────────────────────────────────────────────

def run_secrets_scan(path: str):
    findings = scan_directory(path)
    result = score_findings(findings, SECRETS_LABELS)

    ui.section_title("SECRETS SCAN")
    ui.kv("Scanned", path)
    ui.kv("Findings", str(len(findings)))
    ui.print_risk_result(result["score"], result["label"])
    ui.print_findings(result["findings"])
    ui.divider()
    ui.print_note("Values are partially redacted. Rotate any real credentials")
    ui.print_note("found here and move them to environment variables / a .env file.")


# ── Interactive menu ────────────────────────────────────────────

def _read_pasted_block() -> str:
    print()
    ui.print_note("Paste the email text below, then type END on its own line.")
    ui.print_note("Easiest source: open the email, click Forward (don't send),")
    ui.print_note("select all the text in the forward box, copy, paste here.")
    print()
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def interactive_menu():
    ui.print_banner()
    ui.menu_option("1", "Check an email address")
    ui.menu_option("2", "Check a full email file (.eml)")
    ui.menu_option("3", "Paste a forwarded email (no file needed)")
    ui.menu_option("4", "Check a single URL")
    ui.menu_option("5", "Scan a code folder for hardcoded secrets")
    ui.menu_option("6", "Quit")
    ui.divider()
    choice = input("  Choose an option (1-6): ").strip()
    print()

    if choice == "1":
        email = input("  Enter the email address to check: ").strip()
        print()
        run_address_check(email)
    elif choice == "2":
        path = input("  Enter the path to the .eml file: ").strip()
        print()
        run_email_check(path)
    elif choice == "3":
        raw_text = _read_pasted_block()
        print()
        run_email_check_from_paste(raw_text)
    elif choice == "4":
        url = input("  Enter the URL to check: ").strip()
        print()
        run_url_check(url)
    elif choice == "5":
        path = input("  Enter the folder path to scan: ").strip()
        print()
        run_secrets_scan(path)
    elif choice == "6":
        sys.exit(0)
    else:
        ui.print_error("Invalid choice.")


def main():
    if len(sys.argv) == 3 and sys.argv[1] in ("address", "email", "url", "scan"):
        mode, arg = sys.argv[1], sys.argv[2]
        if mode == "address":
            run_address_check(arg)
        elif mode == "email":
            run_email_check(arg)
        elif mode == "url":
            run_url_check(arg)
        elif mode == "scan":
            run_secrets_scan(arg)
        return

    if len(sys.argv) == 2 and sys.argv[1] == "paste":
        raw_text = sys.stdin.read()
        run_email_check_from_paste(raw_text)
        return

    while True:
        interactive_menu()
        print()
        input(f"  Press Enter to return to the menu...")
        print()


if __name__ == "__main__":
    main()
