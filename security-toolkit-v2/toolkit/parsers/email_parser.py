"""
email_parser.py
Parses email content (from a .eml file, pasted raw source, OR a casually
forwarded email) into a normalized structure the checkers can work with.
"""

import re
from email import policy
from email.parser import BytesParser, Parser
from dataclasses import dataclass, field


@dataclass
class ParsedEmail:
    subject: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to_addr: str = ""
    date: str = ""
    authentication_results: str = ""
    received_headers: list = field(default_factory=list)
    body_text: str = ""
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    limited_headers: bool = False  # True for a casual forward — auth headers won't exist


URL_REGEX = re.compile(r'https?://[^\s<>"\')\]]+')

# Matches the header block Gmail/Outlook/Apple Mail insert automatically
# when you hit "Forward" on an email.
FORWARD_FROM_REGEX = re.compile(r"^From:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
FORWARD_SUBJECT_REGEX = re.compile(r"^Subject:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
FORWARD_DATE_REGEX = re.compile(r"^Date:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
FORWARD_TO_REGEX = re.compile(r"^To:\s*(.+)$", re.MULTILINE | re.IGNORECASE)


def parse_eml(file_path: str) -> ParsedEmail:
    """Load a .eml file from disk and return a ParsedEmail object."""
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return _parsed_from_message(msg)


def parse_raw_text(raw_text: str) -> ParsedEmail:
    """
    Parse pasted email text — either true raw source (From 'Show original')
    or a casually forwarded email (just hit Forward, paste the result).
    Falls back to regex extraction of the "Forwarded message" header block
    when strict RFC822 parsing finds nothing.
    """
    msg = Parser(policy=policy.default).parsestr(raw_text)
    parsed = _parsed_from_message(msg)

    if not parsed.from_addr and not parsed.subject:
        parsed.limited_headers = True

        from_match = FORWARD_FROM_REGEX.search(raw_text)
        subject_match = FORWARD_SUBJECT_REGEX.search(raw_text)
        date_match = FORWARD_DATE_REGEX.search(raw_text)
        to_match = FORWARD_TO_REGEX.search(raw_text)

        parsed.from_addr = from_match.group(1).strip() if from_match else ""
        parsed.subject = subject_match.group(1).strip() if subject_match else ""
        parsed.date = date_match.group(1).strip() if date_match else ""
        parsed.to_addr = to_match.group(1).strip() if to_match else ""

        parsed.body_text = raw_text
        parsed.urls = list(set(URL_REGEX.findall(raw_text)))

    return parsed


def _parsed_from_message(msg) -> ParsedEmail:
    parsed = ParsedEmail()
    parsed.subject = msg.get("Subject", "")
    parsed.from_addr = msg.get("From", "")
    parsed.reply_to = msg.get("Reply-To", "")
    parsed.return_path = msg.get("Return-Path", "")
    parsed.to_addr = msg.get("To", "")
    parsed.date = msg.get("Date", "")
    parsed.authentication_results = msg.get("Authentication-Results", "")
    parsed.received_headers = msg.get_all("Received", [])

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")

            if "attachment" in disposition:
                parsed.attachments.append(part.get_filename() or "unnamed_attachment")
                continue

            if content_type == "text/plain" and not body:
                body = part.get_content()
            elif content_type == "text/html" and not body:
                html = part.get_content()
                body = re.sub(r"<[^>]+>", " ", html)
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            body = msg.get_content()
        elif content_type == "text/html":
            html = msg.get_content()
            body = re.sub(r"<[^>]+>", " ", html)

    parsed.body_text = body
    parsed.urls = list(set(URL_REGEX.findall(body)))

    return parsed
