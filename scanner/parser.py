import re
import email
from email import policy
from email.utils import parseaddr
from bs4 import BeautifulSoup

class ParsedEmail:
    def __init__(self):
        self.sender_display_name = ""
        self.sender_address = ""
        self.sender_domain = ""
        self.reply_to_address = ""
        self.reply_to_domain = ""
        self.return_path = ""
        self.recipient = ""
        self.subject = ""
        self.date = ""
        self.body_text = ""
        self.body_html = ""
        self.headers = {}
        self.urls = []         # list of dicts: {'url': ..., 'anchor_text': ..., 'is_hidden_mismatch': ...}
        self.attachments = []  # list of dicts: {'filename': ..., 'size': ..., 'content_type': ..., 'is_dangerous': ...}
        self.raw_eml = ""
        self.input_type = "direct"

def extract_urls_from_text(text: str) -> list:
    """Extract standalone URLs from plain text."""
    url_pattern = r'https?://[^\s<>"\'{}|\\^`]+'
    return list(set(re.findall(url_pattern, text)))

def parse_direct_input(sender: str, subject: str, body: str, reply_to: str = "", attachments_names: list = None) -> ParsedEmail:
    """Parse direct copy-pasted email input."""
    parsed = ParsedEmail()
    parsed.input_type = "direct"
    parsed.subject = subject.strip()
    parsed.body_text = body.strip()

    # Parse sender: "Display Name <email@domain.com>" or just "email@domain.com"
    name, addr = parseaddr(sender)
    parsed.sender_display_name = name.strip()
    parsed.sender_address = addr.lower().strip() if addr else sender.lower().strip()
    if "@" in parsed.sender_address:
        parsed.sender_domain = parsed.sender_address.split("@")[-1]

    if reply_to:
        _, r_addr = parseaddr(reply_to)
        parsed.reply_to_address = r_addr.lower().strip() if r_addr else reply_to.lower().strip()
        if "@" in parsed.reply_to_address:
            parsed.reply_to_domain = parsed.reply_to_address.split("@")[-1]

    # Check for HTML content in body
    has_html_tags = bool(re.search(r'<(p|div|html|body|table|tr|td|span|b|strong|i|em|h[1-6]|a\s|br\s*/?>|ul|ol|li|script|iframe)[^>]*>', body, re.IGNORECASE))
    if has_html_tags:
        parsed.body_html = body
        soup = BeautifulSoup(body, "html.parser")
        parsed.body_text = soup.get_text(separator="\n").strip()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            anchor_text = a_tag.get_text().strip()
            parsed.urls.append({
                "url": href,
                "anchor_text": anchor_text
            })
    else:
        # Plain text URLs
        found_urls = extract_urls_from_text(body)
        for u in found_urls:
            parsed.urls.append({
                "url": u,
                "anchor_text": u
            })

    # Attachments
    if attachments_names:
        for fname in attachments_names:
            if fname and fname.strip():
                parsed.attachments.append({
                    "filename": fname.strip(),
                    "size": 0,
                    "content_type": "application/octet-stream"
                })

    return parsed

def parse_eml_bytes(eml_bytes: bytes) -> ParsedEmail:
    """Parse raw .eml file content with complete MIME headers and attachments."""
    msg = email.message_from_bytes(eml_bytes, policy=policy.default)
    parsed = ParsedEmail()
    parsed.input_type = "eml"
    parsed.raw_eml = eml_bytes.decode("utf-8", errors="ignore")

    # Headers
    parsed.headers = {k: str(v) for k, v in msg.items()}
    parsed.subject = str(msg.get("Subject", "")).strip()
    parsed.date = str(msg.get("Date", "")).strip()

    # Sender parsing
    raw_from = str(msg.get("From", ""))
    disp_name, addr = parseaddr(raw_from)
    parsed.sender_display_name = disp_name.strip()
    parsed.sender_address = addr.lower().strip() if addr else raw_from.lower().strip()
    if "@" in parsed.sender_address:
        parsed.sender_domain = parsed.sender_address.split("@")[-1]

    # Reply-To parsing
    raw_reply = str(msg.get("Reply-To", ""))
    if raw_reply:
        _, r_addr = parseaddr(raw_reply)
        parsed.reply_to_address = r_addr.lower().strip() if r_addr else raw_reply.lower().strip()
        if "@" in parsed.reply_to_address:
            parsed.reply_to_domain = parsed.reply_to_address.split("@")[-1]

    # Return-Path
    parsed.return_path = str(msg.get("Return-Path", "")).strip()
    parsed.recipient = str(msg.get("To", "")).strip()

    # Extract Body and Attachments
    text_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            # Attachments
            if "attachment" in content_disposition.lower() or filename:
                payload = part.get_payload(decode=True) or b""
                parsed.attachments.append({
                    "filename": filename or "unnamed_attachment",
                    "size": len(payload),
                    "content_type": content_type
                })
            elif content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    text_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        decoded = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore") if payload else ""
        if content_type == "text/html":
            html_parts.append(decoded)
        else:
            text_parts.append(decoded)

    parsed.body_html = "\n".join(html_parts)
    if parsed.body_html:
        soup = BeautifulSoup(parsed.body_html, "html.parser")
        parsed.body_text = soup.get_text(separator="\n").strip()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            anchor_text = a.get_text().strip()
            parsed.urls.append({
                "url": href,
                "anchor_text": anchor_text
            })
    else:
        parsed.body_text = "\n".join(text_parts).strip()
        found_urls = extract_urls_from_text(parsed.body_text)
        for u in found_urls:
            parsed.urls.append({
                "url": u,
                "anchor_text": u
            })

    return parsed
