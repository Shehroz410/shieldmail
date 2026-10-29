import imaplib
import email
from email import policy
from scanner.parser import parse_eml_bytes

# In-memory storage for active session's fetched live emails
_LIVE_INBOX_STORE = {}

def get_imap_host_by_provider(email_address: str) -> tuple[str, int]:
    """Auto-detect IMAP server based on email domain."""
    email_lower = email_address.lower().strip()
    domain = email_lower.split("@")[-1] if "@" in email_lower else ""

    if "gmail.com" in domain or "googlemail.com" in domain:
        return "imap.gmail.com", 993
    elif "outlook.com" in domain or "hotmail.com" in domain or "live.com" in domain or "office365.com" in domain:
        return "outlook.office365.com", 993
    elif "yahoo.com" in domain or "ymail.com" in domain:
        return "imap.mail.yahoo.com", 993
    elif "zoho.com" in domain:
        return "imappro.zoho.com", 993
    elif "icloud.com" in domain or "me.com" in domain:
        return "imap.mail.me.com", 993
    else:
        # Default to Gmail or domain IMAP
        return f"imap.{domain}" if domain else "imap.gmail.com", 993

def connect_and_fetch_inbox(username: str, password: str, host: str = None, port: int = 993, limit: int = 15) -> dict:
    """
    Connects to real IMAP server (Gmail / Outlook / Yahoo / Corporate),
    fetches recent real emails directly from the user's live mailbox in readonly mode.
    """
    username = username.strip()
    password = password.strip()

    if not host:
        host, port = get_imap_host_by_provider(username)

    try:
        # Connect with SSL
        mail = imaplib.IMAP4_SSL(host, port)
        mail.login(username, password)
        mail.select("INBOX", readonly=True)

        # Search for all messages
        status, messages = mail.search(None, "ALL")
        if status != "OK" or not messages[0]:
            mail.logout()
            return {"success": True, "count": 0, "emails": [], "host": host}

        message_ids = messages[0].split()
        # Take the most recent 'limit' messages
        target_ids = message_ids[-limit:]
        target_ids.reverse()

        fetched_emails = []
        _LIVE_INBOX_STORE.clear()

        for idx, mid in enumerate(target_ids):
            msg_id_str = mid.decode()
            res, data = mail.fetch(mid, "(RFC822)")
            if res != "OK" or not data:
                continue

            raw_bytes = data[0][1]
            parsed = parse_eml_bytes(raw_bytes)
            parsed.input_type = "gmail_sync"

            item_id = f"live_{msg_id_str}_{idx}"
            _LIVE_INBOX_STORE[item_id] = {
                "parsed": parsed,
                "raw_bytes": raw_bytes
            }

            snippet = parsed.body_text[:140].replace("\n", " ").strip() if parsed.body_text else "No preview text available."

            fetched_emails.append({
                "id": item_id,
                "sender": f"{parsed.sender_display_name} <{parsed.sender_address}>" if parsed.sender_display_name else parsed.sender_address,
                "reply_to": parsed.reply_to_address,
                "subject": parsed.subject or "(No Subject)",
                "date": parsed.date or "Recent",
                "snippet": snippet,
                "attachments": [att["filename"] for att in parsed.attachments],
                "links_count": len(parsed.urls)
            })

        mail.logout()
        return {
            "success": True,
            "count": len(fetched_emails),
            "emails": fetched_emails,
            "host": host,
            "username": username
        }

    except imaplib.IMAP4.error as e:
        err_msg = str(e)
        if "AUTHENTICATIONFAILED" in err_msg or "Invalid credentials" in err_msg:
            return {
                "success": False,
                "error": "Authentication failed. For Gmail, please use an 'App Password' (generated at myaccount.google.com/apppasswords), not your main account password."
            }
        return {"success": False, "error": f"IMAP Error: {err_msg}"}
    except Exception as e:
        return {"success": False, "error": f"Connection Error: {str(e)}"}

def get_live_email_parsed(item_id: str):
    """Retrieve in-memory parsed email for live scanning."""
    item = _LIVE_INBOX_STORE.get(item_id)
    if item:
        return item["parsed"]
    return None

def get_live_inbox_items():
    """Return currently loaded live emails."""
    items = []
    for item_id, data in _LIVE_INBOX_STORE.items():
        parsed = data["parsed"]
        items.append({
            "id": item_id,
            "sender": f"{parsed.sender_display_name} <{parsed.sender_address}>" if parsed.sender_display_name else parsed.sender_address,
            "subject": parsed.subject or "(No Subject)",
            "date": parsed.date or "Recent",
            "snippet": parsed.body_text[:140].replace("\n", " ").strip() if parsed.body_text else "",
            "attachments": [att["filename"] for att in parsed.attachments],
            "links_count": len(parsed.urls)
        })
    return items

def clear_live_inbox():
    _LIVE_INBOX_STORE.clear()
