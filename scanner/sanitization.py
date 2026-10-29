import re
from bs4 import BeautifulSoup

def defang_url(url: str) -> str:
    """Convert dangerous URL to defanged format: https:// -> hxxps://, . -> [.]"""
    if not url:
        return ""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Replace dots in host
    parts = defanged.split("/", 3)
    if len(parts) >= 3:
        host = parts[2].replace(".", "[.]")
        rest = "/" + parts[3] if len(parts) > 3 else ""
        defanged = f"{parts[0]}//{host}{rest}"
    else:
        defanged = defanged.replace(".", "[.]")
    return defanged

def defang_email(addr: str) -> str:
    """Defang email address: user@domain.com -> user[@]domain[.]com"""
    if not addr:
        return ""
    return addr.replace("@", "[@]").replace(".", "[.]")

def sanitize_email_html(html_content: str) -> str:
    """
    Sanitizes email HTML for safe visual preview:
    1. Removes all <script>, <iframe>, <object>, <embed>, <applet> tags (XSS defense).
    2. Removes all inline event handlers (onload, onerror, onclick, etc.).
    3. Neutralizes <a> tags into non-clickable defanged text badges.
    4. Strips tracking pixels (1x1 images or hidden beacons).
    """
    if not html_content or not html_content.strip():
        return ""

    soup = BeautifulSoup(html_content, "html.parser")

    # 1. Remove dangerous script and executable tags
    for tag in soup.find_all(["script", "iframe", "object", "embed", "applet", "form", "base", "link"]):
        tag.decompose()

    # 2. Remove tracking pixels (1x1 or hidden images)
    for img in soup.find_all("img"):
        width = str(img.get("width", "")).strip()
        height = str(img.get("height", "")).strip()
        style = str(img.get("style", "")).lower()
        if (width in ["0", "1"] and height in ["0", "1"]) or "display:none" in style or "visibility:hidden" in style:
            img.decompose()
        else:
            # Replace img src with safe placeholder or disable auto-fetching to prevent tracking beacons
            img_src = img.get("src", "")
            if img_src.startswith("http://") or img_src.startswith("https://"):
                img["data-original-src"] = defang_url(img_src)
                img["src"] = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='80' height='24'><rect width='100%' height='100%' fill='%231f2937'/><text x='50%' y='65%' font-size='10' fill='%239ca3af' text-anchor='middle'>[Image Blocked]</text></svg>"
                img["title"] = f"External image blocked for tracking protection ({defang_url(img_src)})"

    # 3. Remove all inline event handlers (on*)
    for tag in soup.find_all(True):
        attrs_to_remove = [attr for attr in tag.attrs if attr.lower().startswith("on") or attr.lower().startswith("javascript:")]
        for attr in attrs_to_remove:
            del tag[attr]
        
        # Check href attribute for javascript:
        if tag.has_attr("href") and tag["href"].lower().startswith("javascript:"):
            del tag["href"]

    # 4. Convert all hyperlinks to non-clickable defanged elements
    for a in soup.find_all("a"):
        original_href = a.get("href", "")
        defanged_dest = defang_url(original_href)
        text_content = a.get_text()
        
        # Replace <a> with a customized styled <span class="defanged-url">
        new_tag = soup.new_tag("span")
        new_tag["class"] = "defanged-link inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-red-950/40 text-red-400 border border-red-500/30 cursor-not-allowed select-all"
        new_tag["title"] = f"DEFANGED (Non-Clickable): {defanged_dest}"
        new_tag.string = f"[DEFANGED] {text_content} [{defanged_dest}]"
        a.replace_with(new_tag)

    return str(soup)

def create_safe_preview(parsed_email) -> dict:
    """Generate sanitized and defanged preview components for the UI."""
    raw_sender = parsed_email.sender_address
    raw_reply = parsed_email.reply_to_address

    defanged_sender = f"{parsed_email.sender_display_name} <{defang_email(raw_sender)}>" if parsed_email.sender_display_name else defang_email(raw_sender)
    defanged_reply = defang_email(raw_reply) if raw_reply else ""

    safe_body_html = ""
    if parsed_email.body_html:
        safe_body_html = sanitize_email_html(parsed_email.body_html)
    else:
        # Defang plain text
        body_text = parsed_email.body_text
        for u in parsed_email.urls:
            raw_url = u.get("url", "")
            if raw_url:
                body_text = body_text.replace(raw_url, defang_url(raw_url))
        safe_body_html = f"<pre class='whitespace-pre-wrap font-sans text-sm text-gray-300'>{body_text}</pre>"

    return {
        "defanged_sender": defanged_sender,
        "defanged_reply_to": defanged_reply,
        "defanged_subject": parsed_email.subject,
        "sanitized_html": safe_body_html
    }
