import re
import requests
from urllib.parse import urlparse
from config import Config
from database import get_reported_domains
from scanner.header_rules import is_official_brand_domain

DANGEROUS_EXTENSIONS_CRITICAL = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".ps1", ".jar", ".iso", ".msi", ".pif", ".wsf", ".apk"
}

DANGEROUS_EXTENSIONS_HIGH = {
    ".zip", ".rar", ".7z", ".tar.gz", ".xlsm", ".docm", ".dotm", ".pptm"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".work", ".click", ".club", ".cfd", ".rest", ".live", ".support", ".gq", ".ml", ".cf", ".tk", ".online", ".site"
}

SUSPICIOUS_URL_PATHS = [
    "verify", "login", "signin", "account-update", "confirm", "wallet", "banking", "secure-portal", "auth", "credential", "suspend", "steal"
]

def check_google_safe_browsing(urls: list, api_key: str) -> dict:
    """Check extracted URLs with Google Safe Browsing API v4."""
    if not api_key or not urls:
        return {}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "email-security-scanner",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:50]]
        }
    }

    try:
        res = requests.post(endpoint, json=payload, timeout=5)
        if res.status_code == 200:
            data = res.json()
            matches = data.get("matches", [])
            flagged = {}
            for m in matches:
                flagged[m.get("threat", {}).get("url")] = m.get("threatType")
            return flagged
    except Exception:
        pass
    return {}

def extract_domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower().split(":")[0]
        # Clean potential userinfo or brackets
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        return netloc.strip("[]")
    except Exception:
        return ""

def get_registered_domain(domain: str) -> str:
    """Extract eTLD+1 registered root domain (e.g. mailer.netflix.com -> netflix.com)."""
    if not domain:
        return ""
    clean = domain.lower().split(":")[0].strip("[]").strip()
    parts = clean.split(".")
    if len(parts) >= 2:
        if len(parts) >= 3 and parts[-2] in ["co", "com", "gov", "org", "edu", "net"] and len(parts[-1]) <= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return clean

def analyze_links_and_attachments(parsed_email) -> dict:
    """
    Step 3: Link (URL) & Attachment Analysis
    Returns:
      - score: 0 to 100 risk score
      - indicators: list of threat items
      - malicious_links_found: bool
      - dangerous_attachments_found: bool
      - inspected_links: list of details
      - inspected_attachments: list of details
    """
    indicators = []
    penalties = 0
    malicious_links_found = False
    dangerous_attachments_found = False
    inspected_links = []
    inspected_attachments = []

    # Get local blacklisted domains
    reported_db = get_reported_domains()
    blacklisted_set = {b["domain"].lower(): b["reason"] for b in reported_db}

    # Gather URLs
    all_urls = [item["url"] for item in parsed_email.urls if item.get("url")]

    # 1. Google Safe Browsing check if API key exists
    gsb_results = {}
    if Config.SAFE_BROWSING_API_KEY:
        gsb_results = check_google_safe_browsing(all_urls, Config.SAFE_BROWSING_API_KEY)

    # 2. Inspect each link
    for link_item in parsed_email.urls:
        url = link_item.get("url", "").strip()
        anchor_text = link_item.get("anchor_text", "").strip()
        if not url:
            continue

        domain = extract_domain_from_url(url)
        link_risk = 0
        link_reasons = []
        is_hidden_mismatch = False

        # A. Hidden Link Mismatch
        # Email mein likha hai https://www.hbl.com/login lekin uske peeche asali link http://login-verify-account.xyz/steal chhupa hua hai.
        anchor_lower = anchor_text.lower().strip()
        is_email_address = "@" in anchor_lower or (anchor_lower.startswith("[") and "@" in anchor_lower)

        # Only evaluate anchor text as a displayed URL trap if it is NOT an email address
        # and explicitly purports to be a website/URL
        looks_like_url = False
        if not is_email_address:
            if "http://" in anchor_lower or "https://" in anchor_lower or anchor_lower.startswith("www."):
                looks_like_url = True
            elif "." in anchor_lower and " " not in anchor_lower and any(anchor_lower.endswith(t) or anchor_lower.split("/")[0].endswith(t) for t in [".com", ".org", ".net", ".pk", ".edu", ".gov", ".co"]):
                looks_like_url = True

        if looks_like_url:
            anchor_domain = extract_domain_from_url(anchor_text if "://" in anchor_text else f"https://{anchor_text}")
            anchor_root = get_registered_domain(anchor_domain)
            dest_root = get_registered_domain(domain)
            
            is_dest_official, dest_brand = is_official_brand_domain(domain)
            is_anchor_official, anchor_brand = is_official_brand_domain(anchor_domain)

            # Check if there is a true deceptive domain mismatch
            if anchor_root and dest_root and anchor_root != dest_root:
                # If destination is an officially verified brand domain (e.g. netflix.com, google.com), it is NOT a malicious trap
                if is_dest_official and (is_anchor_official and anchor_brand == dest_brand):
                    is_hidden_mismatch = False
                elif is_dest_official and not is_anchor_official:
                    # Legitimate link to a verified brand portal
                    is_hidden_mismatch = False
                else:
                    is_hidden_mismatch = True
                    link_risk += 80
                    malicious_links_found = True
                    indicators.append({
                        "type": "Hidden Link Mismatch (Phishing Trap)",
                        "description": f"Deceptive Link Trap: The displayed text says '{anchor_text}' but the hidden destination actually redirects to '{url}'!",
                        "severity": "Critical"
                    })
                    link_reasons.append(f"Deceptive href mismatch: text shows {anchor_domain} but loads {domain}")

        # B. Google Safe Browsing match
        if url in gsb_results:
            threat_type = gsb_results[url]
            link_risk += 95
            malicious_links_found = True
            indicators.append({
                "type": "Google Safe Browsing Match",
                "description": f"URL '{url}' is confirmed as {threat_type} in Google Safe Browsing database!",
                "severity": "Critical"
            })
            link_reasons.append(f"Flagged by Google Safe Browsing: {threat_type}")

        # C. Local Threat Intelligence Blacklist match
        for b_dom, reason in blacklisted_set.items():
            if domain == b_dom or domain.endswith("." + b_dom):
                link_risk += 90
                malicious_links_found = True
                indicators.append({
                    "type": "Blacklisted URL Destination",
                    "description": f"Link destination domain '{domain}' is listed in Threat Database: {reason}",
                    "severity": "Critical"
                })
                link_reasons.append(f"Blacklisted domain: {reason}")
                break

        # D. IP Address instead of domain name
        # e.g. http://192.168.1.1/login or http://45.33.32.156/
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain):
            link_risk += 70
            indicators.append({
                "type": "Direct IP Address Link",
                "description": f"Suspicious Link: Uses a raw IP address ({domain}) instead of an authenticated domain name.",
                "severity": "High"
            })
            link_reasons.append("Raw numeric IP host instead of domain name")

        # E. Suspicious TLD check
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                link_risk += 35
                indicators.append({
                    "type": "High-Risk Top-Level Domain (TLD)",
                    "description": f"URL uses high-abuse TLD '{tld}' commonly associated with spam and phishing campaigns ({domain}).",
                    "severity": "Medium"
                })
                link_reasons.append(f"High-abuse TLD {tld}")
                break

        # F. Suspicious Phishing Keywords in URL Path (Only on unverified / third-party domains)
        is_official_dest, _ = is_official_brand_domain(domain)
        if not is_official_dest:
            path_lower = url.lower()
            matched_kw = [kw for kw in SUSPICIOUS_URL_PATHS if kw in path_lower]
            if len(matched_kw) >= 2:
                link_risk += 30
                indicators.append({
                    "type": "Suspicious URL Path Pattern",
                    "description": f"Link path contains credential harvesting indicators: {', '.join(matched_kw)}",
                    "severity": "Medium"
                })
                link_reasons.append(f"Suspicious path keywords: {matched_kw}")
        else:
            link_reasons.append("Official brand destination domain")

        penalties += link_risk
        inspected_links.append({
            "url": url,
            "domain": domain,
            "anchor_text": anchor_text,
            "is_hidden_mismatch": is_hidden_mismatch,
            "risk_score": min(100, link_risk),
            "reasons": link_reasons
        })

    # 3. Dangerous Attachments Check
    # Agar email ke sath .exe, .scr, .bat, ya .zip file lagi ho to foran warning dena.
    for att in parsed_email.attachments:
        filename = att.get("filename", "")
        size = att.get("size", 0)
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
        att_risk = 0
        reasons = []

        if ext in DANGEROUS_EXTENSIONS_CRITICAL:
            att_risk += 95
            dangerous_attachments_found = True
            indicators.append({
                "type": "Critical Dangerous Attachment",
                "description": f"High Threat File: Attachment '{filename}' has an executable or script extension ({ext}) that can execute malware immediately upon opening!",
                "severity": "Critical"
            })
            reasons.append(f"Executable/script file extension {ext}")
        elif ext in DANGEROUS_EXTENSIONS_HIGH:
            att_risk += 60
            dangerous_attachments_found = True
            indicators.append({
                "type": "High-Risk Archive/Macro Attachment",
                "description": f"Suspicious Attachment: File '{filename}' ({ext}) is an archive or macro document frequently used to drop ransomware and evade filters.",
                "severity": "High"
            })
            reasons.append(f"High-risk compressed container or macro file {ext}")

        penalties += att_risk
        inspected_attachments.append({
            "filename": filename,
            "extension": ext,
            "size": size,
            "risk_score": min(100, att_risk),
            "reasons": reasons
        })

    final_link_score = min(100, penalties)

    return {
        "score": final_link_score,
        "indicators": indicators,
        "malicious_links_found": malicious_links_found,
        "dangerous_attachments_found": dangerous_attachments_found,
        "links": inspected_links,
        "attachments": inspected_attachments
    }
