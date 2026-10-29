import re
from database import get_reported_domains

# High-value target brand domains to protect against typosquatting
KNOWN_BRANDS = {
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "meta": "meta.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "hbl": "hbl.com",
    "ubl": "ubl.com.pk",
    "office365": "office.com",
    "outlook": "outlook.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "binance": "binance.com",
    "spotify": "spotify.com"
}

# Whitelist of legitimate registered secondary domains and mail relays used officially by major brands
LEGITIMATE_BRAND_DOMAINS = {
    "netflix": {
        "netflix.com", "netflixmail.com", "mailer.netflix.com", "account.netflix.com",
        "help.netflix.com", "msg.netflix.com", "members.netflix.com", "info.netflix.com",
        "updates.netflix.com", "mail.netflix.com"
    },
    "amazon": {
        "amazon.com", "amazonses.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca",
        "amazon.in", "amazon.co.jp", "amazon.com.au", "marketplace.amazon.com"
    },
    "paypal": {
        "paypal.com", "paypal-communication.com", "paypal.co.uk", "paypal.de", "paypal.ca"
    },
    "microsoft": {
        "microsoft.com", "office.com", "office365.com", "microsoftsupport.com",
        "live.com", "outlook.com", "onedrive.com", "sharepoint.com", "azure.com", "teams.microsoft.com"
    },
    "google": {
        "google.com", "googlemail.com", "accounts.google.com", "youtube.com",
        "notifications.google.com", "cloud.google.com", "gmail.com"
    },
    "apple": {
        "apple.com", "email.apple.com", "icloud.com", "id.apple.com", "appleid.apple.com"
    },
    "spotify": {
        "spotify.com", "news.spotify.com", "spotifymail.com"
    },
    "github": {
        "github.com", "githubmail.com"
    },
    "slack": {
        "slack.com", "slack-mail.com", "slack-msgs.com"
    },
    "hbl": {
        "hbl.com"
    },
    "ubl": {
        "ubl.com.pk"
    }
}

def is_official_brand_domain(domain: str) -> tuple[bool, str]:
    """Check if domain is an authentic registered domain/subdomain of a known brand."""
    if not domain:
        return False, ""
    clean = domain.lower().split(":")[0].strip()
    for brand, domains in LEGITIMATE_BRAND_DOMAINS.items():
        for d in domains:
            if clean == d or clean.endswith("." + d):
                return True, brand
    return False, ""

FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "yandex.com", "zoho.com", "icloud.com"
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_lookalike(domain_name: str) -> str:
    """Normalize common typosquatting visual swaps (rn->m, 0->o, 1->l, etc)."""
    norm = domain_name.lower()
    norm = norm.replace("rn", "m")
    norm = norm.replace("vv", "w")
    norm = norm.replace("0", "o")
    norm = norm.replace("1", "l")
    norm = norm.replace("!", "i")
    norm = norm.replace("3", "e")
    norm = norm.replace("@", "a")
    norm = norm.replace("5", "s")
    return norm

def check_lookalike_domain(domain: str) -> dict:
    """Check if domain is a typosquatting / lookalike clone of a known brand."""
    if not domain:
        return None

    clean_dom = domain.lower().split(":")[0].strip()
    
    # Official brand domains are never typosquatting clones
    is_official, _ = is_official_brand_domain(clean_dom)
    if is_official:
        return None

    root_dom = clean_dom.split(".")[0]
    normalized = normalize_lookalike(root_dom)

    # 1. Exact visual replacement match (e.g. arnazon -> amazon, paypai -> paypal)
    for brand, target_dom in KNOWN_BRANDS.items():
        if clean_dom == target_dom:
            continue
        
        target_root = target_dom.split(".")[0]
        
        # Check normalized match
        if normalized == target_root:
            return {
                "detected": True,
                "target_brand": brand.title(),
                "target_domain": target_dom,
                "spoofed_domain": clean_dom,
                "reason": f"Typosquatting/Homoglyph clone targeting {brand.title()} (e.g. visual character swap 'rn' -> 'm' or 'I' -> 'l')"
            }

        # Check Levenshtein distance on root domain
        dist = levenshtein_distance(root_dom, target_root)
        if 1 <= dist <= 2 and len(root_dom) >= 4:
            return {
                "detected": True,
                "target_brand": brand.title(),
                "target_domain": target_dom,
                "spoofed_domain": clean_dom,
                "reason": f"Lookalike domain closely resembling legitimate brand {brand.title()} ({target_dom}) with distance {dist}"
            }

        # Check brand name embedded in suspicious domain (e.g. amazon-security-update.com)
        if brand in root_dom and not clean_dom.endswith("." + target_dom) and clean_dom != target_dom:
            return {
                "detected": True,
                "target_brand": brand.title(),
                "target_domain": target_dom,
                "spoofed_domain": clean_dom,
                "reason": f"Suspicious lookalike domain embedding official trademark '{brand}' in unauthorized host '{clean_dom}'"
            }

    return None

def analyze_headers(parsed_email) -> dict:
    """
    Step 2: Header & Sender Spoofing Check (Rule-Based Engine)
    Returns:
      - score: 0 to 100 technical risk
      - indicators: list of detected threat items
      - spoof_detected: bool
    """
    indicators = []
    technical_penalties = 0
    is_spoofed = False

    display_name = parsed_email.sender_display_name
    sender_addr = parsed_email.sender_address
    sender_domain = parsed_email.sender_domain
    reply_to_addr = parsed_email.reply_to_address
    reply_to_domain = parsed_email.reply_to_domain

    # 1. Check Reported Domains Database (Local Blacklist)
    try:
        blacklisted = get_reported_domains()
        for b in blacklisted:
            b_domain = b["domain"].lower()
            if sender_domain and (sender_domain == b_domain or sender_domain.endswith("." + b_domain)):
                technical_penalties += 90
                is_spoofed = True
                indicators.append({
                    "type": "Blacklisted Domain",
                    "description": f"Sender domain '{sender_domain}' is actively flagged in Threat Intelligence Blacklist: {b['reason']}",
                    "severity": "Critical"
                })
            if reply_to_domain and (reply_to_domain == b_domain or reply_to_domain.endswith("." + b_domain)):
                technical_penalties += 90
                is_spoofed = True
                indicators.append({
                    "type": "Blacklisted Domain",
                    "description": f"Reply-To domain '{reply_to_domain}' is flagged in Threat Intelligence Blacklist: {b['reason']}",
                    "severity": "Critical"
                })
    except Exception as e:
        pass

    # 2. Display Name vs. Actual Email Mismatch Check
    # Aksar upar naam "Microsoft Support" likha hota hai magar asali email billing-update99@gmail.com hoti hai.
    is_official_sender, official_brand_name = is_official_brand_domain(sender_domain)

    if display_name:
        display_lower = display_name.lower()
        for brand, official_dom in KNOWN_BRANDS.items():
            if brand in display_lower:
                # Check if sender is legitimately from that brand's official domains
                is_legit, matched_brand = is_official_brand_domain(sender_domain)
                if is_legit and matched_brand == brand:
                    # Verified Genuine Brand Identity!
                    indicators.append({
                        "type": "Authenticated Brand Identity",
                        "description": f"Verified official sender domain for {brand.title()} ({sender_domain}). Matches display identity '{display_name}'.",
                        "severity": "Safe"
                    })
                    break
                
                # Otherwise, sender claims to be brand but is NOT from official domain
                if sender_domain != official_dom and not sender_domain.endswith("." + official_dom):
                    is_spoofed = True
                    technical_penalties += 75
                    if sender_domain in FREE_MAIL_PROVIDERS:
                        indicators.append({
                            "type": "Sender Impersonation (Bahroop)",
                            "description": f"Display Name claims to be '{display_name}', but sender is using a free public webmail address ({sender_addr}) instead of {official_dom}!",
                            "severity": "Critical"
                        })
                    else:
                        indicators.append({
                            "type": "Sender Impersonation (Bahroop)",
                            "description": f"Display Name claims to be '{display_name}', but the real sending address is {sender_addr} (expected official domain {official_dom})!",
                            "severity": "High"
                        })
                break

        # Check for authority keywords in display name with unverified domain
        authority_keywords = ["it support", "security team", "billing department", "account verification", "help desk", "ceo office", "admin team"]
        for kw in authority_keywords:
            if kw in display_lower and sender_domain in FREE_MAIL_PROVIDERS:
                technical_penalties += 60
                indicators.append({
                    "type": "Display Name Authority Spoofing",
                    "description": f"Sender display name implies official authority ('{display_name}') while originating from public free webmail '{sender_domain}'.",
                    "severity": "High"
                })
                break

    # 3. Reply-To Mismatch Check
    # Email aayi info@company.com se, lekin jab reply karein to jawab attacker@darkmail.ru ko jata hai.
    if reply_to_addr and reply_to_domain:
        if reply_to_domain != sender_domain:
            technical_penalties += 70
            is_spoofed = True
            indicators.append({
                "type": "Reply-To Mismatch",
                "description": f"Reply redirection detected: Email sent from '{sender_addr}', but responses are silently rerouted to '{reply_to_addr}'!",
                "severity": "Critical"
            })

    # 4. Lookalike Domains (Typosquatting Check)
    # Maslan arnazon.com (m ki jagah rn) ya paypaI.com (chote l ki jagah bada I) ko pakarna.
    lookalike_info = check_lookalike_domain(sender_domain)
    if lookalike_info:
        technical_penalties += 80
        is_spoofed = True
        indicators.append({
            "type": "Lookalike Domain (Typosquatting)",
            "description": f"Typosquatting fraud: Sender domain '{sender_domain}' mimics legitimate brand {lookalike_info['target_brand']} ({lookalike_info['target_domain']}). {lookalike_info['reason']}",
            "severity": "Critical"
        })

    if reply_to_domain and reply_to_domain != sender_domain:
        rt_lookalike = check_lookalike_domain(reply_to_domain)
        if rt_lookalike:
            technical_penalties += 80
            indicators.append({
                "type": "Lookalike Reply-To Domain",
                "description": f"Reply-To domain '{reply_to_domain}' is a typosquatting imitation of {rt_lookalike['target_brand']}.",
                "severity": "Critical"
            })

    # 5. SPF / DKIM / DMARC Header Authentication Check
    raw_headers = parsed_email.headers
    auth_results = raw_headers.get("Authentication-Results", "") or raw_headers.get("authentication-results", "")
    received_spf = raw_headers.get("Received-SPF", "") or raw_headers.get("received-spf", "")
    dkim_sig = raw_headers.get("DKIM-Signature", "") or raw_headers.get("dkim-signature", "")

    spf_status = "Not Found"
    dkim_status = "Not Found"
    dmarc_status = "Not Found"

    if auth_results or received_spf or dkim_sig:
        combined_auth = f"{auth_results} {received_spf}".lower()

        # Check SPF
        if "spf=pass" in combined_auth or "pass (google.com:" in combined_auth:
            spf_status = "PASS"
        elif "spf=fail" in combined_auth or "spf=softfail" in combined_auth or "fail (google.com:" in combined_auth:
            spf_status = "FAIL"
            technical_penalties += 45
            indicators.append({
                "type": "SPF Authentication Failure",
                "description": "SPF check failed: Sender IP server is NOT authorized to send emails on behalf of this domain.",
                "severity": "High"
            })
        elif "spf=neutral" in combined_auth or "spf=none" in combined_auth:
            spf_status = "NONE"

        # Check DKIM
        if "dkim=pass" in combined_auth:
            dkim_status = "PASS"
        elif "dkim=fail" in combined_auth:
            dkim_status = "FAIL"
            technical_penalties += 45
            indicators.append({
                "type": "DKIM Cryptographic Failure",
                "description": "DKIM signature check failed: Digital cryptographic signature is invalid or email was altered in transit.",
                "severity": "High"
            })
        elif dkim_sig:
            dkim_status = "PRESENT"

        # Check DMARC
        if "dmarc=pass" in combined_auth:
            dmarc_status = "PASS"
        elif "dmarc=fail" in combined_auth:
            dmarc_status = "FAIL"
            technical_penalties += 50
            indicators.append({
                "type": "DMARC Policy Failure",
                "description": "DMARC alignment check failed: Domain policy rejects this email due to spoofing or unauthenticated sender.",
                "severity": "Critical"
            })

    # Calculate final technical score (0 - 100)
    final_tech_score = min(100, technical_penalties)
    if is_official_sender and not is_spoofed:
        final_tech_score = 0
    elif not indicators and (spf_status == "PASS" or dkim_status == "PASS"):
        final_tech_score = max(0, final_tech_score - 10)

    return {
        "score": final_tech_score,
        "indicators": indicators,
        "is_spoofed": is_spoofed,
        "is_official_brand": is_official_sender,
        "official_brand_name": official_brand_name,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status
    }
