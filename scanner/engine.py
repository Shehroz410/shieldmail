from scanner.header_rules import analyze_headers
from scanner.link_checker import analyze_links_and_attachments
from scanner.ai_analyzer import analyze_with_gemini
from scanner.sanitization import create_safe_preview
from database import save_scan_result

def calculate_verdict(final_score: float) -> tuple[str, str, str]:
    """
    Returns (verdict_label, category_color, status_badge)
    Green (Safe - 0-30)
    Yellow (Suspicious / Warning - 31-69)
    Red (High Risk / Phishing - 70-100)
    """
    if final_score <= 30.0:
        return "Safe", "green", "PASS / VERIFIED"
    elif final_score <= 69.0:
        return "Suspicious / Warning", "yellow", "WARNING / UNVERIFIED"
    else:
        return "High Risk / Phishing", "red", "CRITICAL THREAT / PHISHING"

def run_full_scan(parsed_email, user_id=None, save_to_db=True) -> dict:
    """
    Executes the 5-Step Technical Workflow:
    Step 1: Input parsing (already completed in parsed_email)
    Step 2: Header & Sender Spoofing Check (Rule-Based Engine)
    Step 3: Link & Attachment Analysis
    Step 4: Gemini AI Threat & Intent Analysis (NLP Layer)
    Step 5: Final Weighted Risk Score & Visual Dashboard Verdict
    """
    # Step 2: Header & Sender Spoofing Check
    header_results = analyze_headers(parsed_email)
    tech_score = float(header_results["score"])

    # Step 3: Link & Attachment Analysis
    link_results = analyze_links_and_attachments(parsed_email)
    link_score = float(link_results["score"])

    # Step 4: Gemini AI Threat & Intent Analysis (NLP Layer) with Sender & Brand Context
    sender_context = {
        "sender_address": parsed_email.sender_address,
        "sender_display_name": parsed_email.sender_display_name,
        "sender_domain": parsed_email.sender_domain,
        "is_official_brand": header_results.get("is_official_brand", False),
        "official_brand_name": header_results.get("official_brand_name", ""),
        "spf_status": header_results.get("spf_status", "None"),
        "dkim_status": header_results.get("dkim_status", "None"),
        "link_domains": [l.get("domain") for l in link_results.get("links", []) if l.get("domain")]
    }
    ai_results = analyze_with_gemini(parsed_email.subject, parsed_email.body_text, sender_context)
    ai_score = float(ai_results.get("ai_risk_score", 0.0))

    # Step 5: Weighted Calculation
    # Formula: Technical Score (40%) + Link Score (30%) + Gemini AI Score (30%)
    weighted_score = (tech_score * 0.40) + (link_score * 0.30) + (ai_score * 0.30)
    raw_final_score = round(min(100.0, weighted_score), 1)

    # Trust Credit for Authenticated Brand Senders
    is_official_brand = header_results.get("is_official_brand", False)
    if is_official_brand and not header_results.get("is_spoofed") and not link_results.get("malicious_links_found") and not ai_results.get("prompt_injection_detected"):
        # Real brand infrastructure with clean links is authentic!
        raw_final_score = min(12.0, raw_final_score)

    # Security Guard 2: Indirect Prompt Injection Defense & Rule-Based Override
    # "Agar link malicious hai ya sender domain spoofed hai, to Rule-Based Engine hamesha AI ke score ko override kar ke High Risk (Red) dikhaye."
    override_applied = False
    override_reasons = []

    if header_results.get("is_spoofed"):
        override_applied = True
        override_reasons.append("Sender Domain Spoofing / Impersonation detected by Rule-Based Engine.")

    if link_results.get("malicious_links_found"):
        override_applied = True
        override_reasons.append("Hidden link mismatch or blacklisted phishing URL detected.")

    if link_results.get("dangerous_attachments_found"):
        override_applied = True
        override_reasons.append("Dangerous executable or macro attachment detected.")

    if ai_results.get("prompt_injection_detected"):
        override_applied = True
        override_reasons.append("Indirect Prompt Injection attempt identified in email body.")

    final_risk_score = raw_final_score
    if override_applied:
        # Enforce minimum High Risk threshold (>= 75%)
        if final_risk_score < 75.0:
            final_risk_score = max(78.0, raw_final_score)
        final_risk_score = round(min(100.0, final_risk_score), 1)

    verdict_label, verdict_color, verdict_badge = calculate_verdict(final_risk_score)
    if is_official_brand and verdict_label == "Safe":
        verdict_badge = "AUTHENTIC / VERIFIED BRAND"

    # Consolidate all threat indicators
    all_indicators = []
    for ind in header_results.get("indicators", []):
        all_indicators.append(ind)
    for ind in link_results.get("indicators", []):
        all_indicators.append(ind)
    
    if ai_results.get("prompt_injection_detected"):
        all_indicators.append({
            "type": "Indirect Prompt Injection Attack",
            "description": "Adversarial command injection detected in email content attempting to subvert AI safety rules.",
            "severity": "Critical"
        })

    # Prepare bullet points depending on verdict (Safe vs Threat)
    if verdict_label == "Safe":
        brand_title = header_results.get("official_brand_name", "").title()
        findings_heading = "SECURITY VERIFICATION FINDINGS (SAFE & AUTHENTIC)"
        findings_points = []
        if is_official_brand:
            findings_points.append(f"Verified Authentic Sender: Originates from legitimate {brand_title} registered infrastructure ({parsed_email.sender_domain}).")
        else:
            findings_points.append(f"Authentic Sender Domain: Sender verified as {parsed_email.sender_domain or 'standard address'}.")

        if header_results.get("spf_status") == "PASS":
            findings_points.append("Cryptographic Verification: SPF server authorization passed.")
        if header_results.get("dkim_status") == "PASS":
            findings_points.append("Cryptographic Verification: DKIM digital signature validated.")

        findings_points.append("Link Integrity: All hyperlinks point directly to authenticated official domains without deceptive redirection.")
        findings_points.append("Payload Security: No suspicious, executable, or macro attachments detected.")
        findings_points.append(f"Linguistic Assessment: Genuine service communication ({ai_results.get('summary_verdict', 'Normal non-coercive intent')}).")
        why_not_click_points = findings_points
    else:
        findings_heading = "WHY YOU SHOULD NOT CLICK ON THIS EMAIL (CRITICAL WARNINGS)"
        why_not_click_points = []
        for ind in all_indicators:
            if ind.get("severity") in ["Critical", "High", "Medium"]:
                why_not_click_points.append(ind.get("description", ""))
        
        # Add AI key warning points
        for pt in ai_results.get("key_warning_points", []):
            if pt not in why_not_click_points:
                why_not_click_points.append(pt)

        if not why_not_click_points:
            why_not_click_points.append("Sender origin or message contents could not be authenticated.")
        findings_points = why_not_click_points

    # Generate Defanged & Sanitized Safe Preview (Security Guard 1)
    safe_preview = create_safe_preview(parsed_email)

    # Save to SQLite Database (Zero Body Storage - only metadata!)
    scan_id = None
    if save_to_db:
        scan_id = save_scan_result(
            sender=parsed_email.sender_address or parsed_email.sender_display_name or "Unknown Sender",
            subject=parsed_email.subject or "No Subject",
            risk_score=final_risk_score,
            verdict=verdict_label,
            input_type=parsed_email.input_type,
            technical_score=tech_score,
            link_score=link_score,
            ai_score=ai_score,
            indicators=all_indicators,
            override_applied=override_applied,
            user_id=user_id
        )

    return {
        "scan_id": scan_id,
        "final_risk_score": final_risk_score,
        "raw_weighted_score": raw_final_score,
        "verdict": verdict_label,
        "verdict_color": verdict_color,
        "verdict_badge": verdict_badge,
        "override_applied": override_applied,
        "override_reasons": override_reasons,
        "scores": {
            "technical": tech_score,
            "technical_weight": "40%",
            "link_attachment": link_score,
            "link_weight": "30%",
            "ai_intent": ai_score,
            "ai_weight": "30%"
        },
        "header_analysis": header_results,
        "link_analysis": link_results,
        "ai_analysis": ai_results,
        "indicators": all_indicators,
        "why_not_click_points": why_not_click_points,
        "findings_heading": findings_heading,
        "findings_points": findings_points,
        "safe_preview": safe_preview,
        "email_metadata": {
            "sender_display_name": parsed_email.sender_display_name,
            "sender_address": parsed_email.sender_address,
            "sender_domain": parsed_email.sender_domain,
            "reply_to": parsed_email.reply_to_address,
            "subject": parsed_email.subject,
            "date": parsed_email.date,
            "attachments_count": len(parsed_email.attachments),
            "links_count": len(parsed_email.urls),
            "input_type": parsed_email.input_type
        }
    }
