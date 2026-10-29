import sqlite3
import hashlib
from datetime import datetime
from config import Config

def get_db_connection():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'analyst',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 2. ScanHistory Table (Privacy: ZERO full body stored!)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        sender TEXT NOT NULL,
        sender_domain TEXT,
        subject TEXT NOT NULL,
        final_risk_score REAL NOT NULL,
        verdict TEXT NOT NULL,
        input_type TEXT NOT NULL,
        technical_score REAL DEFAULT 0,
        link_score REAL DEFAULT 0,
        ai_score REAL DEFAULT 0,
        override_applied INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # 3. ThreatIndicators Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        indicator_type TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
    )
    """)

    # 4. ReportedDomains Table (Local Blacklist / Threat Intel)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reported_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        reason TEXT NOT NULL,
        reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        risk_level TEXT DEFAULT 'High'
    )
    """)

    # Seed default user if not exists
    cursor.execute("SELECT id FROM users WHERE username = ?", ("analyst@soc.security",))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("analyst@soc.security", hash_password("admin123"), "analyst")
        )

    # Seed known threat domains / lookalikes
    sample_blacklists = [
        ("arnazon.com", "Typosquatting lookalike targeting Amazon customers ('rn' simulates 'm')", "High"),
        ("paypai.com", "Typosquatting lookalike targeting PayPal (capital 'I' simulates lowercase 'l')", "High"),
        ("login-verify-account.xyz", "Credential harvesting portal identified in credential stuffing campaigns", "Critical"),
        ("darkmail.ru", "Known bulletproof mail exchanger hosting spear-phishing reply-to relays", "Critical"),
        ("security-update-microsoft365.online", "Fake Office 365 OAuth consent and token phishing portal", "High"),
        ("bank-auth-verify.top", "Banking credential phishing site targeting 2FA codes", "High"),
        ("urgent-wire-transfer.cc", "Business Email Compromise (BEC) wire redirection gateway", "High"),
        ("micros0ft.com", "Typosquatting lookalike replacing letter 'o' with digit '0'", "High")
    ]

    for domain, reason, risk in sample_blacklists:
        cursor.execute(
            "INSERT OR IGNORE INTO reported_domains (domain, reason, risk_level) VALUES (?, ?, ?)",
            (domain.lower(), reason, risk)
        )

    conn.commit()
    conn.close()

def save_scan_result(sender, subject, risk_score, verdict, input_type, technical_score, link_score, ai_score, indicators, override_applied=False, user_id=None):
    """
    Saves scan metadata and threat indicators adhering to Zero Body Storage policy.
    Raw email text is NOT saved.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Extract domain from sender
    sender_domain = ""
    if "@" in sender:
        sender_domain = sender.split("@")[-1].strip().strip(">").strip()

    cursor.execute("""
        INSERT INTO scan_history (
            user_id, sender, sender_domain, subject, final_risk_score,
            verdict, input_type, technical_score, link_score, ai_score, override_applied
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, sender, sender_domain, subject, risk_score,
        verdict, input_type, technical_score, link_score, ai_score, 1 if override_applied else 0
    ))
    scan_id = cursor.lastrowid

    for ind in indicators:
        cursor.execute("""
            INSERT INTO threat_indicators (scan_id, indicator_type, description, severity)
            VALUES (?, ?, ?, ?)
        """, (
            scan_id,
            ind.get("type", "General Threat"),
            ind.get("description", ""),
            ind.get("severity", "Medium")
        ))

    conn.commit()
    conn.close()
    return scan_id

def get_scan_history(limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT h.*, COUNT(t.id) as threat_count
        FROM scan_history h
        LEFT JOIN threat_indicators t ON h.id = t.scan_id
        GROUP BY h.id
        ORDER BY h.scan_date DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    history = [dict(row) for row in rows]
    conn.close()
    return history

def clear_scan_history():
    """Purge all scan records and threat indicators to reset counters."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threat_indicators")
    cursor.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()

def get_scan_details(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return None
    
    cursor.execute("SELECT * FROM threat_indicators WHERE scan_id = ?", (scan_id,))
    indicators = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    result = dict(scan)
    result["indicators"] = indicators
    return result

def get_reported_domains():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reported_domains ORDER BY reported_at DESC")
    domains = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return domains

def add_reported_domain(domain, reason, risk_level="High"):
    conn = get_db_connection()
    cursor = conn.cursor()
    domain = domain.lower().strip()
    cursor.execute("""
        INSERT OR REPLACE INTO reported_domains (domain, reason, risk_level, reported_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    """, (domain, reason, risk_level))
    conn.commit()
    conn.close()

def delete_reported_domain(domain_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM reported_domains WHERE id = ?", (domain_id,))
    conn.commit()
    conn.close()
