import re
import time
from urllib.parse import unquote

from database import cleanup_rate_requests, get_recent_rate_requests, record_rate_request

RATE_LIMIT = 20
RATE_WINDOW = 60

PATTERNS = {
    "SQL Injection": [r"\bunion\s+(all\s+)?select\b", r"\bor\s+1\s*=\s*1\b", r"\band\s+1\s*=\s*1\b", r"'\s*or\s+'[^']*'\s*=\s*'[^']*", r"\bsleep\s*\(", r"\bbenchmark\s*\(", r"\bdrop\s+table\b"],
    "XSS": [r"<\s*script\b", r"javascript\s*:", r"\bonerror\s*=", r"\bonload\s*=", r"<\s*iframe\b"],
    "Directory Traversal": [r"\.\./", r"\.\.\\", r"%2e%2e(?:%2f|%5c)"],
    "Command Injection": [r"[;&|]\s*(whoami|id|dir|ls|cat|type|ipconfig|ifconfig)\b", r"\b(powershell|cmd\.exe|bash|sh)\b", r"`[^`]+`"],
}
THREAT_SCORES = {"SQL Injection": 50, "XSS": 40, "Directory Traversal": 45, "Command Injection": 80, "Rate Limit": 25}


def detect_attack(payload):
    if not payload:
        return None
    text = unquote(str(payload))
    for attack_type, patterns in PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return attack_type
    return None


def threat_score(attack_type):
    return THREAT_SCORES.get(attack_type, 0)


def is_rate_limited(ip_address):
    now = time.time()
    cleanup_rate_requests(now - RATE_WINDOW)
    record_rate_request(ip_address, now)
    return get_recent_rate_requests(ip_address, now - RATE_WINDOW) > RATE_LIMIT


def inspect_request(payload, ip_address="127.0.0.1", check_rate_limit=True):
    attack_type = detect_attack(payload)
    if attack_type:
        return {"attack_type": attack_type, "action": "BLOCKED", "score": threat_score(attack_type)}
    if check_rate_limit and is_rate_limited(ip_address):
        return {"attack_type": "Rate Limit", "action": "BLOCKED", "score": threat_score("Rate Limit")}
    return {"attack_type": None, "action": "ALLOWED", "score": 0}
