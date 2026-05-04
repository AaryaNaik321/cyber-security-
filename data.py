"""Threat log text datasets: 50 variants per attack type."""

from __future__ import annotations

import random
from typing import Final

_COUNT: Final[int] = 50

_PHISHING_DOMAINS = (
    "paypa1-secure.net",
    "amaz0n-account.co",
    "microsft-login.ml",
    "app1e-id-verify.tk",
    "netfl1x-billing.ru",
    "linkedln-security.io",
    "coinbase-urgent.xyz",
    "chase-alerts-now.com",
    "wellsfarg0-verify.net",
    "usbank-notify.org",
)


def _phishing_logs() -> list[str]:
    logs: list[str] = []
    for i in range(_COUNT):
        d = _PHISHING_DOMAINS[i % len(_PHISHING_DOMAINS)]
        sid = 1000 + i * 17
        logs.append(
            f"""From: support@{d.split('.')[0]}.com
Subject: URGENT - Your account has been suspended (ref #{sid})
Body: Click here to verify your account: http://{d}/login?token=abc{i:03d}&sid={sid}
Sender IP: 192.168.{(220 + i) % 250}.{(45 + i) % 250}
Reply-To: steal@hacker-domain-{(i % 9) + 1}.ru
Case ID: PHISH-{i:04d}"""
        )
    return logs


def _sql_injection_logs() -> list[str]:
    logs: list[str] = []
    payloads = (
        "admin' OR '1'='1' --",
        "' OR 1=1--",
        "'; DROP TABLE users; --",
        "' UNION SELECT null,username,password FROM users--",
        "1'; EXEC xp_cmdshell('net user')--",
    )
    for i in range(_COUNT):
        p1 = payloads[i % len(payloads)]
        p2 = payloads[(i + 1) % len(payloads)]
        o1, o2, o3 = 203 + (i % 40), 45 + (i % 180), 67 + (i % 150)
        logs.append(
            f"""[DB LOG] 2024-01-{(15 + i % 14):02d} {14 + (i % 8):02d}:{32 + (i % 25):02d}:11
IP: {o1}.{o2}.{o3}.89
Username input: {p1}
Password input: {p2}
Second attempt: ' OR SLEEP({5 + (i % 3)})--
WAF Status: BLOCKED (rule SQLi-{i % 20})"""
        )
    return logs


def _ddos_logs() -> list[str]:
    logs: list[str] = []
    for i in range(_COUNT):
        base = 200 + i * 13
        spike = 5000 + i * 211
        ips = 800 + i * 31
        logs.append(
            f"""[TRAFFIC LOG] 2024-01-{(15 + i % 14):02d} {(8 + i % 12):02d}:00
Normal traffic: {base} requests/sec
Spike detected: {spike:,} requests/sec
Unique source IPs: {ips:,} (botnet pattern)
Server CPU: {min(88 + (i % 12), 99)}%, Memory: {min(82 + (i % 15), 98)}%
Service response time: {20 + (i % 25)}+ seconds
Status: Service degraded (incident DDoS-{i:04d})"""
        )
    return logs


def _malware_logs() -> list[str]:
    logs: list[str] = []
    for i in range(_COUNT):
        host = f"WORKSTATION-{i + 1:02d}"
        port = 4444 + (i % 40)
        c2 = f"185.220.{101 + (i % 50)}.{45 + (i % 180)}"
        logs.append(
            f"""[ENDPOINT LOG] Host: {host}
14:20:05 - Unknown file created: C:/Users/AppData/svchost32_{i}.exe
14:20:06 - Registry modified for auto-startup (Run key MZ-{i:04d})
14:20:08 - Outbound connection to {c2}:{port} (known C2 server)
14:20:10 - Files being encrypted with .locked{i % 5} extension
14:20:12 - Shadow copies deleted (vssadmin)
14:20:14 - Ransom note dropped: README_DECRYPT_{i}.txt"""
        )
    return logs


def _brute_force_logs() -> list[str]:
    logs: list[str] = []
    users = ("admin", "root", "administrator", "test", "guest", "oracle", "postgres")
    for i in range(_COUNT):
        o1, o2, o3 = 78 + (i % 40), 45 + (i % 200), 123 + (i % 120)
        att = 40 + i * 7
        tot = 200 + i * 11
        u = users[i % len(users)]
        logs.append(
            f"""[AUTH LOG] Server: web-app-prod
09:15:01 - Failed login: {u} from IP {o1}.{o2}.{o3} (attempt 1)
09:15:02 - Failed login: {u} from IP {o1}.{o2}.{o3} (attempt {att})
09:15:03 - Failed login: root from IP {o1}.{o2}.{o3} (attempt {att + 42})
09:15:04 - Failed login: administrator from IP {o1}.{o2}.{o3} (attempt {att + 87})
09:16:10 - {tot} failed attempts in {65 + (i % 20)} seconds from single IP
09:16:11 - Accounts targeted: admin, root, administrator, test, guest (burst-{i:04d})"""
        )
    return logs


PHISHING_LOGS = _phishing_logs()
SQL_INJECTION_LOGS = _sql_injection_logs()
DDOS_LOGS = _ddos_logs()
MALWARE_LOGS = _malware_logs()
BRUTE_FORCE_LOGS = _brute_force_logs()

THREAT_LOG_LISTS: dict[str, list[str]] = {
    "Phishing": PHISHING_LOGS,
    "SQL Injection": SQL_INJECTION_LOGS,
    "DDoS Attack": DDOS_LOGS,
    "Malware/Ransomware": MALWARE_LOGS,
    "Brute Force": BRUTE_FORCE_LOGS,
}

_THREAT_KEYS = list(THREAT_LOG_LISTS.keys())


def get_threat_log_sample(threat_choice: str) -> str:
    """Return one log string for the sidebar threat type (random among 50 per type)."""
    if threat_choice == "Auto-Detect":
        key = random.choice(_THREAT_KEYS)
        return random.choice(THREAT_LOG_LISTS[key])
    return random.choice(THREAT_LOG_LISTS.get(threat_choice, PHISHING_LOGS))
