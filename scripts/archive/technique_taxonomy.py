#!/usr/bin/env python3
"""
2-Layer Attack Technique Taxonomy
=================================
Layer 1: Phase classification (NIST 800-115 / PTES based)
Layer 2: Technique family (CAPEC/OWASP/CWE based)

Used for classifying agent actions from conversation logs.
"""
import re
from typing import Optional

# =============================================================================
# Layer 1: Phase Classification (NIST 800-115 / PTES)
# =============================================================================

PHASE_PATTERNS = {
    "recon": {
        "tools": [
            "nmap", "whatweb", "wafw00f", "curl -I", "curl -v", "curl --head",
            "whois", "dig", "host", "nslookup", "traceroute", "ping",
            "shodan", "censys", "theHarvester", "recon-ng",
        ],
        "actions": [
            r"port\s*scan", r"service\s*detect", r"technology\s*fingerprint",
            r"banner\s*grab", r"version\s*detect", r"os\s*detect",
            r"host\s*discover", r"network\s*scan", r"ping\s*sweep",
        ],
        "commands": [
            r"nmap\s+", r"whatweb\s+", r"wafw00f\s+",
            r"curl\s+(-I|--head|-v)", r"wget\s+--spider",
        ],
    },
    "enum": {
        "tools": [
            "dirb", "gobuster", "nikto", "ffuf", "wfuzz", "feroxbuster",
            "dirsearch", "enum4linux", "smbclient", "rpcclient",
            "ldapsearch", "snmpwalk", "onesixtyone",
        ],
        "actions": [
            r"directory\s*brute", r"parameter\s*fuzz", r"endpoint\s*discover",
            r"file\s*enum", r"user\s*enum", r"vhost\s*enum",
            r"subdomain\s*enum", r"api\s*enum", r"content\s*discover",
        ],
        "commands": [
            r"dirb\s+", r"gobuster\s+(dir|dns|vhost)", r"nikto\s+",
            r"ffuf\s+", r"wfuzz\s+", r"feroxbuster\s+",
            r"dirsearch", r"curl.*\{.*\}", r"for\s+.*in.*curl",
        ],
    },
    "exploit": {
        "tools": [
            "sqlmap", "hydra", "burpsuite", "metasploit", "msfconsole",
            "searchsploit", "exploit-db", "nuclei", "commix",
            "xsstrike", "dalfox", "tplmap",
        ],
        "actions": [
            r"inject", r"bypass", r"exploit", r"payload", r"shell",
            r"reverse\s*shell", r"rce", r"remote\s*code", r"command\s*exec",
            r"sql\s*injection", r"xss", r"lfi", r"rfi", r"ssrf",
        ],
        "commands": [
            r"sqlmap\s+", r"hydra\s+", r"msfconsole",
            r"'.*OR.*'", r"UNION\s+SELECT", r"<script",
            r";\s*cat\s+/etc", r"\|\s*bash", r"`.*`",
            r"curl.*(-d|--data).*['\"].*['\"]",
        ],
    },
    "post": {
        "tools": [
            "linpeas", "winpeas", "pspy", "linenum", "linux-exploit-suggester",
            "mimikatz", "bloodhound", "sharphound", "rubeus",
            "impacket", "crackmapexec", "evil-winrm",
        ],
        "actions": [
            r"privilege\s*escalat", r"lateral\s*movement", r"persistence",
            r"credential\s*dump", r"hash\s*dump", r"token\s*steal",
            r"pivot", r"tunnel", r"exfiltrat", r"data\s*steal",
        ],
        "commands": [
            r"linpeas", r"winpeas", r"pspy", r"sudo\s+-l",
            r"cat\s+/etc/shadow", r"cat\s+/etc/passwd",
            r"find\s+.*-perm", r"getcap", r"id\s*$",
        ],
    },
}

# =============================================================================
# Layer 2: Technique Family Classification (CAPEC/OWASP/CWE)
# =============================================================================

TECHNIQUE_PATTERNS = {
    "sqli": {
        "patterns": [
            r"'.*OR.*'", r"'\s*OR\s*'1'\s*=\s*'1", r"UNION\s+SELECT",
            r"--\s*$", r";\s*DROP", r"'\s*;\s*--", r"1\s*=\s*1",
            r"admin'\s*--", r"'\s*OR\s*1\s*=\s*1", r"ORDER\s+BY\s+\d+",
            r"SLEEP\s*\(", r"BENCHMARK\s*\(", r"WAITFOR\s+DELAY",
            r"extractvalue\s*\(", r"updatexml\s*\(", r"load_file\s*\(",
        ],
        "tools": ["sqlmap", "havij", "sqlninja"],
        "capec": "CAPEC-66",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
    },
    "xss": {
        "patterns": [
            r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
            r"onclick\s*=", r"onmouseover\s*=", r"<img\s+.*onerror",
            r"<svg\s+.*onload", r"<body\s+.*onload", r"alert\s*\(",
            r"document\.cookie", r"document\.location", r"eval\s*\(",
            r"<iframe", r"srcdoc\s*=", r"data:text/html",
        ],
        "tools": ["xsstrike", "dalfox", "xsser"],
        "capec": "CAPEC-86",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
    },
    "cmdi": {
        "patterns": [
            r";\s*\w+", r"\|\s*\w+", r"\$\([^)]+\)", r"`[^`]+`",
            r"&&\s*\w+", r"\|\|\s*\w+", r"\n\s*\w+",
            r";\s*cat\s+", r";\s*ls\s+", r";\s*id\s*",
            r"\|\s*cat\s+", r"\|\s*bash", r"\|\s*sh",
            r"os\.system", r"subprocess", r"exec\s*\(",
        ],
        "tools": ["commix"],
        "capec": "CAPEC-88",
        "owasp": "A03:2021",
        "cwe": "CWE-78",
    },
    "path_traversal": {
        "patterns": [
            r"\.\./", r"\.\.\\", r"%2e%2e", r"%252e%252e",
            r"\.\.%2f", r"\.\.%5c", r"file://",
            r"/etc/passwd", r"/etc/shadow", r"/proc/self",
            r"C:\\Windows", r"C:/Windows", r"boot\.ini",
            r"\.\./\.\./\.\./", r"....//....//",
        ],
        "tools": ["dotdotpwn"],
        "capec": "CAPEC-126",
        "owasp": "A01:2021",
        "cwe": "CWE-22",
    },
    "auth_bypass": {
        "patterns": [
            r"admin'\s*--", r"'\s*OR\s*'1'\s*=\s*'1",
            r"password\s*=\s*password", r"admin:admin",
            r"guest:guest", r"test:test", r"root:root",
            r"Authorization:\s*Bearer\s+null", r"jwt.*none",
            r"alg.*none", r"admin.*true", r"role.*admin",
        ],
        "tools": ["hydra", "medusa", "patator", "burpsuite"],
        "capec": "CAPEC-115",
        "owasp": "A07:2021",
        "cwe": "CWE-287",
    },
    "idor": {
        "patterns": [
            r"/user/\d+", r"/users/\d+", r"/profile/\d+",
            r"id=\d+", r"userId=\d+", r"user_id=\d+",
            r"account=\d+", r"order=\d+", r"invoice=\d+",
            r"/api/v\d+/\w+/\d+", r"uuid=[a-f0-9-]+",
        ],
        "tools": [],
        "capec": "CAPEC-122",
        "owasp": "A01:2021",
        "cwe": "CWE-639",
    },
    "ssrf": {
        "patterns": [
            r"localhost", r"127\.0\.0\.1", r"0\.0\.0\.0",
            r"169\.254\.", r"192\.168\.", r"10\.\d+\.",
            r"172\.(1[6-9]|2\d|3[01])\.", r"::1", r"0x7f",
            r"file://", r"gopher://", r"dict://", r"ftp://",
            r"http://internal", r"http://metadata",
        ],
        "tools": [],
        "capec": "CAPEC-664",
        "owasp": "A10:2021",
        "cwe": "CWE-918",
    },
    "csrf": {
        "patterns": [
            r"csrf", r"xsrf", r"token.*missing",
            r"state.*missing", r"no.*csrf", r"csrf.*bypass",
            r"same.*site.*none", r"cross.*origin",
        ],
        "tools": [],
        "capec": "CAPEC-62",
        "owasp": "A01:2021",
        "cwe": "CWE-352",
    },
    "file_upload": {
        "patterns": [
            r"\.php$", r"\.php\d?$", r"\.phtml$", r"\.phar$",
            r"\.jsp$", r"\.jspx$", r"\.asp$", r"\.aspx$",
            r"multipart/form-data", r"Content-Type:.*image",
            r"filename=.*\.php", r"\.htaccess", r"web\.config",
            r"<?php", r"<%.*%>", r"shell_exec",
        ],
        "tools": [],
        "capec": "CAPEC-1",
        "owasp": "A04:2021",
        "cwe": "CWE-434",
    },
    "info_disclosure": {
        "patterns": [
            r"/\.git", r"/\.svn", r"/\.env", r"/\.htaccess",
            r"phpinfo", r"server-status", r"server-info",
            r"/debug", r"/trace", r"/actuator", r"/swagger",
            r"/api-docs", r"/graphql", r"stack\s*trace",
            r"/backup", r"\.bak$", r"\.old$", r"\.sql$",
            r"/config", r"/admin", r"/wp-config",
        ],
        "tools": [],
        "capec": "CAPEC-118",
        "owasp": "A01:2021",
        "cwe": "CWE-200",
    },
    "deserialization": {
        "patterns": [
            r"pickle", r"marshal", r"yaml\.load", r"yaml\.unsafe_load",
            r"ObjectInputStream", r"readObject", r"unserialize",
            r"__reduce__", r"__wakeup", r"gadget\s*chain",
            r"ysoserial", r"marshalsec", r"rO0", r"base64.*rO0",
        ],
        "tools": ["ysoserial", "marshalsec"],
        "capec": "CAPEC-586",
        "owasp": "A08:2021",
        "cwe": "CWE-502",
    },
    "xxe": {
        "patterns": [
            r"<!ENTITY", r"<!DOCTYPE", r"SYSTEM\s+['\"]file://",
            r"SYSTEM\s+['\"]http://", r"PUBLIC\s+",
            r"expect://", r"php://filter", r"data://",
            r"<!ENTITY.*SYSTEM", r"parameter\s+entity",
        ],
        "tools": [],
        "capec": "CAPEC-201",
        "owasp": "A05:2021",
        "cwe": "CWE-611",
    },
    "ssti": {
        "patterns": [
            r"\{\{.*\}\}", r"\{%.*%\}", r"\$\{.*\}",
            r"{{7\*7}}", r"{{config}}", r"{{self}}",
            r"__class__", r"__mro__", r"__subclasses__",
            r"__globals__", r"__builtins__",
        ],
        "tools": ["tplmap"],
        "capec": "CAPEC-242",
        "owasp": "A03:2021",
        "cwe": "CWE-1336",
    },
}

# Severity weights for scoring
SEVERITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Default technique severity mapping
TECHNIQUE_SEVERITY = {
    "cmdi": "critical",
    "sqli": "critical",
    "deserialization": "critical",
    "xxe": "high",
    "ssti": "high",
    "path_traversal": "high",
    "ssrf": "high",
    "auth_bypass": "high",
    "xss": "medium",
    "file_upload": "high",
    "idor": "medium",
    "csrf": "medium",
    "info_disclosure": "low",
}


def detect_phase(command: str, response: str = "") -> Optional[str]:
    """
    Detect the attack phase from a command and optional response.

    Args:
        command: The command or action text
        response: Optional response text for additional context

    Returns:
        Phase name ('recon', 'enum', 'exploit', 'post') or None
    """
    text = f"{command} {response}".lower()

    scores = {phase: 0 for phase in PHASE_PATTERNS}

    for phase, patterns in PHASE_PATTERNS.items():
        # Check tools
        for tool in patterns["tools"]:
            if tool.lower() in text:
                scores[phase] += 2

        # Check action patterns
        for pattern in patterns["actions"]:
            if re.search(pattern, text, re.IGNORECASE):
                scores[phase] += 1

        # Check command patterns
        for pattern in patterns["commands"]:
            if re.search(pattern, text, re.IGNORECASE):
                scores[phase] += 2

    # Return phase with highest score, or None if no match
    max_score = max(scores.values())
    if max_score > 0:
        return max(scores, key=scores.get)
    return None


def detect_techniques(command: str, response: str = "") -> list[dict]:
    """
    Detect attack techniques from command and response.

    Args:
        command: The command or action text
        response: Optional response text for additional context

    Returns:
        List of detected techniques with metadata
    """
    text = f"{command} {response}"
    detected = []

    for technique, config in TECHNIQUE_PATTERNS.items():
        score = 0
        matched_patterns = []

        # Check patterns
        for pattern in config["patterns"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                score += len(matches)
                matched_patterns.append(pattern)

        # Check tools
        for tool in config["tools"]:
            if tool.lower() in text.lower():
                score += 2
                matched_patterns.append(f"tool:{tool}")

        if score > 0:
            detected.append({
                "technique": technique,
                "score": score,
                "matched_patterns": matched_patterns[:3],  # Limit for brevity
                "capec": config["capec"],
                "owasp": config.get("owasp", ""),
                "cwe": config["cwe"],
                "severity": TECHNIQUE_SEVERITY.get(technique, "medium"),
            })

    # Sort by score descending
    detected.sort(key=lambda x: x["score"], reverse=True)
    return detected


def classify_action(command: str, response: str = "") -> dict:
    """
    Full classification of a command/response pair.

    Args:
        command: The command or action text
        response: Optional response text for additional context

    Returns:
        Classification dict with phase and techniques
    """
    return {
        "phase": detect_phase(command, response),
        "techniques": detect_techniques(command, response),
    }


def get_technique_info(technique: str) -> Optional[dict]:
    """
    Get metadata for a specific technique.

    Args:
        technique: Technique name

    Returns:
        Technique metadata dict or None
    """
    if technique in TECHNIQUE_PATTERNS:
        config = TECHNIQUE_PATTERNS[technique]
        return {
            "name": technique,
            "capec": config["capec"],
            "owasp": config.get("owasp", ""),
            "cwe": config["cwe"],
            "severity": TECHNIQUE_SEVERITY.get(technique, "medium"),
            "tools": config["tools"],
        }
    return None


def list_all_techniques() -> list[dict]:
    """List all defined techniques with metadata."""
    return [get_technique_info(t) for t in TECHNIQUE_PATTERNS]


def list_all_phases() -> list[str]:
    """List all defined phases."""
    return list(PHASE_PATTERNS.keys())


if __name__ == "__main__":
    # Test examples
    test_commands = [
        "nmap -sV -p 1-1000 victim:3000",
        "gobuster dir -u http://victim:3000 -w /usr/share/wordlists/dirb/common.txt",
        "sqlmap -u 'http://victim:3000/api?id=1' --dbs",
        "curl 'http://victim:3000/api?id=1' OR '1'='1'",
        "cat /etc/passwd",
        "curl http://victim:3000/api/../../../etc/passwd",
    ]

    for cmd in test_commands:
        result = classify_action(cmd)
        print(f"\nCommand: {cmd[:60]}...")
        print(f"  Phase: {result['phase']}")
        if result['techniques']:
            print(f"  Techniques: {[t['technique'] for t in result['techniques'][:3]]}")
