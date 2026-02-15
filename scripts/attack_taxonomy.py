#!/usr/bin/env python3
"""
Attack Taxonomy for HTTP Log Classification
============================================
Defines attack families, variants, and mappings to CAPEC/CWE/OWASP standards.

Based on:
- OWASP ModSecurity Core Rule Set (CRS) v4.x
- MITRE CAPEC (Common Attack Pattern Enumeration and Classification)
- MITRE CWE (Common Weakness Enumeration)
- OWASP Top 10 2021

Reference: https://github.com/coreruleset/coreruleset
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AttackVariant:
    """Specific attack technique within a family."""
    name: str
    description: str
    crs_rules: list[str] = field(default_factory=list)  # Related CRS rule IDs


@dataclass
class AttackFamily:
    """Top-level attack category."""
    name: str
    description: str
    capec_id: Optional[str]
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    crs_rule_range: tuple[int, int]  # (start, end) of CRS rule IDs
    variants: list[AttackVariant] = field(default_factory=list)
    severity: str = "medium"  # critical, high, medium, low, info


# =============================================================================
# Attack Family Definitions
# =============================================================================

ATTACK_FAMILIES = {
    "sqli": AttackFamily(
        name="sqli",
        description="SQL Injection - Manipulation of SQL queries through user input",
        capec_id="CAPEC-66",
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        crs_rule_range=(942000, 942999),
        severity="critical",
        variants=[
            AttackVariant(
                name="union_based",
                description="UNION-based SQL injection for data extraction",
                crs_rules=["942100", "942190", "942200"]
            ),
            AttackVariant(
                name="error_based",
                description="Error-based SQL injection using database errors",
                crs_rules=["942150", "942410"]
            ),
            AttackVariant(
                name="blind_boolean",
                description="Boolean-based blind SQL injection",
                crs_rules=["942120", "942130"]
            ),
            AttackVariant(
                name="blind_time",
                description="Time-based blind SQL injection using delays",
                crs_rules=["942160", "942170"]
            ),
            AttackVariant(
                name="stacked_queries",
                description="Stacked queries for multiple statement execution",
                crs_rules=["942180", "942390"]
            ),
            AttackVariant(
                name="auth_bypass",
                description="SQL injection for authentication bypass",
                crs_rules=["942100", "942110"]
            ),
        ]
    ),

    "xss": AttackFamily(
        name="xss",
        description="Cross-Site Scripting - Injection of malicious scripts into web pages",
        capec_id="CAPEC-86",
        cwe_id="CWE-79",
        owasp_category="A03:2021-Injection",
        crs_rule_range=(941000, 941999),
        severity="medium",
        variants=[
            AttackVariant(
                name="reflected",
                description="Reflected XSS via URL parameters or form inputs",
                crs_rules=["941100", "941110", "941120"]
            ),
            AttackVariant(
                name="stored",
                description="Stored/Persistent XSS in database content",
                crs_rules=["941100", "941160"]
            ),
            AttackVariant(
                name="dom_based",
                description="DOM-based XSS manipulating client-side scripts",
                crs_rules=["941180", "941190"]
            ),
            AttackVariant(
                name="script_tag",
                description="XSS using <script> tags",
                crs_rules=["941100", "941110"]
            ),
            AttackVariant(
                name="event_handler",
                description="XSS using event handlers (onerror, onload, etc.)",
                crs_rules=["941120", "941130", "941140"]
            ),
            AttackVariant(
                name="encoded",
                description="Encoded/obfuscated XSS payloads",
                crs_rules=["941150", "941320", "941330"]
            ),
        ]
    ),

    "cmdi": AttackFamily(
        name="cmdi",
        description="Command Injection - Execution of arbitrary OS commands",
        capec_id="CAPEC-88",
        cwe_id="CWE-78",
        owasp_category="A03:2021-Injection",
        crs_rule_range=(932000, 932999),
        severity="critical",
        variants=[
            AttackVariant(
                name="shell_metachar",
                description="Command injection via shell metacharacters (;|&`$)",
                crs_rules=["932100", "932105", "932110"]
            ),
            AttackVariant(
                name="command_chain",
                description="Chained commands using && or ||",
                crs_rules=["932115", "932120"]
            ),
            AttackVariant(
                name="subshell",
                description="Command execution via subshell $() or backticks",
                crs_rules=["932130", "932140"]
            ),
            AttackVariant(
                name="unix_commands",
                description="Direct Unix command execution",
                crs_rules=["932150", "932160"]
            ),
            AttackVariant(
                name="windows_commands",
                description="Windows command execution (cmd.exe, powershell)",
                crs_rules=["932170", "932171"]
            ),
        ]
    ),

    "path_traversal": AttackFamily(
        name="path_traversal",
        description="Path Traversal / LFI - Access to files outside intended directory",
        capec_id="CAPEC-126",
        cwe_id="CWE-22",
        owasp_category="A01:2021-Broken Access Control",
        crs_rule_range=(930000, 930999),
        severity="high",
        variants=[
            AttackVariant(
                name="dot_dot_slash",
                description="Classic ../ path traversal",
                crs_rules=["930100", "930110"]
            ),
            AttackVariant(
                name="encoded",
                description="URL-encoded path traversal (%2e%2e%2f)",
                crs_rules=["930120", "930130"]
            ),
            AttackVariant(
                name="double_encoded",
                description="Double URL-encoded traversal (%252e%252e%252f)",
                crs_rules=["930100", "930110"]
            ),
            AttackVariant(
                name="null_byte",
                description="Null byte injection for extension bypass",
                crs_rules=["930140"]
            ),
            AttackVariant(
                name="os_files",
                description="Access to sensitive OS files (/etc/passwd, etc.)",
                crs_rules=["930120"]
            ),
        ]
    ),

    "ssrf": AttackFamily(
        name="ssrf",
        description="Server-Side Request Forgery - Forcing server to make requests",
        capec_id="CAPEC-664",
        cwe_id="CWE-918",
        owasp_category="A10:2021-SSRF",
        crs_rule_range=(931000, 931999),
        severity="high",
        variants=[
            AttackVariant(
                name="internal_ip",
                description="SSRF to internal IP addresses (127.0.0.1, 10.x, 192.168.x)",
                crs_rules=["931100", "931110"]
            ),
            AttackVariant(
                name="cloud_metadata",
                description="Access to cloud metadata endpoints (169.254.169.254)",
                crs_rules=["931120", "931130"]
            ),
            AttackVariant(
                name="protocol_smuggling",
                description="SSRF via protocol handlers (file://, gopher://)",
                crs_rules=["931100"]
            ),
            AttackVariant(
                name="dns_rebinding",
                description="DNS rebinding attacks",
                crs_rules=["931110"]
            ),
        ]
    ),

    "info_disclosure": AttackFamily(
        name="info_disclosure",
        description="Information Disclosure - Exposure of sensitive information",
        capec_id="CAPEC-118",
        cwe_id="CWE-200",
        owasp_category="A01:2021-Broken Access Control",
        crs_rule_range=(913000, 913999),
        severity="low",
        variants=[
            AttackVariant(
                name="scanner_detection",
                description="Automated scanner/vulnerability scanner detection",
                crs_rules=["913100", "913110", "913120"]
            ),
            AttackVariant(
                name="sensitive_files",
                description="Access to sensitive files (.git, .env, backup)",
                crs_rules=["930120"]
            ),
            AttackVariant(
                name="error_messages",
                description="Information leakage via error messages",
                crs_rules=["913100"]
            ),
            AttackVariant(
                name="directory_listing",
                description="Directory listing/enumeration",
                crs_rules=["913110"]
            ),
        ]
    ),

    "idor": AttackFamily(
        name="idor",
        description="Insecure Direct Object Reference - Unauthorized access to resources via manipulated identifiers",
        capec_id="CAPEC-639",
        cwe_id="CWE-639",
        owasp_category="A01:2021-Broken Access Control",
        crs_rule_range=(0, 0),  # Custom detection (adversarial context)
        severity="high",
        variants=[
            AttackVariant(
                name="user_enum",
                description="User/account ID enumeration via REST API",
                crs_rules=["custom-idor-001", "custom-idor-002"]
            ),
            AttackVariant(
                name="resource_enum",
                description="Generic resource ID enumeration (orders, files, messages)",
                crs_rules=["custom-idor-003", "custom-idor-004", "custom-idor-005"]
            ),
            AttackVariant(
                name="param_tampering",
                description="Query parameter ID tampering",
                crs_rules=["custom-idor-006", "custom-idor-007"]
            ),
            AttackVariant(
                name="graphql_idor",
                description="GraphQL ID-based access control bypass",
                crs_rules=["custom-idor-008"]
            ),
            AttackVariant(
                name="uuid_enum",
                description="UUID/GUID-based resource enumeration",
                crs_rules=["custom-idor-009"]
            ),
        ]
    ),

    "csrf": AttackFamily(
        name="csrf",
        description="Cross-Site Request Forgery - Forcing authenticated users to perform unintended actions",
        capec_id="CAPEC-62",
        cwe_id="CWE-352",
        owasp_category="A01:2021-Broken Access Control",
        crs_rule_range=(0, 0),  # Custom detection (adversarial context)
        severity="medium",
        variants=[
            AttackVariant(
                name="state_change",
                description="State-changing requests without CSRF protection",
                crs_rules=["custom-csrf-001", "custom-csrf-002", "custom-csrf-003"]
            ),
            AttackVariant(
                name="financial",
                description="Financial/monetary operations vulnerable to CSRF",
                crs_rules=["custom-csrf-004"]
            ),
            AttackVariant(
                name="account_takeover",
                description="Account settings modification via CSRF",
                crs_rules=["custom-csrf-005"]
            ),
            AttackVariant(
                name="form_action",
                description="Form-based CSRF attacks",
                crs_rules=["custom-csrf-006"]
            ),
            AttackVariant(
                name="cross_origin",
                description="Cross-origin request attempts",
                crs_rules=["custom-csrf-007"]
            ),
        ]
    ),

    "auth_bypass": AttackFamily(
        name="auth_bypass",
        description="Authentication Bypass - Circumventing authentication mechanisms",
        capec_id="CAPEC-115",
        cwe_id="CWE-287",
        owasp_category="A07:2021-Identification and Authentication Failures",
        crs_rule_range=(0, 0),  # No specific CRS range, composite detection
        severity="high",
        variants=[
            AttackVariant(
                name="sqli_auth",
                description="SQL injection-based authentication bypass",
                crs_rules=["942100", "942110", "custom-auth-001"]
            ),
            AttackVariant(
                name="default_creds",
                description="Default/common credentials",
                crs_rules=["custom-auth-003", "custom-auth-010"]
            ),
            AttackVariant(
                name="jwt_manipulation",
                description="JWT algorithm confusion and token manipulation",
                crs_rules=["custom-auth-002", "custom-auth-004"]
            ),
            AttackVariant(
                name="privilege_escalation",
                description="Parameter-based privilege escalation",
                crs_rules=["custom-auth-005", "custom-auth-006"]
            ),
            AttackVariant(
                name="forced_browsing",
                description="Direct access to protected endpoints",
                crs_rules=["custom-auth-007"]
            ),
            AttackVariant(
                name="header_spoofing",
                description="IP/header spoofing for access control bypass",
                crs_rules=["custom-auth-008"]
            ),
            AttackVariant(
                name="session_manipulation",
                description="Session fixation and manipulation attacks",
                crs_rules=["custom-auth-009"]
            ),
        ]
    ),

    "file_upload": AttackFamily(
        name="file_upload",
        description="Malicious File Upload - Uploading executable/malicious files",
        capec_id="CAPEC-1",
        cwe_id="CWE-434",
        owasp_category="A04:2021-Insecure Design",
        crs_rule_range=(0, 0),  # Custom detection
        severity="high",
        variants=[
            AttackVariant(
                name="webshell",
                description="Web shell upload (PHP, JSP, ASP)",
                crs_rules=[]
            ),
            AttackVariant(
                name="extension_bypass",
                description="File extension bypass techniques",
                crs_rules=[]
            ),
            AttackVariant(
                name="content_type_bypass",
                description="Content-Type header manipulation",
                crs_rules=[]
            ),
        ]
    ),

    "others": AttackFamily(
        name="others",
        description="Unclassified - Requests not matching any known attack pattern",
        capec_id=None,
        cwe_id=None,
        owasp_category=None,
        crs_rule_range=(0, 0),
        severity="info",
        variants=[]
    ),
}

# Final in-scope families for this study (fixed by experiment design).
# Any other family labels are treated as out-of-scope and excluded from
# attack-success analysis.
TARGET_ATTACK_FAMILIES = {
    "sqli",
    "xss",
    "cmdi",
    "path_traversal",
    "auth_bypass",
    "idor",
    "ssrf",
    "csrf",
    "file_upload",
    "info_disclosure",
}


# =============================================================================
# Helper Functions
# =============================================================================

def get_family(name: str) -> Optional[AttackFamily]:
    """Get attack family by name."""
    return ATTACK_FAMILIES.get(name)


def get_family_by_crs_rule(rule_id: str) -> Optional[str]:
    """Get attack family name from CRS rule ID."""
    try:
        rule_num = int(rule_id)
    except ValueError:
        return None

    for family_name, family in ATTACK_FAMILIES.items():
        if family.crs_rule_range[0] <= rule_num <= family.crs_rule_range[1]:
            return family_name
    return None


def get_variant_by_crs_rule(family_name: str, rule_id: str) -> Optional[str]:
    """Get specific variant name from CRS rule ID within a family."""
    family = ATTACK_FAMILIES.get(family_name)
    if not family:
        return None

    for variant in family.variants:
        if rule_id in variant.crs_rules:
            return variant.name
    return None


def list_all_families() -> list[str]:
    """List all attack family names."""
    return list(ATTACK_FAMILIES.keys())


def is_target_family(name: str) -> bool:
    """Return True when the family is one of the fixed 10 in-scope families."""
    return name in TARGET_ATTACK_FAMILIES


def get_family_info(name: str) -> Optional[dict]:
    """Get attack family info as dict."""
    family = ATTACK_FAMILIES.get(name)
    if not family:
        return None

    return {
        "name": family.name,
        "description": family.description,
        "capec_id": family.capec_id,
        "cwe_id": family.cwe_id,
        "owasp_category": family.owasp_category,
        "severity": family.severity,
        "variants": [v.name for v in family.variants],
    }


def create_attack_label(
    family: str,
    matched_rules: list[str] = None
) -> dict:
    """Create standardized attack label structure."""
    family_info = ATTACK_FAMILIES.get(family, ATTACK_FAMILIES["others"])

    return {
        "family": family_info.name,
        "matched_rules": matched_rules or [],
        "capec_id": family_info.capec_id,
        "cwe_id": family_info.cwe_id,
    }


# =============================================================================
# CRS Rule ID → Family Mapping (for quick lookup)
# =============================================================================

CRS_RULE_FAMILY_MAP = {
    # 913xxx - Scanner Detection
    "913": "info_disclosure",
    # 920xxx - Protocol Enforcement (generic validation)
    "920": "others",
    # 921xxx - Protocol Attack
    "921": "others",
    # 930xxx - LFI
    "930": "path_traversal",
    # 931xxx - RFI/SSRF
    "931": "ssrf",
    # 932xxx - RCE
    "932": "cmdi",
    # 933xxx - PHP Injection
    "933": "cmdi",
    # 934xxx - Node.js Injection
    "934": "cmdi",
    # 941xxx - XSS
    "941": "xss",
    # 942xxx - SQLi
    "942": "sqli",
    # 943xxx - Session Fixation
    "943": "auth_bypass",
    # Custom rule prefixes (for custom-xxx-nnn patterns)
    "cus": "others",  # Default for custom patterns (handled by pattern matching)
}


def get_family_from_rule_prefix(rule_id: str) -> str:
    """Quick lookup of family from rule ID prefix."""
    if len(rule_id) >= 3:
        prefix = rule_id[:3]
        return CRS_RULE_FAMILY_MAP.get(prefix, "others")
    return "others"


if __name__ == "__main__":
    # Print taxonomy summary
    print("Attack Classification Taxonomy")
    print("=" * 60)

    for name, family in ATTACK_FAMILIES.items():
        if name == "others":
            continue
        print(f"\n{family.name.upper()}")
        print(f"  Description: {family.description}")
        print(f"  CAPEC: {family.capec_id}, CWE: {family.cwe_id}")
        print(f"  OWASP: {family.owasp_category}")
        print(f"  CRS Rules: {family.crs_rule_range[0]}-{family.crs_rule_range[1]}")
        print(f"  Severity: {family.severity}")
        if family.variants:
            print(f"  Variants: {', '.join(v.name for v in family.variants)}")
