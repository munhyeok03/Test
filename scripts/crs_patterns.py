#!/usr/bin/env python3
"""
OWASP CRS Pattern Definitions for HTTP Attack Classification
=============================================================
Regular expressions derived from OWASP ModSecurity Core Rule Set v4.x.

These patterns are simplified versions of CRS rules, optimized for
log analysis rather than real-time WAF operation.

Source: https://github.com/coreruleset/coreruleset
License: Apache 2.0

Note: This is not a complete implementation of CRS. For production WAF
use cases, use the official ModSecurity + CRS installation.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

from attack_taxonomy import (
    get_family_from_rule_prefix,
    get_variant_by_crs_rule,
    ATTACK_FAMILIES,
)


@dataclass
class CRSPattern:
    """A single CRS-derived pattern."""
    rule_id: str
    pattern: str  # Regex pattern
    description: str
    severity: str = "medium"  # critical, high, medium, low
    compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        """Compile regex pattern."""
        try:
            self.compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
        except re.error as e:
            print(f"Warning: Invalid regex in rule {self.rule_id}: {e}")
            self.compiled = None


# =============================================================================
# SQL Injection Patterns (942xxx)
# Based on REQUEST-942-APPLICATION-ATTACK-SQLI.conf
# =============================================================================

SQLI_PATTERNS = [
    # 942100 - SQL Injection Attack Detected via libinjection
    CRSPattern(
        rule_id="942100",
        pattern=r"(?:'|\"|`|;|--|\#|/\*)\s*(?:OR|AND)\s+(?:'|\"|`|;|--|\#|/\*|\d|[\w\s]+(?:=|<|>|LIKE))",
        description="SQL injection via boolean logic",
        severity="critical"
    ),
    # 942110 - SQL Injection Attack: Common Injection Testing Detected
    CRSPattern(
        rule_id="942110",
        pattern=r"(?:'\s*(?:OR|AND)\s*'?\d*'?\s*=\s*'?\d*|'\s*(?:OR|AND)\s*'[^']*'\s*=\s*'[^']*')",
        description="SQL injection authentication bypass pattern",
        severity="critical"
    ),
    # 942120 - SQL Injection Attack: SQL Operator Detected
    CRSPattern(
        rule_id="942120",
        pattern=r"(?:\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b.*\bWHERE\b)",
        description="UNION SELECT or SELECT FROM WHERE",
        severity="critical"
    ),
    # 942130 - SQL Injection Attack: SQL Tautology Detected
    CRSPattern(
        rule_id="942130",
        pattern=r"(?:'\s*=\s*'|1\s*=\s*1|'[^']*'\s*=\s*'[^']*')",
        description="SQL tautology (always true condition)",
        severity="high"
    ),
    # 942140 - SQL Injection Attack: Common DB Names Detected
    CRSPattern(
        rule_id="942140",
        pattern=r"(?:\b(?:information_schema|mysql|sys|performance_schema)\b)",
        description="Reference to system databases",
        severity="high"
    ),
    # 942150 - SQL Injection Attack
    CRSPattern(
        rule_id="942150",
        pattern=r"(?:SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|pg_sleep)",
        description="Time-based SQL injection",
        severity="critical"
    ),
    # 942160 - Detects blind sqli tests using sleep() or benchmark()
    CRSPattern(
        rule_id="942160",
        pattern=r"(?:(?:SLEEP|BENCHMARK|WAIT\s+FOR\s+DELAY)\s*\([^)]*\))",
        description="Blind SQL injection timing attack",
        severity="critical"
    ),
    # 942170 - SQL Injection Attack: Concatenation
    CRSPattern(
        rule_id="942170",
        pattern=r"(?:\|\||CONCAT|CONCAT_WS|GROUP_CONCAT)\s*\(",
        description="SQL string concatenation",
        severity="medium"
    ),
    # 942180 - Detects basic SQL authentication bypass attempts
    CRSPattern(
        rule_id="942180",
        pattern=r"(?:'--|\)\s*--|;\s*--)",
        description="SQL comment-based injection",
        severity="high"
    ),
    # 942190 - Detects MSSQL code execution and information gathering attempts
    CRSPattern(
        rule_id="942190",
        pattern=r"(?:EXEC\s*\(|EXECUTE\s+|xp_cmdshell|sp_executesql)",
        description="MSSQL stored procedure execution",
        severity="critical"
    ),
    # 942200 - Detects MySQL comment-/space-obfuscated injections
    CRSPattern(
        rule_id="942200",
        pattern=r"(?:/\*[!+]|\*/\s*(?:UNION|SELECT|INSERT|UPDATE|DELETE))",
        description="MySQL comment obfuscation",
        severity="high"
    ),
    # 942210 - Detects chained SQL injection attempts
    CRSPattern(
        rule_id="942210",
        pattern=r"(?:;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE))",
        description="Stacked SQL queries",
        severity="critical"
    ),
    # 942220 - Integer Overflow Attack
    CRSPattern(
        rule_id="942220",
        pattern=r"(?:\d{10,})",
        description="Potential integer overflow",
        severity="low"
    ),
    # 942230 - Detects conditional SQL injection attempts
    CRSPattern(
        rule_id="942230",
        pattern=r"(?:CASE\s+WHEN|IF\s*\([^)]+,)",
        description="Conditional SQL injection",
        severity="high"
    ),
    # 942240 - Detects MySQL charset switch and MSSQL DoS attempts
    CRSPattern(
        rule_id="942240",
        pattern=r"(?:CHARSET\s*=|COLLATE\s+)",
        description="Charset manipulation",
        severity="medium"
    ),
    # 942250 - Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections
    CRSPattern(
        rule_id="942250",
        pattern=r"(?:MATCH\s*\([^)]+\)\s*AGAINST|EXECUTE\s+IMMEDIATE)",
        description="Advanced SQL injection techniques",
        severity="high"
    ),
    # 942260 - Detects basic SQL authentication bypass attempts 2/3
    CRSPattern(
        rule_id="942260",
        pattern=r"(?:admin'--|'\s*OR\s+'[^']*'\s*=\s*')",
        description="Admin SQL injection bypass",
        severity="critical"
    ),
    # 942270 - SQL injection
    CRSPattern(
        rule_id="942270",
        pattern=r"(?:0x[0-9a-f]+|X'[0-9a-f]+')",
        description="Hex-encoded SQL injection",
        severity="medium"
    ),
    # 942280 - Detects Postgres pg_sleep injection
    CRSPattern(
        rule_id="942280",
        pattern=r"(?:pg_sleep\s*\(|;.*\bSELECT\b.*pg_sleep)",
        description="PostgreSQL time-based injection",
        severity="critical"
    ),
    # 942290 - Detects basic MongoDB SQL injection attempts
    CRSPattern(
        rule_id="942290",
        pattern=r'(?:\$(?:where|gt|lt|ne|eq|regex|exists|type)\s*:)',
        description="MongoDB NoSQL injection",
        severity="high"
    ),
    # 942300 - Detects MySQL comments, conditions and ch(a)r injections
    CRSPattern(
        rule_id="942300",
        pattern=r"(?:CHAR\s*\(\d+(?:\s*,\s*\d+)*\)|CHR\s*\(\d+\))",
        description="CHAR/CHR function injection",
        severity="high"
    ),
    # 942310 - Detects chained SQL injection attempts 2/2
    CRSPattern(
        rule_id="942310",
        pattern=r"(?:'\s*;\s*(?:DROP|DELETE|UPDATE|INSERT))",
        description="Destructive stacked queries",
        severity="critical"
    ),
    # 942320 - Detects MySQL and PostgreSQL stored procedure/function injections
    CRSPattern(
        rule_id="942320",
        pattern=r"(?:CREATE\s+(?:FUNCTION|PROCEDURE)|LOAD_FILE\s*\()",
        description="Stored procedure/function creation or file read",
        severity="critical"
    ),
    # 942330 - Detects classic SQL injection probings
    CRSPattern(
        rule_id="942330",
        pattern=r"(?:'\s*(?:HAVING|GROUP\s+BY|ORDER\s+BY)\s+\d+)",
        description="SQL injection probing",
        severity="medium"
    ),
    # 942340 - Detects basic SQL authentication bypass attempts 3/3
    CRSPattern(
        rule_id="942340",
        pattern=r"(?:'\s*OR\s+\d+\s*=\s*\d+)",
        description="Numeric tautology injection",
        severity="high"
    ),
    # 942350 - Detects MySQL UDF injection and other data/structure manipulation attempts
    CRSPattern(
        rule_id="942350",
        pattern=r"(?:INTO\s+(?:OUTFILE|DUMPFILE)\s*')",
        description="MySQL file write attempt",
        severity="critical"
    ),
    # 942360 - Detects concatenated basic SQL injection and SQLLFI attempts
    CRSPattern(
        rule_id="942360",
        pattern=r"(?:UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL|0x|CHAR))",
        description="UNION SELECT with NULL/encoded values",
        severity="critical"
    ),
    # 942370 - Detects classic SQL injection probings 2/2
    CRSPattern(
        rule_id="942370",
        pattern=r"(?:';\s*(?:SHUTDOWN|EXEC|DROP))",
        description="Dangerous command injection via SQL",
        severity="critical"
    ),
    # 942380 - SQL Injection Attack
    CRSPattern(
        rule_id="942380",
        pattern=r"(?:@@(?:version|datadir|basedir|hostname))",
        description="MySQL variable extraction",
        severity="high"
    ),
    # 942390 - SQL Injection Attack
    CRSPattern(
        rule_id="942390",
        pattern=r"(?:;\s*\bDECLARE\b|\bCURSOR\b\s+FOR)",
        description="SQL cursor/declare injection",
        severity="high"
    ),
    # 942400 - SQL Injection Attack
    CRSPattern(
        rule_id="942400",
        pattern=r"(?:\bEXTRACTVALUE\s*\(|\bUPDATEXML\s*\()",
        description="XML-based SQL injection",
        severity="critical"
    ),
    # 942410 - SQL Injection Attack
    CRSPattern(
        rule_id="942410",
        pattern=r"(?:--\s*$|/\*.*\*/|#\s*$)",
        description="SQL comment termination",
        severity="medium"
    ),
    # 942420 - Restricted SQL Character Anomaly Detection
    CRSPattern(
        rule_id="942420",
        pattern=r"(?:(?:[\'\"])\s*!\s*[\'\"])",
        description="SQL quote anomaly",
        severity="low"
    ),
    # 942430 - Restricted SQL Character Anomaly Detection (args)
    CRSPattern(
        rule_id="942430",
        pattern=r"(?:CONVERT\s*\(|CAST\s*\([^)]+\s+AS\s+)",
        description="SQL type conversion",
        severity="medium"
    ),
    # 942440 - SQL Comment Sequence Detected
    CRSPattern(
        rule_id="942440",
        pattern=r"(?:/\*!?\d*)",
        description="MySQL version-specific comment",
        severity="medium"
    ),
    # 942450 - SQL Hex Encoding Identified
    CRSPattern(
        rule_id="942450",
        pattern=r"(?:0x[0-9A-Fa-f]{8,})",
        description="Long hex-encoded value",
        severity="medium"
    ),
    # 942460 - SQL Injection Attack (boolean/logical)
    CRSPattern(
        rule_id="942460",
        pattern=r"(?:AND\s+\d+\s*(?:=|<|>)\s*\d+|OR\s+\d+\s*(?:=|<|>)\s*\d+)",
        description="Boolean condition injection",
        severity="high"
    ),
]


# =============================================================================
# XSS Patterns (941xxx)
# Based on REQUEST-941-APPLICATION-ATTACK-XSS.conf
# =============================================================================

XSS_PATTERNS = [
    # 941100 - XSS Attack Detected via libinjection
    CRSPattern(
        rule_id="941100",
        pattern=r"(?:<script[^>]*>|</script>)",
        description="Script tag injection",
        severity="critical"
    ),
    # 941110 - XSS Filter - Category 1: Script Tag Vector
    CRSPattern(
        rule_id="941110",
        pattern=r"(?:<script\b[^>]*>[^<]*</script>|<script\b)",
        description="Script tag with content",
        severity="critical"
    ),
    # 941120 - XSS Filter - Category 2: Event Handler Vector
    CRSPattern(
        rule_id="941120",
        pattern=r"(?:\bon\w+\s*=\s*['\"][^'\"]*['\"]|\bon\w+\s*=\s*[^\s>]+)",
        description="Event handler attribute",
        severity="high"
    ),
    # 941130 - XSS Filter - Category 3: Attribute Vector
    CRSPattern(
        rule_id="941130",
        pattern=r"(?:javascript\s*:|vbscript\s*:|data\s*:text/html)",
        description="JavaScript/VBScript protocol",
        severity="critical"
    ),
    # 941140 - XSS Filter - Category 4: JavaScript URI Vector
    CRSPattern(
        rule_id="941140",
        pattern=r'(?:href\s*=\s*["\']?\s*javascript:|src\s*=\s*["\']?\s*javascript:)',
        description="JavaScript in href/src",
        severity="critical"
    ),
    # 941150 - XSS Filter - Category 5: Disallowed HTML Attributes
    CRSPattern(
        rule_id="941150",
        pattern=r"(?:<[^>]+\b(?:style|background)\s*=\s*[^>]*(?:expression|javascript|vbscript))",
        description="XSS via style/background attributes",
        severity="high"
    ),
    # 941160 - NoScript XSS InjectionChecker: HTML Injection
    CRSPattern(
        rule_id="941160",
        pattern=r"(?:<(?:img|iframe|object|embed|applet|form|input|button|select|textarea|style|link|meta|base)[^>]*>)",
        description="Potentially dangerous HTML tags",
        severity="medium"
    ),
    # 941170 - NoScript XSS InjectionChecker: Attribute Injection
    CRSPattern(
        rule_id="941170",
        pattern=r'(?:[\'"]\s*(?:formaction|action|href|src|data|poster|code|value)\s*=)',
        description="Attribute injection attempt",
        severity="medium"
    ),
    # 941180 - Node-Validator Blacklist Keywords
    CRSPattern(
        rule_id="941180",
        pattern=r"(?:document\s*\.\s*(?:cookie|domain|write|location)|window\s*\.\s*(?:location|open))",
        description="DOM manipulation attempt",
        severity="high"
    ),
    # 941190 - IE XSS Filters - Attack Detected
    CRSPattern(
        rule_id="941190",
        pattern=r"(?:<[^>]*\s+on\w+\s*=)",
        description="Event handler in tag",
        severity="high"
    ),
    # 941200 - IE XSS Filters - Attack Detected 2
    CRSPattern(
        rule_id="941200",
        pattern=r"(?:alert\s*\(|confirm\s*\(|prompt\s*\()",
        description="JavaScript dialog functions",
        severity="medium"
    ),
    # 941210 - IE XSS Filters - Attack Detected 3
    CRSPattern(
        rule_id="941210",
        pattern=r"(?:eval\s*\(|setTimeout\s*\(|setInterval\s*\(|Function\s*\(|new\s+Function)",
        description="JavaScript code execution",
        severity="critical"
    ),
    # 941220 - IE XSS Filters - Attack Detected 4
    CRSPattern(
        rule_id="941220",
        pattern=r"(?:document\s*\[\s*['\"]cookie['\"]|window\s*\[\s*['\"]location['\"])",
        description="Bracket notation DOM access",
        severity="high"
    ),
    # 941230 - IE XSS Filters - Attack Detected 5
    CRSPattern(
        rule_id="941230",
        pattern=r"(?:fromCharCode\s*\(|String\s*\.\s*fromCharCode)",
        description="String.fromCharCode encoding",
        severity="medium"
    ),
    # 941240 - IE XSS Filters - Attack Detected 6
    CRSPattern(
        rule_id="941240",
        pattern=r"(?:innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML)",
        description="DOM HTML injection",
        severity="high"
    ),
    # 941250 - IE XSS Filters - Attack Detected 7
    CRSPattern(
        rule_id="941250",
        pattern=r"(?:import\s*\(|require\s*\()",
        description="Dynamic import/require",
        severity="medium"
    ),
    # 941260 - IE XSS Filters - Attack Detected 8
    CRSPattern(
        rule_id="941260",
        pattern=r"(?:\.\s*constructor\s*\(|\.\s*__proto__)",
        description="Prototype pollution",
        severity="high"
    ),
    # 941270 - IE XSS Filters - Attack Detected 9
    CRSPattern(
        rule_id="941270",
        pattern=r"(?:<svg[^>]*onload|<svg[^>]*onerror|<body[^>]*onload)",
        description="SVG/body event handlers",
        severity="critical"
    ),
    # 941280 - IE XSS Filters - Attack Detected 10
    CRSPattern(
        rule_id="941280",
        pattern=r"(?:<math[^>]*>|<maction[^>]*>)",
        description="MathML XSS vectors",
        severity="medium"
    ),
    # 941290 - IE XSS Filters - Attack Detected 11
    CRSPattern(
        rule_id="941290",
        pattern=r"(?:<details[^>]*ontoggle|<video[^>]*onerror|<audio[^>]*onerror)",
        description="HTML5 event handlers",
        severity="high"
    ),
    # 941300 - IE XSS Filters - Attack Detected 12
    CRSPattern(
        rule_id="941300",
        pattern=r"(?:<isindex[^>]*>|<input[^>]*onfocus[^>]*autofocus)",
        description="Legacy/autofocus XSS",
        severity="high"
    ),
    # 941310 - US-ASCII Malformed Encoding XSS Filter
    CRSPattern(
        rule_id="941310",
        pattern=r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})",
        description="Hex/Unicode escape sequences",
        severity="medium"
    ),
    # 941320 - Possible XSS Attack Detected - HTML Tag Handler
    CRSPattern(
        rule_id="941320",
        pattern=r"(?:%3C|%3E|&lt;|&gt;|&#60|&#62|&#x3c|&#x3e)",
        description="Encoded angle brackets",
        severity="medium"
    ),
    # 941330 - IE XSS Filters - Attack Detected 13
    CRSPattern(
        rule_id="941330",
        pattern=r"(?:\\x3c|\\x3e|\\u003c|\\u003e)",
        description="Escaped angle brackets",
        severity="medium"
    ),
    # 941340 - IE XSS Filters - Attack Detected 14
    CRSPattern(
        rule_id="941340",
        pattern=r"(?:<marquee[^>]*>|<blink[^>]*>)",
        description="Deprecated HTML tags",
        severity="low"
    ),
    # 941350 - UTF-7 Encoding IE XSS
    CRSPattern(
        rule_id="941350",
        pattern=r"(?:\+ADw-|\+AD4-)",
        description="UTF-7 encoded XSS",
        severity="high"
    ),
    # 941360 - JSFuck / Hieroglyphy Obfuscation Detected
    CRSPattern(
        rule_id="941360",
        pattern=r"(?:\[\]\[\s*['\"]|\]\s*\(\s*\)\s*\[)",
        description="JSFuck obfuscation",
        severity="high"
    ),
    # 941370 - JavaScript global variable
    CRSPattern(
        rule_id="941370",
        pattern=r"(?:this\s*\[\s*['\"]|self\s*\[\s*['\"])",
        description="Global variable access via brackets",
        severity="medium"
    ),
    # 941380 - AngularJS Client Side Template Injection
    CRSPattern(
        rule_id="941380",
        pattern=r"(?:\{\{.*\}\}|\[\[.*\]\])",
        description="Template injection (AngularJS, etc.)",
        severity="high"
    ),
]


# =============================================================================
# Command Injection / RCE Patterns (932xxx)
# Based on REQUEST-932-APPLICATION-ATTACK-RCE.conf
# =============================================================================

CMDI_PATTERNS = [
    # 932100 - Remote Command Execution: Unix Command Injection
    CRSPattern(
        rule_id="932100",
        pattern=r"(?:;\s*(?:ls|cat|id|whoami|uname|pwd|echo|wget|curl)\b)",
        description="Unix command after semicolon",
        severity="critical"
    ),
    # 932105 - Remote Command Execution: Unix Command Injection
    CRSPattern(
        rule_id="932105",
        pattern=r"(?:\|\s*(?:ls|cat|id|whoami|uname|pwd|sh|bash)\b)",
        description="Unix command after pipe",
        severity="critical"
    ),
    # 932110 - Remote Command Execution: Windows Command Injection
    CRSPattern(
        rule_id="932110",
        pattern=r"(?:(?:cmd|powershell)(?:\.exe)?(?:\s+/c)?)",
        description="Windows shell invocation",
        severity="critical"
    ),
    # 932115 - Remote Command Execution: Windows Command Injection
    CRSPattern(
        rule_id="932115",
        pattern=r"(?:&\s*(?:dir|type|echo|set|net|whoami)\b)",
        description="Windows command after ampersand",
        severity="critical"
    ),
    # 932120 - Remote Command Execution: Windows PowerShell Command
    CRSPattern(
        rule_id="932120",
        pattern=r"(?:Invoke-Expression|IEX|Invoke-Command|Invoke-WebRequest|Start-Process)",
        description="PowerShell cmdlets",
        severity="critical"
    ),
    # 932130 - Remote Command Execution: Unix Shell Expression
    CRSPattern(
        rule_id="932130",
        pattern=r"(?:\$\([^)]+\)|`[^`]+`)",
        description="Shell command substitution",
        severity="critical"
    ),
    # 932140 - Remote Command Execution: Windows FOR/IF Command
    CRSPattern(
        rule_id="932140",
        pattern=r"(?:(?:for|if)\s+.*\s+(?:do|in)\b)",
        description="Windows FOR/IF loops",
        severity="high"
    ),
    # 932150 - Remote Command Execution: Direct Unix Command Execution
    CRSPattern(
        rule_id="932150",
        pattern=r"(?:/bin/(?:bash|sh|dash|zsh|csh|ksh|tcsh)|/usr/bin/(?:perl|python|ruby|php|node))",
        description="Direct shell/interpreter path",
        severity="critical"
    ),
    # 932160 - Remote Command Execution: Unix Shell Code
    CRSPattern(
        rule_id="932160",
        pattern=r"(?:(?:nc|netcat|ncat)\s+.*-[elcp]|\bexec\s+\d+[<>]|/dev/(?:tcp|udp)/)",
        description="Reverse shell patterns",
        severity="critical"
    ),
    # 932170 - Remote Command Execution: Shellshock
    CRSPattern(
        rule_id="932170",
        pattern=r"(?:\(\)\s*\{[^}]*;\s*\}\s*;)",
        description="Shellshock exploit pattern",
        severity="critical"
    ),
    # 932171 - Remote Command Execution: Shellshock 2
    CRSPattern(
        rule_id="932171",
        pattern=r"(?:\(\)\s*\{)",
        description="Shellshock function definition",
        severity="high"
    ),
    # 932180 - Restricted File Upload Attempt
    CRSPattern(
        rule_id="932180",
        pattern=r"(?:\.(?:php|phtml|php3|php4|php5|phps|phar|inc)[;\s]|\.(?:jsp|jspx|jspa|jsw|jsv|jspf))",
        description="Executable file extension",
        severity="high"
    ),
    # 932190 - Remote Command Execution: Wildcard Bypass
    CRSPattern(
        rule_id="932190",
        pattern=r"(?:/\?\?\?/\?\?\?/\?\?\?\?\?|/\?\?\?/\?\?\?\?\?\?\?\?\?\?)",
        description="Wildcard command bypass",
        severity="high"
    ),
    # 932200 - RCE Bypass Technique
    CRSPattern(
        rule_id="932200",
        pattern=r'(?:\$(?:IFS|PATH|HOME|USER|SHELL)|\${[^}]+})',
        description="Shell variable injection",
        severity="high"
    ),
]


# =============================================================================
# Path Traversal / LFI Patterns (930xxx)
# Based on REQUEST-930-APPLICATION-ATTACK-LFI.conf
# =============================================================================

PATH_TRAVERSAL_PATTERNS = [
    # 930100 - Path Traversal Attack (/../)
    CRSPattern(
        rule_id="930100",
        pattern=r"(?:\.\./|\.\.\\)",
        description="Basic path traversal",
        severity="high"
    ),
    # 930110 - Path Traversal Attack (/../)
    CRSPattern(
        rule_id="930110",
        pattern=r"(?:\.\.(?:/|\\|%2[fF]|%5[cC])){2,}",
        description="Multiple path traversal sequences",
        severity="critical"
    ),
    # 930120 - OS File Access Attempt
    CRSPattern(
        rule_id="930120",
        pattern=r"(?:/etc/(?:passwd|shadow|group|hosts|issue|motd|mysql/my\.cnf)|/proc/(?:self|version|cmdline)|boot\.ini|win\.ini|system\.ini)",
        description="Sensitive system file access",
        severity="critical"
    ),
    # 930130 - Restricted File Access Attempt
    CRSPattern(
        rule_id="930130",
        pattern=r"(?:/var/log/|/var/www/|\bwp-config\.php|\.htaccess|\.htpasswd)",
        description="Web server file access",
        severity="high"
    ),
    # 930140 - Path Traversal with Null Byte
    CRSPattern(
        rule_id="930140",
        pattern=r"(?:%00|\\x00|\\0)",
        description="Null byte injection",
        severity="high"
    ),
    # 930150 - URL-encoded path traversal
    CRSPattern(
        rule_id="930150",
        pattern=r"(?:%2[eE]%2[eE](?:%2[fF]|%5[cC])|%252[eE]%252[eE]%252[fF])",
        description="URL-encoded traversal",
        severity="high"
    ),
    # 930160 - Double URL-encoded path traversal
    CRSPattern(
        rule_id="930160",
        pattern=r"(?:%25%32%65%25%32%65(?:%25%32%66|%25%35%63))",
        description="Double URL-encoded traversal",
        severity="critical"
    ),
]


# =============================================================================
# SSRF / RFI Patterns (931xxx)
# Based on REQUEST-931-APPLICATION-ATTACK-RFI.conf
# =============================================================================

SSRF_PATTERNS = [
    # 931100 - Possible Remote File Inclusion (RFI) Attack
    CRSPattern(
        rule_id="931100",
        pattern=r"(?:(?:url|path|file|page|doc|document|folder|root|img|image)\s*=\s*(?:https?://|ftp://|file://|php://|data://|expect://|zip://|glob://|phar://))",
        description="URL parameter with protocol",
        severity="high"
    ),
    # 931110 - Possible Remote File Inclusion (RFI) Attack
    CRSPattern(
        rule_id="931110",
        pattern=r"(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1|0x7[fF]|2130706433)",
        description="Localhost reference",
        severity="high"
    ),
    # 931120 - Cloud Instance Metadata SSRF
    CRSPattern(
        rule_id="931120",
        pattern=r"(?:169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal)",
        description="Cloud metadata endpoint",
        severity="critical"
    ),
    # 931130 - Internal IP Address SSRF
    CRSPattern(
        rule_id="931130",
        pattern=r"(?:(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})",
        description="Internal IP address reference",
        severity="high"
    ),
    # 931140 - Protocol Handler SSRF
    CRSPattern(
        rule_id="931140",
        pattern=r"(?:gopher://|dict://|ldap://|tftp://)",
        description="Alternative protocol handlers",
        severity="high"
    ),
]


# =============================================================================
# Scanner Detection / Info Disclosure Patterns (913xxx)
# Based on REQUEST-913-SCANNER-DETECTION.conf
# =============================================================================

INFO_DISCLOSURE_PATTERNS = [
    # 913100 - Found User-Agent associated with security scanner
    CRSPattern(
        rule_id="913100",
        pattern=r"(?:nikto|sqlmap|nmap|nessus|openvas|acunetix|appscan|burp|w3af|arachni|skipfish|grabber|webshag|dirbuster|gobuster|wfuzz|zaproxy|nuclei|masscan|zap|whatweb|wafw00f)",
        description="Security scanner User-Agent",
        severity="medium"
    ),
    # 913110 - Found request header associated with security scanner
    CRSPattern(
        rule_id="913110",
        pattern=r"(?:X-Scanner|X-Scan|X-Wipp|X-Proxy|X-Forwarded-By|X-Burp-Token)",
        description="Scanner-specific headers",
        severity="low"
    ),
    # 913120 - Found request filename/argument associated with security scanner
    CRSPattern(
        rule_id="913120",
        pattern=r"(?:\.bak|\.backup|\.old|\.orig|\.temp|\.tmp|\.swp|~$)",
        description="Backup file extension probing",
        severity="medium"
    ),
    # Version Control Directories (CWE-527)
    CRSPattern(
        rule_id="custom-info-001",
        pattern=r"(?:/\.(?:git|svn|hg|bzr)(?:/|$))",
        description="Version control directory access",
        severity="high"
    ),
    CRSPattern(
        rule_id="custom-info-002",
        pattern=r"(?:/\.(?:git|svn)/(?:config|HEAD|index|objects|refs|logs|COMMIT_EDITMSG))",
        description="Version control metadata file access",
        severity="high"
    ),
    # Environment/Configuration Files (CWE-538)
    CRSPattern(
        rule_id="custom-info-003",
        pattern=r"(?:/\.env(?:\.(?:local|dev|development|staging|production|test|backup|example))?(?:$|\?))",
        description="Environment file access attempt",
        severity="critical"
    ),
    CRSPattern(
        rule_id="custom-info-004",
        pattern=r"(?:/(?:config|configuration|settings)\.(?:php|py|rb|js|json|yml|yaml|xml|ini))",
        description="Configuration file access",
        severity="high"
    ),
    CRSPattern(
        rule_id="custom-info-005",
        pattern=r"(?:/(?:web|app)\.config|/appsettings\.json|/secrets\.(?:json|yml|yaml))",
        description="Application secrets file access",
        severity="critical"
    ),
    # Log Files (CWE-532)
    CRSPattern(
        rule_id="custom-info-006",
        pattern=r"(?:/(?:var/)?log(?:s)?/|\.log(?:$|\?)|/(?:access|error|debug|application)\.log)",
        description="Log file access attempt",
        severity="medium"
    ),
    CRSPattern(
        rule_id="custom-info-007",
        pattern=r"(?:/(?:debug|trace|audit)\.(?:log|txt))",
        description="Debug/trace log access",
        severity="medium"
    ),
    # Database Files (CWE-530)
    CRSPattern(
        rule_id="custom-info-008",
        pattern=r"(?:/(?:database|db)\.(?:sql|sqlite|sqlite3|mdb|accdb|dump))",
        description="Database file access attempt",
        severity="critical"
    ),
    CRSPattern(
        rule_id="custom-info-009",
        pattern=r"(?:/(?:backup|dump|export)\.(?:sql|tar|gz|zip|bak))",
        description="Database backup file access",
        severity="critical"
    ),
    # Source Code Exposure (CWE-540)
    CRSPattern(
        rule_id="custom-info-010",
        pattern=r"(?:\.(?:php|asp|aspx|jsp|py|rb)~|\.(?:php|asp|aspx|jsp)\.swp)",
        description="Source code backup file access",
        severity="high"
    ),
    CRSPattern(
        rule_id="custom-info-011",
        pattern=r"(?:/(?:src|source|sources|code|app)/.*\.(?:php|py|rb|js|java|go))",
        description="Source directory enumeration",
        severity="medium"
    ),
    # Package Manager Files (CWE-538)
    CRSPattern(
        rule_id="custom-info-012",
        pattern=r"(?:/(?:package|composer|Gemfile|requirements|Pipfile|Cargo)\.(?:json|lock|txt|toml))",
        description="Package manager file access",
        severity="low"
    ),
    # Cloud/Infrastructure Metadata (CWE-200)
    CRSPattern(
        rule_id="custom-info-013",
        pattern=r"(?:/latest/(?:meta-data|user-data|dynamic)|/computeMetadata/v1/)",
        description="Cloud instance metadata access",
        severity="critical"
    ),
    CRSPattern(
        rule_id="custom-info-014",
        pattern=r"(?:\.(?:aws|azure|gcp)/(?:credentials|config))",
        description="Cloud provider credential file access",
        severity="critical"
    ),
    # Server Configuration Files
    CRSPattern(
        rule_id="custom-info-015",
        pattern=r"(?:/\.htaccess|/\.htpasswd|/nginx\.conf|/httpd\.conf|/server\.xml)",
        description="Server configuration file access",
        severity="high"
    ),
    # IDE/Editor Metadata
    CRSPattern(
        rule_id="custom-info-016",
        pattern=r"(?:/\.(?:idea|vscode|vs|project|settings)/|/\.editorconfig)",
        description="IDE metadata directory access",
        severity="low"
    ),
    # Docker/Container Files
    CRSPattern(
        rule_id="custom-info-017",
        pattern=r"(?:/(?:Dockerfile|docker-compose\.yml|\.dockerignore|kubernetes\.yml))",
        description="Container configuration file access",
        severity="medium"
    ),
    # Error Response Patterns (for response analysis)
    CRSPattern(
        rule_id="custom-info-018",
        pattern=r"(?:stack\s*trace|traceback|exception|fatal\s+error|parse\s+error|syntax\s+error)",
        description="Error message information leak",
        severity="medium"
    ),
    CRSPattern(
        rule_id="custom-info-019",
        pattern=r"(?:mysql_|mysqli_|pg_|ora-\d+|sqlite_|mssql_|SQLSTATE\[)",
        description="Database error message leak",
        severity="high"
    ),
    # Robots.txt / Sitemap (recon)
    CRSPattern(
        rule_id="custom-info-020",
        pattern=r"(?:/robots\.txt|/sitemap\.xml|/crossdomain\.xml|/clientaccesspolicy\.xml)",
        description="Web crawling metadata access",
        severity="low"
    ),
]


# =============================================================================
# Deserialization Patterns (944xxx)
# Based on REQUEST-944-APPLICATION-ATTACK-JAVA.conf and custom
# =============================================================================

DESERIALIZATION_PATTERNS = [
    # 944100 - Java Serialization Attack
    CRSPattern(
        rule_id="944100",
        pattern=r"(?:rO0AB|aced0005|AAAAAA|H4sIA|YWNlZDAwMDU)",
        description="Java serialized object signature",
        severity="critical"
    ),
    # 944110 - Java Deserialization Gadgets
    CRSPattern(
        rule_id="944110",
        pattern=r"(?:org\.apache\.commons\.collections\.functors|org\.springframework\.beans\.factory|com\.sun\.org\.apache\.xalan)",
        description="Known Java gadget chains",
        severity="critical"
    ),
    # 944120 - Python Pickle
    CRSPattern(
        rule_id="944120",
        pattern=r"(?:cposix|c__builtin__|csubprocess|cos\nsystem|c__main__)",
        description="Python pickle exploitation",
        severity="critical"
    ),
    # 944130 - Python YAML Deserialization
    CRSPattern(
        rule_id="944130",
        pattern=r"(?:!!python/object|!!python/object/apply|!!python/object/new)",
        description="Python YAML exploitation",
        severity="critical"
    ),
    # 944200 - PHP Object Injection
    CRSPattern(
        rule_id="944200",
        pattern=r'(?:O:\d+:"[^"]+":)',
        description="PHP serialized object",
        severity="critical"
    ),
    # 944210 - Node.js Deserialization
    CRSPattern(
        rule_id="944210",
        pattern=r'(?:_$$ND_FUNC\$\$_|{"rce":|{"run":)',
        description="Node.js serialize-javascript exploitation",
        severity="critical"
    ),
]


# =============================================================================
# IDOR Patterns (Custom - Adversarial Context)
# Based on OWASP WSTG-AUTHZ-04, CWE-639
# In adversarial context, resource ID access patterns indicate IDOR attempts
# =============================================================================

IDOR_PATTERNS = [
    # 1. REST API User/Account Resource Access
    CRSPattern(
        rule_id="custom-idor-001",
        pattern=r"(?:/(?:api/)?(?:v\d+/)?(?:user|users|profile|profiles|account|accounts)/\d+)",
        description="User/account ID enumeration via REST API",
        severity="high"
    ),
    CRSPattern(
        rule_id="custom-idor-002",
        pattern=r"(?:/(?:api/)?(?:v\d+/)?(?:member|members|customer|customers|employee|employees)/\d+)",
        description="Member/customer ID enumeration",
        severity="high"
    ),
    # 2. Order/Transaction Resource Access
    CRSPattern(
        rule_id="custom-idor-003",
        pattern=r"(?:/(?:api/)?(?:v\d+/)?(?:order|orders|purchase|purchases|transaction|transactions)/\d+)",
        description="Order/transaction ID enumeration",
        severity="high"
    ),
    # 3. File/Document Resource Access
    CRSPattern(
        rule_id="custom-idor-004",
        pattern=r"(?:/(?:api/)?(?:v\d+/)?(?:file|files|document|documents|attachment|attachments|upload|uploads)/\d+)",
        description="File/document ID enumeration",
        severity="high"
    ),
    # 4. Message/Communication Resource Access
    CRSPattern(
        rule_id="custom-idor-005",
        pattern=r"(?:/(?:api/)?(?:v\d+/)?(?:message|messages|chat|chats|conversation|conversations|inbox)/\d+)",
        description="Message/conversation ID enumeration",
        severity="medium"
    ),
    # 5. Query Parameter ID Access
    CRSPattern(
        rule_id="custom-idor-006",
        pattern=r"(?:[?&](?:id|user_?id|userId|uid|account_?id|accountId)=\d+)",
        description="User/account ID in query parameter",
        severity="high"
    ),
    CRSPattern(
        rule_id="custom-idor-007",
        pattern=r"(?:[?&](?:order_?id|orderId|oid|file_?id|fileId|fid|doc_?id|docId)=\d+)",
        description="Resource ID in query parameter",
        severity="medium"
    ),
    # 6. GraphQL ID Access
    CRSPattern(
        rule_id="custom-idor-008",
        pattern=r'(?:(?:query|mutation)\s*(?:\w+\s*)?\{[^}]*(?:id|ID|userId|accountId)\s*:\s*["\']?\d+)',
        description="GraphQL ID-based resource access",
        severity="high"
    ),
    # 7. UUID/GUID Resource Access (predictable in some cases)
    CRSPattern(
        rule_id="custom-idor-009",
        pattern=r"(?:/(?:api/)?(?:v\d+/)?\w+/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        description="UUID-based resource access",
        severity="medium"
    ),
    # 8. Nested Resource Access
    CRSPattern(
        rule_id="custom-idor-010",
        pattern=r"(?:/(?:api/)?(?:v\d+/)?(?:user|users)/\d+/(?:order|orders|file|files|message|messages))",
        description="Nested resource access via user ID",
        severity="high"
    ),
    # 9. Admin/Internal Endpoint ID Access
    CRSPattern(
        rule_id="custom-idor-011",
        pattern=r"(?:/(?:admin|internal|management|backend)/(?:user|users|account|accounts)/\d+)",
        description="Admin endpoint user ID access",
        severity="critical"
    ),
    # 10. Basket/Cart ID Access (common in e-commerce)
    CRSPattern(
        rule_id="custom-idor-012",
        pattern=r"(?:/(?:api/)?(?:v\d+/)?(?:basket|baskets|cart|carts|checkout)/\d+)",
        description="Shopping basket/cart ID enumeration",
        severity="high"
    ),
]


# =============================================================================
# CSRF Patterns (Custom - Adversarial Context)
# Based on OWASP WSTG-SESS-05, CWE-352, Mitch (IEEE 2019)
# In adversarial context, state-changing requests indicate CSRF attack attempts
# =============================================================================

CSRF_PATTERNS = [
    # 1. Financial/Monetary State Changes
    CRSPattern(
        rule_id="custom-csrf-001",
        pattern=r"(?:(?:POST|PUT|PATCH)\s+/(?:api/)?(?:v\d+/)?(?:transfer|send|pay|payment|withdraw|deposit))",
        description="Financial operation state change",
        severity="critical"
    ),
    # 2. Account Settings Modification
    CRSPattern(
        rule_id="custom-csrf-002",
        pattern=r"(?:(?:POST|PUT|PATCH)\s+/(?:api/)?(?:v\d+/)?(?:password|email|phone|profile|settings|preferences))",
        description="Account settings modification",
        severity="high"
    ),
    # 3. Administrative Actions
    CRSPattern(
        rule_id="custom-csrf-003",
        pattern=r"(?:(?:POST|PUT|DELETE|PATCH)\s+/(?:api/)?(?:v\d+/)?(?:admin|manage|moderate|config|configuration))",
        description="Administrative action request",
        severity="critical"
    ),
    # 4. Destructive Operations
    CRSPattern(
        rule_id="custom-csrf-004",
        pattern=r"(?:(?:POST|DELETE)\s+/(?:api/)?(?:v\d+/)?(?:delete|remove|destroy|purge|wipe))",
        description="Destructive operation request",
        severity="high"
    ),
    # 5. User Management Actions
    CRSPattern(
        rule_id="custom-csrf-005",
        pattern=r"(?:(?:POST|PUT|DELETE)\s+/(?:api/)?(?:v\d+/)?(?:user|users|account|accounts)/\d+(?:/(?:delete|disable|enable|activate|deactivate))?)",
        description="User management action",
        severity="high"
    ),
    # 6. Form-Based State Change (URL-encoded body)
    CRSPattern(
        rule_id="custom-csrf-006",
        pattern=r"(?:Content-Type:\s*application/x-www-form-urlencoded.*(?:action=|submit=|confirm=|approve=))",
        description="Form-based state change request",
        severity="medium"
    ),
    # 7. Cross-Origin Indicators
    CRSPattern(
        rule_id="custom-csrf-007",
        pattern=r"(?:Origin:\s*(?:null|https?://(?!(?:localhost|127\.0\.0\.1|victim))))",
        description="Cross-origin request indicator",
        severity="medium"
    ),
    # 8. Explicit CSRF Testing Keywords
    CRSPattern(
        rule_id="custom-csrf-008",
        pattern=r"(?:(?:csrf|xsrf|forgery).*(?:bypass|test|exploit|attack|token))",
        description="Explicit CSRF testing attempt",
        severity="high"
    ),
    # 9. Token Manipulation Attempts
    CRSPattern(
        rule_id="custom-csrf-009",
        pattern=r"(?:(?:csrf_token|xsrf_token|_token|authenticity_token)\s*=\s*(?:null|undefined|''|\"\"|test|bypass))",
        description="CSRF token manipulation attempt",
        severity="high"
    ),
    # 10. State Change via GET (Anti-pattern exploitation)
    CRSPattern(
        rule_id="custom-csrf-010",
        pattern=r"(?:GET\s+/(?:api/)?(?:v\d+/)?(?:delete|remove|update|change|modify|transfer)\?)",
        description="State change via GET request (anti-pattern)",
        severity="medium"
    ),
]


# =============================================================================
# Custom Patterns (Auth Bypass, File Upload, etc.)
# =============================================================================

AUTH_BYPASS_PATTERNS = [
    # Original patterns (extended)
    CRSPattern(
        rule_id="custom-auth-001",
        pattern=r"(?:/(?:login|signin|authenticate|auth).*(?:admin'--|'\s*OR\s*'?\d+'\s*=\s*'?\d+))",
        description="SQL injection on login endpoints",
        severity="critical"
    ),
    CRSPattern(
        rule_id="custom-auth-002",
        pattern=r'(?:"alg"\s*:\s*"(?:none|None|NONE)")',
        description="JWT algorithm none bypass",
        severity="critical"
    ),
    CRSPattern(
        rule_id="custom-auth-003",
        pattern=r"(?:(?:admin|root|test|guest|user|demo|manager|operator)(?::|%3[aA])(?:admin|root|test|guest|password|123456|pass|qwerty|letmein))",
        description="Default credentials attempt",
        severity="high"
    ),
    # JWT Manipulation (extended)
    CRSPattern(
        rule_id="custom-auth-004",
        pattern=r'(?:"alg"\s*:\s*"(?:HS256|HS384|HS512)".*"typ"\s*:\s*"JWT")',
        description="JWT with symmetric algorithm (potential key confusion)",
        severity="medium"
    ),
    CRSPattern(
        rule_id="custom-auth-005",
        pattern=r"(?:eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.)",
        description="JWT token structure detected",
        severity="low"
    ),
    # Privilege Escalation Parameters (CAPEC-122)
    CRSPattern(
        rule_id="custom-auth-006",
        pattern=r"(?:(?:admin|role|privilege|isAdmin|is_admin|superuser|is_superuser)\s*[=:]\s*(?:true|1|yes|admin|root|superuser))",
        description="Privilege escalation parameter injection",
        severity="critical"
    ),
    CRSPattern(
        rule_id="custom-auth-007",
        pattern=r"(?:(?:user_type|userType|user_role|userRole|access_level|accessLevel)\s*[=:]\s*(?:admin|administrator|superuser|root|manager))",
        description="Role elevation parameter injection",
        severity="critical"
    ),
    # Forced Browsing / Direct Access (CAPEC-115)
    CRSPattern(
        rule_id="custom-auth-008",
        pattern=r"(?:/(?:admin|administrator|dashboard|internal|debug|console|management|backend|superuser)(?:/|$|\?))",
        description="Direct access to admin/protected endpoints",
        severity="high"
    ),
    # Header Spoofing (CAPEC-194)
    CRSPattern(
        rule_id="custom-auth-009",
        pattern=r"(?:X-Forwarded-For:\s*(?:127\.0\.0\.1|localhost|::1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+))",
        description="IP spoofing via X-Forwarded-For",
        severity="high"
    ),
    CRSPattern(
        rule_id="custom-auth-010",
        pattern=r"(?:X-(?:Original-URL|Rewrite-URL|Custom-IP-Authorization):\s*)",
        description="URL/authorization header manipulation",
        severity="high"
    ),
    # Session Manipulation
    CRSPattern(
        rule_id="custom-auth-011",
        pattern=r"(?:(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session_id|sid)\s*=\s*[a-fA-F0-9]{20,})",
        description="Session ID manipulation/fixation attempt",
        severity="high"
    ),
    # Additional Default Credentials
    CRSPattern(
        rule_id="custom-auth-012",
        pattern=r'(?:(?:"password"|"passwd"|"pwd")\s*:\s*(?:"password"|"123456"|"admin"|"root"|"test"|"qwerty"|"letmein"|"welcome"))',
        description="Common password in JSON body",
        severity="medium"
    ),
    # Authentication Endpoint Probing
    CRSPattern(
        rule_id="custom-auth-013",
        pattern=r"(?:/(?:api/)?(?:v\d+/)?(?:oauth|oauth2|token|jwt|auth|authenticate|login|signin|sso)/)",
        description="Authentication endpoint probing",
        severity="low"
    ),
]

FILE_UPLOAD_PATTERNS = [
    # Original patterns
    CRSPattern(
        rule_id="custom-upload-001",
        pattern=r"(?:Content-Disposition:.*filename=.*\.(?:php|phtml|php3|php4|php5|phar|jsp|jspx|asp|aspx|exe|dll|sh|bash|ps1|py|pl|rb|cgi))",
        description="Executable file upload attempt",
        severity="critical"
    ),
    CRSPattern(
        rule_id="custom-upload-002",
        pattern=r"(?:Content-Type:\s*(?:application/x-httpd-php|text/x-php|application/x-php|application/x-executable|application/x-msdos-program))",
        description="Executable content type in upload",
        severity="high"
    ),
    CRSPattern(
        rule_id="custom-upload-003",
        pattern=r"(?:<\?php|<%@|<jsp:|<%=|<\?=)",
        description="Server-side code in upload content",
        severity="critical"
    ),
    # Double Extension Bypass
    CRSPattern(
        rule_id="custom-upload-004",
        pattern=r"(?:filename=.*\.(?:php|jsp|asp|aspx|exe)\.(?:jpg|jpeg|png|gif|pdf|txt|doc))",
        description="Double extension bypass attempt",
        severity="critical"
    ),
    CRSPattern(
        rule_id="custom-upload-005",
        pattern=r"(?:filename=.*\.(?:jpg|jpeg|png|gif|pdf)\.(?:php|jsp|asp|aspx|exe))",
        description="Reverse double extension bypass",
        severity="critical"
    ),
    # Null Byte Injection
    CRSPattern(
        rule_id="custom-upload-006",
        pattern=r"(?:filename=.*\.(?:php|jsp|asp|aspx)(?:%00|\\x00|\\0)\.(?:jpg|jpeg|png|gif))",
        description="Null byte extension bypass",
        severity="critical"
    ),
    # Content-Type Mismatch
    CRSPattern(
        rule_id="custom-upload-007",
        pattern=r"(?:Content-Type:\s*image/(?:jpeg|png|gif).*(?:<\?php|<script|<%|<jsp:))",
        description="Content-Type mismatch (image header with code)",
        severity="critical"
    ),
    # Web Shell Signatures
    CRSPattern(
        rule_id="custom-upload-008",
        pattern=r"(?:(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|FILES))",
        description="PHP web shell pattern",
        severity="critical"
    ),
    # Polyglot File Indicators
    CRSPattern(
        rule_id="custom-upload-009",
        pattern=r"(?:GIF89a.*<\?php|JFIF.*<\?php|\x89PNG.*<\?php)",
        description="Polyglot file (image header + PHP code)",
        severity="critical"
    ),
    # SVG XSS in Upload
    CRSPattern(
        rule_id="custom-upload-010",
        pattern=r"(?:<svg[^>]*>.*(?:onload|onerror|onclick)\s*=)",
        description="SVG with embedded JavaScript",
        severity="high"
    ),
    # htaccess Upload
    CRSPattern(
        rule_id="custom-upload-011",
        pattern=r"(?:filename=.*\.htaccess)",
        description="Apache .htaccess upload attempt",
        severity="critical"
    ),
]


# =============================================================================
# Pattern Collections
# =============================================================================

ALL_PATTERNS = {
    "sqli": SQLI_PATTERNS,
    "xss": XSS_PATTERNS,
    "cmdi": CMDI_PATTERNS,
    "path_traversal": PATH_TRAVERSAL_PATTERNS,
    "ssrf": SSRF_PATTERNS,
    "info_disclosure": INFO_DISCLOSURE_PATTERNS,
    "deserialization": DESERIALIZATION_PATTERNS,
    "auth_bypass": AUTH_BYPASS_PATTERNS,
    "file_upload": FILE_UPLOAD_PATTERNS,
    "idor": IDOR_PATTERNS,
    "csrf": CSRF_PATTERNS,
}

# CRS anomaly scoring defaults (OWASP CRS documentation).
# - Severity to score mapping: CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2
# - CRS blocking threshold default is 5, but for offline log attribution we use
#   threshold 4 so that a single ERROR-level rule is retained as an attack
#   attempt signal across the fixed 10-technique taxonomy.
CRS_SEVERITY_SCORES = {
    "critical": 5,
    "high": 4,    # aligned with ERROR
    "medium": 3,  # aligned with WARNING
    "low": 2,     # aligned with NOTICE
}
DEFAULT_INBOUND_ANOMALY_THRESHOLD = 4


def get_all_patterns_flat() -> list[tuple[str, CRSPattern]]:
    """Get all patterns as flat list of (family, pattern) tuples."""
    result = []
    for family, patterns in ALL_PATTERNS.items():
        for pattern in patterns:
            result.append((family, pattern))
    return result


def match_patterns(text: str) -> list[dict]:
    """
    Match text against all CRS patterns.

    Args:
        text: Text to match (URL, body, headers combined)

    Returns:
        List of matched patterns with metadata
    """
    matches = []

    for family, patterns in ALL_PATTERNS.items():
        for pattern in patterns:
            if pattern.compiled and pattern.compiled.search(text):
                matches.append({
                    "family": family,
                    "rule_id": pattern.rule_id,
                    "description": pattern.description,
                    "severity": pattern.severity,
                })

    return matches


def classify_text(text: str) -> dict:
    """
    Classify text and return attack label.

    Args:
        text: Combined text from HTTP request

    Returns:
        Attack label dictionary
    """
    matches = match_patterns(text)

    if not matches:
        return {
            "family": "others",
            "matched_rules": [],
            "capec_id": None,
            "cwe_id": None,
            "anomaly_score": 0,
            "classification_threshold": DEFAULT_INBOUND_ANOMALY_THRESHOLD,
            "family_scores": {},
            "classification_method": "crs_anomaly_scoring_v1",
        }

    # Group by family
    family_matches = {}
    for match in matches:
        family = match["family"]
        if family not in family_matches:
            family_matches[family] = []
        family_matches[family].append(match)

    # Compute CRS-style anomaly score by family
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    family_scores = {}
    family_max_severity = {}
    for family_name, family_list in family_matches.items():
        family_scores[family_name] = sum(
            CRS_SEVERITY_SCORES.get(m["severity"], 0) for m in family_list
        )
        family_max_severity[family_name] = max(
            severity_rank.get(m["severity"], 0) for m in family_list
        )

    # Enforce default inbound threshold to reduce low-signal false positives.
    candidate_families = [
        family_name
        for family_name, score in family_scores.items()
        if score >= DEFAULT_INBOUND_ANOMALY_THRESHOLD
    ]

    if not candidate_families:
        return {
            "family": "others",
            "matched_rules": [],
            "capec_id": None,
            "cwe_id": None,
            "anomaly_score": 0,
            "classification_threshold": DEFAULT_INBOUND_ANOMALY_THRESHOLD,
            "family_scores": family_scores,
            "classification_method": "crs_anomaly_scoring_v1",
        }

    # Tie-break: anomaly score -> max severity -> number of matched rules.
    def family_score(family_name):
        return (
            family_scores[family_name],
            family_max_severity[family_name],
            len(family_matches[family_name]),
        )

    primary_family = max(candidate_families, key=family_score)
    family_info = ATTACK_FAMILIES.get(primary_family, ATTACK_FAMILIES["others"])

    # Get matched rules for primary family
    matched_rules = [m["rule_id"] for m in family_matches[primary_family]]

    # Note: variants 매핑은 불완전하여 family 수준에서만 분류
    # variants 기능이 필요하면 get_variant_by_crs_rule() 매핑 보완 필요

    return {
        "family": primary_family,
        "matched_rules": matched_rules[:10],  # Limit to 10 rules
        "capec_id": family_info.capec_id,
        "cwe_id": family_info.cwe_id,
        "anomaly_score": family_scores[primary_family],
        "classification_threshold": DEFAULT_INBOUND_ANOMALY_THRESHOLD,
        "family_scores": family_scores,
        "classification_method": "crs_anomaly_scoring_v1",
    }


if __name__ == "__main__":
    # Test patterns
    test_cases = [
        # SQL Injection
        ("' OR '1'='1", "sqli"),
        ("UNION SELECT * FROM users", "sqli"),
        # XSS
        ("<script>alert(1)</script>", "xss"),
        ("onerror=alert(1)", "xss"),
        # Command Injection
        ("; cat /etc/passwd", "cmdi"),
        ("| id", "cmdi"),
        # Path Traversal
        ("../../etc/passwd", "path_traversal"),
        ("%2e%2e%2fetc/passwd", "path_traversal"),
        # SSRF
        ("http://127.0.0.1:8080", "ssrf"),
        ("169.254.169.254", "ssrf"),
        # Info Disclosure
        ("nikto", "others"),
        ("/.git/config", "info_disclosure"),
        ("/.env", "info_disclosure"),
        # Deserialization
        ("rO0ABXNy", "deserialization"),
        # IDOR (new)
        ("/api/users/123", "idor"),
        ("/api/v1/order/456", "idor"),
        ("?user_id=789", "idor"),
        ("/users/1/orders", "idor"),
        ("/admin/users/999", "idor"),
        # CSRF (new)
        ("POST /api/transfer", "csrf"),
        ("POST /api/v1/delete", "csrf"),
        ("PUT /api/password", "csrf"),
        ("POST /admin/config", "csrf"),
        ("csrf_token=bypass", "csrf"),
        # Auth Bypass (extended)
        ("admin:admin", "auth_bypass"),
        ('"alg": "none"', "auth_bypass"),
        ("admin=true", "auth_bypass"),
        ("role=admin", "auth_bypass"),
        ("/admin/dashboard", "auth_bypass"),
        ("X-Original-URL: /admin", "auth_bypass"),
        # File Upload (extended)
        ("Content-Disposition: filename=shell.php", "file_upload"),
        ("filename=test.php.jpg", "file_upload"),
        ("<?php system($_GET['cmd']);", "file_upload"),
    ]

    print("CRS Pattern Tests")
    print("=" * 60)

    passed = 0
    failed = 0
    for text, expected in test_cases:
        result = classify_text(text)
        status = "PASS" if result["family"] == expected else "FAIL"
        if result["family"] == expected:
            passed += 1
        else:
            failed += 1
        print(f"[{status}] '{text[:45]:<45}' -> {result['family']:<18} (expected: {expected})")
        if result["matched_rules"] and result["family"] != expected:
            print(f"  Rules: {result['matched_rules'][:3]}")

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {len(test_cases)} total")

    # Print pattern counts
    print("\nPattern Counts by Family:")
    print("-" * 40)
    for family, patterns in ALL_PATTERNS.items():
        print(f"  {family:<20} {len(patterns):>3} patterns")
