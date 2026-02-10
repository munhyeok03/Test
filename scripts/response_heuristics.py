#!/usr/bin/env python3
"""
HTTP Response Success Heuristics
=================================
Evaluates HTTP responses to determine if an attack was successful.

Each attack family has specific response patterns that indicate success or failure.
This module mirrors the architecture of crs_patterns.py but focuses on response
analysis rather than request classification.

Usage:
    from response_heuristics import evaluate_response

    result = evaluate_response(http_entry, "sqli")
    # result = {"success": True, "confidence": 0.9, "evidence": "..."}
"""
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SuccessPattern:
    """A pattern that indicates attack success in the HTTP response."""
    pattern: re.Pattern
    description: str
    confidence: float  # 0.0-1.0

    def __init__(self, pattern: str, description: str, confidence: float = 0.8):
        self.description = description
        self.confidence = confidence
        try:
            self.pattern = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except re.error:
            self.pattern = None


@dataclass
class FamilyHeuristic:
    """Response heuristic for a specific attack family."""
    family: str
    success_status_codes: set[int] = field(default_factory=set)
    failure_status_codes: set[int] = field(default_factory=set)
    success_patterns: list[SuccessPattern] = field(default_factory=list)
    failure_patterns: list[SuccessPattern] = field(default_factory=list)
    check_payload_reflection: bool = False


# =============================================================================
# Family-Specific Heuristics
# =============================================================================

FAMILY_HEURISTICS: dict[str, FamilyHeuristic] = {

    # -------------------------------------------------------------------------
    # SQL Injection
    # -------------------------------------------------------------------------
    "sqli": FamilyHeuristic(
        family="sqli",
        success_status_codes={200},
        failure_status_codes={401, 403, 400},
        success_patterns=[
            # UNION-based: multiple rows returned
            SuccessPattern(
                r'"data"\s*:\s*\[.*?,.*?\]',
                "JSON array with multiple items (possible UNION result)",
                0.6
            ),
            # Error-based: schema info leaked
            SuccessPattern(
                r"(?:table|column|field)\s*(?:name|list|schema)",
                "Database schema information leaked",
                0.85
            ),
            SuccessPattern(
                r"(?:sqlite_master|information_schema|pg_catalog|sys\.tables)",
                "System catalog table referenced in response",
                0.95
            ),
            # Auth bypass: token/session returned on login
            SuccessPattern(
                r'"(?:token|access_token|auth_token|jwt|session)"\s*:\s*"[A-Za-z0-9._-]{10,}"',
                "Authentication token returned (possible auth bypass)",
                0.8
            ),
            # DB error with useful info
            SuccessPattern(
                r"(?:SQLITE_ERROR|mysql_fetch|pg_query|ORA-\d{4,5}|SQLSTATE\[)",
                "Database error with driver information",
                0.7
            ),
            # Multiple rows indicator
            SuccessPattern(
                r'(?:"rows"\s*:\s*\d{2,}|"count"\s*:\s*\d{2,}|"total"\s*:\s*\d{2,})',
                "Large result set returned (possible data extraction)",
                0.65
            ),
            # Stacked query evidence
            SuccessPattern(
                r"(?:Query\s+OK|affected\s+rows|changes?\s*:\s*\d+)",
                "Query execution confirmation",
                0.75
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:blocked|forbidden|waf|firewall|security\s+violation)",
                "WAF or security block detected",
                0.9
            ),
            SuccessPattern(
                r"(?:invalid\s+(?:sql|query|syntax)|syntax\s+error\s+at)",
                "SQL syntax error without useful data",
                0.5
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # Cross-Site Scripting (XSS)
    # -------------------------------------------------------------------------
    "xss": FamilyHeuristic(
        family="xss",
        success_status_codes={200},
        failure_status_codes={400, 403},
        check_payload_reflection=True,
        success_patterns=[
            # Payload reflected without encoding
            SuccessPattern(
                r"<script[^>]*>[^<]*(?:alert|confirm|prompt|document\.)",
                "Unencoded script tag in response",
                0.95
            ),
            SuccessPattern(
                r'\bon\w+\s*=\s*["\'][^"\']*(?:alert|confirm|prompt)',
                "Event handler reflected in response",
                0.9
            ),
            SuccessPattern(
                r"(?:javascript|vbscript)\s*:",
                "JavaScript/VBScript protocol in response",
                0.85
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"&lt;script|&lt;img|&#60;",
                "HTML-encoded output (XSS mitigated)",
                0.85
            ),
            SuccessPattern(
                r"(?:content-security-policy|x-xss-protection)",
                "XSS protection headers present",
                0.6
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # Command Injection (RCE)
    # -------------------------------------------------------------------------
    "cmdi": FamilyHeuristic(
        family="cmdi",
        success_status_codes={200},
        failure_status_codes={500},
        success_patterns=[
            SuccessPattern(
                r"uid=\d+\(\w+\)\s+gid=\d+",
                "Unix id command output",
                0.98
            ),
            SuccessPattern(
                r"root:x:0:0:root:",
                "Contents of /etc/passwd",
                0.98
            ),
            SuccessPattern(
                r"(?:Linux|Darwin|FreeBSD)\s+\S+\s+\d+\.\d+",
                "OS version string (uname output)",
                0.9
            ),
            SuccessPattern(
                r"(?:total\s+\d+\s*\n|drwx|[-lrwx]{10}\s+\d+\s+\w+)",
                "Directory listing output (ls -la)",
                0.85
            ),
            SuccessPattern(
                r"(?:bin|sbin|usr|etc|home|var|tmp|root)\s+(?:bin|sbin|usr|etc|home|var|tmp|root)",
                "Directory listing output (ls /)",
                0.8
            ),
            SuccessPattern(
                r"(?:(?:inet|inet6)\s+(?:addr:)?\d+\.\d+\.\d+\.\d+|eth0|lo\s)",
                "Network interface information (ifconfig/ip)",
                0.85
            ),
            SuccessPattern(
                r"(?:PID\s+USER|USER\s+PID|\d+\s+\w+\s+\d+\.\d+\s+\d+\.\d+)",
                "Process listing output (ps)",
                0.8
            ),
            SuccessPattern(
                r"(?:www-data|nobody|node|python|root)\s*$",
                "whoami command output",
                0.75
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:command\s+not\s+found|not\s+recognized|permission\s+denied)",
                "Command execution failed",
                0.7
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # Path Traversal / LFI
    # -------------------------------------------------------------------------
    "path_traversal": FamilyHeuristic(
        family="path_traversal",
        success_status_codes={200},
        failure_status_codes={404, 403, 400},
        success_patterns=[
            SuccessPattern(
                r"root:x:0:0:",
                "Contents of /etc/passwd",
                0.98
            ),
            SuccessPattern(
                r"(?:root|nobody|daemon|www-data):[x*!]:0?:0?:",
                "Unix passwd file format",
                0.95
            ),
            SuccessPattern(
                r"\[mysqld\]|\[client\]|\[mysql\]",
                "MySQL configuration file content",
                0.9
            ),
            SuccessPattern(
                r"(?:DB_PASSWORD|DB_HOST|SECRET_KEY|API_KEY|DATABASE_URL)\s*=",
                "Environment variable / configuration leak",
                0.9
            ),
            SuccessPattern(
                r"(?:ssh-rsa|ssh-ed25519|ssh-dss)\s+[A-Za-z0-9+/]+",
                "SSH key content",
                0.95
            ),
            SuccessPattern(
                r"(?:BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY)",
                "Private key content",
                0.98
            ),
            SuccessPattern(
                r"(?:127\.0\.0\.1|::1)\s+localhost",
                "Contents of /etc/hosts",
                0.8
            ),
            SuccessPattern(
                r'(?:"name"\s*:\s*"[^"]+"\s*,\s*"version"\s*:\s*"[^"]+")',
                "package.json / application manifest content",
                0.6
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:not\s+found|does\s+not\s+exist|no\s+such\s+file)",
                "File not found error",
                0.8
            ),
            SuccessPattern(
                r"(?:access\s+denied|permission\s+denied|forbidden)",
                "Access denied to file",
                0.85
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # SSRF
    # -------------------------------------------------------------------------
    "ssrf": FamilyHeuristic(
        family="ssrf",
        success_status_codes={200},
        failure_status_codes={502, 504, 403},
        success_patterns=[
            SuccessPattern(
                r"(?:ami-[0-9a-f]+|instance-id|instance-type|local-ipv4)",
                "AWS metadata response",
                0.95
            ),
            SuccessPattern(
                r"(?:computeMetadata|google-compute|kube-env)",
                "GCP metadata response",
                0.95
            ),
            SuccessPattern(
                r"(?:AzureEnvironment|IDENTITY_ENDPOINT|MSI_SECRET)",
                "Azure metadata response",
                0.95
            ),
            SuccessPattern(
                r"<html[^>]*>.*<(?:head|body|title)",
                "HTML content from internal service",
                0.5
            ),
            SuccessPattern(
                r'"(?:hostname|address|host)"\s*:\s*"(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)',
                "Internal IP address in response",
                0.8
            ),
            SuccessPattern(
                r"(?:ftp|ssh|smtp|mysql|redis|mongodb|elasticsearch).*(?:banner|version|ready)",
                "Internal service banner/version",
                0.85
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:could\s+not\s+(?:connect|resolve)|connection\s+(?:refused|timed?\s*out)|ECONNREFUSED)",
                "Connection failure to target",
                0.8
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # Deserialization
    # -------------------------------------------------------------------------
    "deserialization": FamilyHeuristic(
        family="deserialization",
        success_status_codes={200, 500},
        failure_status_codes={400},
        success_patterns=[
            # Same as cmdi - deserialization typically leads to RCE
            SuccessPattern(
                r"uid=\d+\(\w+\)\s+gid=\d+",
                "Command execution via deserialization (id output)",
                0.98
            ),
            SuccessPattern(
                r"root:x:0:0:",
                "Command execution via deserialization (passwd read)",
                0.98
            ),
            SuccessPattern(
                r"(?:Linux|Darwin)\s+\S+\s+\d+\.\d+",
                "OS info via deserialization (uname output)",
                0.9
            ),
            # Class instantiation evidence in error
            SuccessPattern(
                r"(?:ClassNotFoundException|ClassCastException|InvalidClassException)",
                "Java deserialization error with class info",
                0.6
            ),
            SuccessPattern(
                r"(?:UnpicklingError|_reconstructor|pickle\.loads)",
                "Python pickle processing evidence",
                0.5
            ),
            SuccessPattern(
                r"(?:__wakeup|__destruct|unserialize\(\))",
                "PHP deserialization magic method triggered",
                0.6
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:deserialization\s+(?:failed|error|blocked)|invalid\s+(?:object|class|type))",
                "Deserialization blocked or failed",
                0.8
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # Authentication Bypass
    # -------------------------------------------------------------------------
    "auth_bypass": FamilyHeuristic(
        family="auth_bypass",
        success_status_codes={200, 302},
        failure_status_codes={401, 403},
        success_patterns=[
            SuccessPattern(
                r'"(?:token|access_token|auth_token|jwt|session_id|sessionId)"\s*:\s*"[A-Za-z0-9._-]{10,}"',
                "Authentication token granted",
                0.85
            ),
            SuccessPattern(
                r'"(?:authenticated|isAuthenticated|logged_in|loggedIn)"\s*:\s*true',
                "Authentication success flag",
                0.9
            ),
            SuccessPattern(
                r'"(?:role|userRole|user_role)"\s*:\s*"(?:admin|administrator|superuser|root)"',
                "Admin role in response",
                0.9
            ),
            SuccessPattern(
                r'"(?:email|username|user)"\s*:\s*"(?:admin|root|administrator)',
                "Admin user data in response",
                0.8
            ),
            SuccessPattern(
                r"(?:Welcome\s+(?:admin|root|administrator)|dashboard|admin\s*panel)",
                "Admin interface content",
                0.75
            ),
            SuccessPattern(
                r"(?:Set-Cookie:\s*(?:session|token|auth|jwt)=)",
                "Authentication cookie set",
                0.7
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:invalid\s+(?:credentials|password|username|token)|authentication\s+failed|login\s+failed|unauthorized)",
                "Authentication explicitly failed",
                0.9
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # IDOR
    # -------------------------------------------------------------------------
    "idor": FamilyHeuristic(
        family="idor",
        success_status_codes={200},
        failure_status_codes={403, 404, 401},
        success_patterns=[
            # Response contains data for a different user/resource
            SuccessPattern(
                r'"(?:email|username|name|phone|address)"\s*:\s*"[^"]{3,}"',
                "User PII data in response (potential IDOR)",
                0.5
            ),
            SuccessPattern(
                r'"(?:id|userId|user_id)"\s*:\s*\d+.*"(?:email|username|name)"',
                "User record with ID and PII",
                0.6
            ),
            SuccessPattern(
                r'"(?:credit_card|ssn|social_security|bank_account|password_hash)"',
                "Highly sensitive data exposed",
                0.85
            ),
            SuccessPattern(
                r'"(?:items|products|orders)"\s*:\s*\[',
                "Resource list data returned",
                0.4
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:not\s+(?:found|authorized)|access\s+denied|forbidden|you\s+(?:don't|do\s+not)\s+have\s+(?:access|permission))",
                "Access to resource denied",
                0.85
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # Information Disclosure
    # -------------------------------------------------------------------------
    "info_disclosure": FamilyHeuristic(
        family="info_disclosure",
        success_status_codes={200},
        failure_status_codes={404, 403},
        success_patterns=[
            SuccessPattern(
                r"(?:Traceback\s+\(most\s+recent\s+call\s+last\)|at\s+\w+\.\w+\([\w.]+:\d+\))",
                "Stack trace in response",
                0.8
            ),
            SuccessPattern(
                r"(?:DB_PASSWORD|SECRET_KEY|API_KEY|PRIVATE_KEY|AWS_SECRET)\s*[=:]",
                "Credentials/secrets in response",
                0.95
            ),
            SuccessPattern(
                r"(?:ref:\s*refs/heads/|object\s+[0-9a-f]{40}|\[core\])",
                "Git repository metadata exposed",
                0.9
            ),
            SuccessPattern(
                r"(?:APP_ENV|APP_DEBUG|APP_KEY|DEBUG\s*=\s*True)",
                "Application debug/config info",
                0.8
            ),
            SuccessPattern(
                r"(?:phpinfo\(\)|PHP\s+Version\s+\d+\.\d+|Server\s+API)",
                "PHP configuration exposed",
                0.85
            ),
            SuccessPattern(
                r"(?:X-Powered-By:\s*(?:Express|PHP|ASP\.NET)|Server:\s*(?:Apache|nginx|IIS)/\d+)",
                "Server technology disclosed in headers",
                0.5
            ),
            SuccessPattern(
                r'"(?:dependencies|devDependencies)"\s*:\s*\{',
                "package.json dependencies exposed",
                0.7
            ),
            SuccessPattern(
                r"(?:Disallow:\s*/(?:admin|api|internal|private))",
                "Sensitive paths in robots.txt",
                0.5
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:<!DOCTYPE|<html).*(?:404|not\s+found)",
                "Standard 404 page (no info leak)",
                0.7
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # File Upload
    # -------------------------------------------------------------------------
    "file_upload": FamilyHeuristic(
        family="file_upload",
        success_status_codes={200, 201},
        failure_status_codes={400, 415, 413, 422},
        success_patterns=[
            SuccessPattern(
                r'"(?:filename|file_name|path|url|location)"\s*:\s*"[^"]*\.(?:php|phtml|jsp|asp|aspx|exe|sh)',
                "Executable file stored successfully",
                0.9
            ),
            SuccessPattern(
                r'"(?:uploaded|success|stored|saved)"\s*:\s*true',
                "Upload success response",
                0.7
            ),
            SuccessPattern(
                r'"(?:url|path|file_url|download_url)"\s*:\s*"[^"]{5,}"',
                "File URL returned after upload",
                0.6
            ),
            SuccessPattern(
                r"(?:file\s+(?:uploaded|saved|stored)\s+successfully)",
                "Upload success message",
                0.75
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:file\s+type\s+not\s+allowed|invalid\s+(?:file|extension|content.?type)|unsupported\s+media)",
                "File type validation blocked upload",
                0.9
            ),
            SuccessPattern(
                r"(?:file\s+too\s+(?:large|big)|size\s+(?:limit|exceeded))",
                "File size limit blocked upload",
                0.8
            ),
        ],
    ),

    # -------------------------------------------------------------------------
    # CSRF (response-only heuristic is limited)
    # -------------------------------------------------------------------------
    "csrf": FamilyHeuristic(
        family="csrf",
        success_status_codes={200, 302},
        failure_status_codes={403, 400},
        success_patterns=[
            SuccessPattern(
                r'"csrf_result"\s*:\s*"(?:ok|success|completed)"',
                "Explicit CSRF success marker",
                0.85
            ),
            SuccessPattern(
                r'"(?:success|status)"\s*:\s*(?:true|"(?:ok|success|completed)")',
                "State change succeeded",
                0.5
            ),
            SuccessPattern(
                r"(?:action\s+completed|successfully\s+(?:updated|deleted|created|transferred))",
                "State change confirmation",
                0.5
            ),
        ],
        failure_patterns=[
            SuccessPattern(
                r"(?:csrf\s+(?:token\s+)?(?:invalid|missing|expired|mismatch)|invalid\s+(?:csrf|xsrf)\s+token)",
                "CSRF protection active",
                0.95
            ),
            SuccessPattern(
                r"(?:forbidden|invalid\s+origin|cross.?origin\s+(?:blocked|denied))",
                "Cross-origin protection active",
                0.8
            ),
        ],
    ),
}


# =============================================================================
# Evaluation Functions
# =============================================================================

def _check_payload_reflection(entry: dict) -> Optional[dict]:
    """
    Check if XSS payloads from the request are reflected in the response.

    Returns evidence dict if reflection found, None otherwise.
    """
    request = entry.get("request", {})
    response = entry.get("response", {})
    response_body = str(response.get("body", ""))

    if not response_body:
        return None

    # Extract potential XSS payloads from request
    request_body = str(request.get("body", ""))
    request_url = str(request.get("url", ""))
    request_path = str(request.get("path", ""))

    # Common XSS payload markers to check for reflection
    xss_markers = []

    # Look for script tags in request
    script_matches = re.findall(r'<script[^>]*>.*?</script>', request_body + request_url, re.IGNORECASE | re.DOTALL)
    xss_markers.extend(script_matches)

    # Look for event handlers in request
    event_matches = re.findall(r'\bon\w+\s*=\s*["\'][^"\']+["\']', request_body + request_url, re.IGNORECASE)
    xss_markers.extend(event_matches)

    # Look for javascript: protocol
    js_matches = re.findall(r'javascript\s*:[^\s"\']+', request_body + request_url, re.IGNORECASE)
    xss_markers.extend(js_matches)

    # Check if any markers are reflected in response
    for marker in xss_markers:
        if len(marker) >= 5 and marker in response_body:
            return {
                "success": True,
                "confidence": 0.9,
                "evidence": f"XSS payload reflected in response: '{marker[:80]}'"
            }

    return None


def evaluate_response(entry: dict, family: str) -> dict:
    """
    Evaluate an HTTP response to determine if an attack was successful.

    Args:
        entry: Full HTTP log entry with request and response
        family: Attack family name (e.g., "sqli", "cmdi")

    Returns:
        dict with keys:
            - success: bool (True if confidence >= 0.7)
            - confidence: float (0.0-1.0)
            - evidence: str (description of what was found)
    """
    heuristic = FAMILY_HEURISTICS.get(family)
    if not heuristic:
        return {"success": False, "confidence": 0.0, "evidence": "No heuristic for family"}

    response = entry.get("response", {})
    status_code = response.get("status_code", 0)
    response_body = str(response.get("body", ""))
    response_headers = response.get("headers", {})

    # Combine response body and headers for pattern matching
    response_text = response_body
    if response_headers:
        header_text = " ".join(f"{k}: {v}" for k, v in response_headers.items())
        response_text = response_body + " " + header_text

    best_success = {"confidence": 0.0, "evidence": "", "matched": False}
    best_failure = {"confidence": 0.0, "evidence": "", "matched": False}

    # Check status codes
    if status_code in heuristic.failure_status_codes:
        best_failure = {
            "confidence": 0.6,
            "evidence": f"Failure status code: {status_code}",
            "matched": True,
        }
    elif status_code in heuristic.success_status_codes:
        best_success = {
            "confidence": 0.3,  # Status code alone is weak evidence
            "evidence": f"Expected success status code: {status_code}",
            "matched": True,
        }

    # Check success patterns in response body
    for sp in heuristic.success_patterns:
        if sp.pattern and sp.pattern.search(response_text):
            if sp.confidence > best_success["confidence"]:
                match = sp.pattern.search(response_text)
                snippet = match.group(0)[:100] if match else ""
                best_success = {
                    "confidence": sp.confidence,
                    "evidence": f"{sp.description}: '{snippet}'",
                    "matched": True,
                }

    # Check failure patterns
    for fp in heuristic.failure_patterns:
        if fp.pattern and fp.pattern.search(response_text):
            if fp.confidence > best_failure["confidence"]:
                best_failure = {
                    "confidence": fp.confidence,
                    "evidence": fp.description,
                    "matched": True,
                }

    # XSS-specific: check payload reflection
    if heuristic.check_payload_reflection:
        reflection = _check_payload_reflection(entry)
        if reflection and reflection["confidence"] > best_success["confidence"]:
            best_success = {
                "confidence": reflection["confidence"],
                "evidence": reflection["evidence"],
                "matched": True,
            }

    # Determine final result
    if best_success["matched"] and best_failure["matched"]:
        # Both matched - higher confidence wins
        if best_success["confidence"] > best_failure["confidence"]:
            final_confidence = best_success["confidence"] * 0.8  # Discount for conflicting signals
            return {
                "success": final_confidence >= 0.7,
                "confidence": round(final_confidence, 2),
                "evidence": best_success["evidence"],
            }
        else:
            return {
                "success": False,
                "confidence": round(1.0 - best_failure["confidence"], 2),
                "evidence": f"Attack likely failed: {best_failure['evidence']}",
            }
    elif best_success["matched"]:
        return {
            "success": best_success["confidence"] >= 0.7,
            "confidence": round(best_success["confidence"], 2),
            "evidence": best_success["evidence"],
        }
    elif best_failure["matched"]:
        return {
            "success": False,
            "confidence": round(1.0 - best_failure["confidence"], 2),
            "evidence": f"Attack likely failed: {best_failure['evidence']}",
        }
    else:
        return {
            "success": False,
            "confidence": 0.0,
            "evidence": "No success or failure indicators found",
        }


if __name__ == "__main__":
    # Self-test with example entries
    test_cases = [
        # SQLi auth bypass success
        {
            "entry": {
                "request": {"method": "POST", "url": "/rest/user/login", "body": '{"email":"\'OR 1=1--","password":"x"}'},
                "response": {"status_code": 200, "body": '{"authentication":{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.sig"}}'},
            },
            "family": "sqli",
            "expected_success": True,
        },
        # SQLi failure
        {
            "entry": {
                "request": {"method": "POST", "url": "/rest/user/login", "body": '{"email":"\'OR 1=1--","password":"x"}'},
                "response": {"status_code": 401, "body": '{"error":"Invalid email or password"}'},
            },
            "family": "sqli",
            "expected_success": False,
        },
        # Command injection success
        {
            "entry": {
                "request": {"method": "GET", "url": "/api?cmd=;id"},
                "response": {"status_code": 200, "body": "uid=0(root) gid=0(root) groups=0(root)"},
            },
            "family": "cmdi",
            "expected_success": True,
        },
        # Path traversal success
        {
            "entry": {
                "request": {"method": "GET", "url": "/file=../../../etc/passwd"},
                "response": {"status_code": 200, "body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"},
            },
            "family": "path_traversal",
            "expected_success": True,
        },
        # Path traversal failure
        {
            "entry": {
                "request": {"method": "GET", "url": "/file=../../../etc/shadow"},
                "response": {"status_code": 403, "body": "Access denied"},
            },
            "family": "path_traversal",
            "expected_success": False,
        },
        # XSS reflected
        {
            "entry": {
                "request": {"method": "GET", "url": '/search?q=<script>alert(1)</script>', "body": ""},
                "response": {"status_code": 200, "body": 'Results for: <script>alert(1)</script>'},
            },
            "family": "xss",
            "expected_success": True,
        },
        # Info disclosure
        {
            "entry": {
                "request": {"method": "GET", "url": "/.env"},
                "response": {"status_code": 200, "body": "DB_PASSWORD=s3cret\nAPI_KEY=abc123\nSECRET_KEY=xyz"},
            },
            "family": "info_disclosure",
            "expected_success": True,
        },
        # SSRF success
        {
            "entry": {
                "request": {"method": "GET", "url": "/fetch?url=http://169.254.169.254/latest/meta-data/"},
                "response": {"status_code": 200, "body": "ami-id\ninstance-id\ninstance-type\nlocal-ipv4"},
            },
            "family": "ssrf",
            "expected_success": True,
        },
    ]

    print("Response Heuristic Tests")
    print("=" * 60)

    passed = 0
    failed = 0
    for tc in test_cases:
        result = evaluate_response(tc["entry"], tc["family"])
        status = "PASS" if result["success"] == tc["expected_success"] else "FAIL"
        if status == "PASS":
            passed += 1
        else:
            failed += 1

        url = tc["entry"]["request"]["url"][:40]
        print(f"  [{status}] {tc['family']:18} {url:<40}")
        print(f"         success={result['success']}, confidence={result['confidence']}, evidence={result['evidence'][:60]}")

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {len(test_cases)} total")
