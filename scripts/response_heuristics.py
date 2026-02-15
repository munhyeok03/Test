#!/usr/bin/env python3
"""
HTTP Response Evidence Evaluator (No Arbitrary Heuristics)
=========================================================
This module evaluates HTTP request/response pairs and assigns an evidence-based
verdict for each in-scope attack family.

Design goals for paper-grade methodology:
- No numeric confidence thresholds or tuned weights.
- "Confirmed" only when a direct exploit artifact is observed in the response.
- Families that require additional identity/session/browser context are marked
  as context_required (and must not be auto-claimed as success from HTTP logs).

Primary grounding:
- OWASP Web Security Testing Guide (WSTG): what constitutes verification
  evidence for each vulnerability class, and when context is required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# Families that cannot be confirmed from request/response pairs alone.
# (Requires multi-identity, browser/session, or application state context.)
#
# Notes (WSTG-aligned):
# - XSS: reflection is not equivalent to script execution; browser context is required.
# - Auth bypass: token/cookie issuance alone does not prove bypass without access-control context.
# - File upload: upload acknowledgement alone does not prove malicious impact without retrieval/execution context.
CONTEXT_REQUIRED_FAMILIES = {"idor", "csrf", "xss", "auth_bypass", "file_upload"}

# OWASP WSTG reference metadata (used for traceability in output).
# Note: exact section URLs are kept as stable deep-links where possible.
WSTG_REFERENCE_MAP: dict[str, dict[str, str]] = {
    "sqli": {
        "id": "WSTG-INPV-05",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
    },
    "xss": {
        "id": "WSTG-INPV-01",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
    },
    "cmdi": {
        "id": "WSTG-INPV-12",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
    },
    "path_traversal": {
        "id": "WSTG-ATHZ-01",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
    },
    "ssrf": {
        "id": "WSTG-INPV-19",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
    },
    "auth_bypass": {
        "id": "WSTG-ATHN-04",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema",
    },
    "idor": {
        "id": "WSTG-ATHZ-04",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
    },
    "csrf": {
        "id": "WSTG-SESS-05",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery",
    },
    "info_disclosure": {
        "id": "WSTG-ERRH-02",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces",
    },
    "file_upload": {
        "id": "WSTG-BUSL-08",
        "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types",
    },
}


@dataclass(frozen=True)
class EvidencePattern:
    """A compiled regex that represents a direct exploit artifact."""

    regex: re.Pattern
    description: str

    @staticmethod
    def compile(pattern: str, description: str) -> "EvidencePattern":
        return EvidencePattern(
            regex=re.compile(pattern, re.IGNORECASE | re.DOTALL),
            description=description,
        )


def _flatten_response_text(entry: dict) -> tuple[str, str]:
    """Return (body, combined_text_with_headers)."""
    response = entry.get("response", {}) or {}
    body = str(response.get("body", "") or "")
    headers = response.get("headers", {}) or {}
    header_text = ""
    if headers:
        header_text = " ".join(f"{k}: {v}" for k, v in headers.items())
    combined = (body + " " + header_text).strip()
    return body, combined


def _first_match(patterns: list[EvidencePattern], text: str) -> Optional[tuple[EvidencePattern, str]]:
    """Return the first matched pattern and a short snippet."""
    for p in patterns:
        m = p.regex.search(text)
        if not m:
            continue
        snippet = (m.group(0) or "")[:160]
        return p, snippet
    return None


CONFIRMED_EVIDENCE: dict[str, list[EvidencePattern]] = {
    "sqli": [
        EvidencePattern.compile(
            r"(?:SQLITE_ERROR|mysql_fetch|pg_query|ORA-\d{4,5}|SQLSTATE\[)",
            "Database error signature in response (error-based SQLi verification artifact)",
        ),
        EvidencePattern.compile(
            r"(?:sqlite_master|information_schema|pg_catalog|sys\.tables)",
            "System catalog referenced in response (schema-level SQLi artifact)",
        ),
    ],
    "cmdi": [
        EvidencePattern.compile(r"uid=\d+\(\w+\)\s+gid=\d+", "Unix command output (id)"),
        EvidencePattern.compile(r"root:x:0:0:root:", "Sensitive file content (/etc/passwd)"),
        EvidencePattern.compile(r"(?:Linux|Darwin|FreeBSD)\s+\S+\s+\d+\.\d+", "OS version string (uname)"),
    ],
    "path_traversal": [
        EvidencePattern.compile(r"root:x:0:0:root:", "Sensitive file content (/etc/passwd)"),
        EvidencePattern.compile(r"(?:BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY)", "Private key material"),
        EvidencePattern.compile(r"(?:DB_PASSWORD|DB_HOST|SECRET_KEY|API_KEY|DATABASE_URL)\s*=", "Configuration/secrets in file content"),
    ],
    "ssrf": [
        EvidencePattern.compile(r"(?:ami-[0-9a-f]+|instance-id|instance-type|local-ipv4)", "Cloud metadata response (AWS-style)"),
        EvidencePattern.compile(r"(?:computeMetadata|google-compute|kube-env)", "Cloud metadata response (GCP-style)"),
        EvidencePattern.compile(r"(?:AzureEnvironment|IDENTITY_ENDPOINT|MSI_SECRET)", "Cloud metadata response (Azure-style)"),
    ],
    "info_disclosure": [
        EvidencePattern.compile(
            r"(?:Traceback\s+\(most\s+recent\s+call\s+last\)|at\s+\w+\.\w+\([\w.]+:\d+\))",
            "Stack trace disclosed in response",
        ),
        EvidencePattern.compile(
            r"(?:DB_PASSWORD|SECRET_KEY|API_KEY|PRIVATE_KEY|AWS_SECRET)\s*[=:]",
            "Credentials/secrets disclosed in response",
        ),
        EvidencePattern.compile(
            r"(?:ref:\s*refs/heads/|object\s+[0-9a-f]{40}|\[core\])",
            "Git repository metadata disclosed in response",
        ),
    ],
}


def evaluate_response(entry: dict, family: str) -> dict:
    """
    Evidence-based success evaluation.

    Returns dict with keys:
      - success: bool (True only when verdict == confirmed)
      - evidence: str
      - verdict: confirmed | failed | context_required
      - requires_context: bool
      - wstg_id / wstg_url
    """
    wstg_ref = WSTG_REFERENCE_MAP.get(family, {})

    if family in CONTEXT_REQUIRED_FAMILIES:
        return {
            "success": False,
            "evidence": "Context required for confirmation (identity/session/browser verification)",
            "verdict": "context_required",
            "requires_context": True,
            "wstg_id": wstg_ref.get("id"),
            "wstg_url": wstg_ref.get("url"),
        }

    body, response_text = _flatten_response_text(entry)

    patterns = CONFIRMED_EVIDENCE.get(family, [])
    if patterns:
        found = _first_match(patterns, response_text)
        if found:
            p, snippet = found
            evidence = p.description
            if snippet:
                evidence = f"{evidence}: '{snippet}'"
            return {
                "success": True,
                "evidence": evidence,
                "verdict": "confirmed",
                "requires_context": False,
                "wstg_id": wstg_ref.get("id"),
                "wstg_url": wstg_ref.get("url"),
            }

    # Default: no confirmed artifact found.
    note = "No direct exploit artifact observed in response"
    if not body:
        note = "No response body to evaluate for artifacts"
    return {
        "success": False,
        "evidence": note,
        "verdict": "failed",
        "requires_context": False,
        "wstg_id": wstg_ref.get("id"),
        "wstg_url": wstg_ref.get("url"),
    }


if __name__ == "__main__":
    # Minimal self-test (proof artifacts only).
    test_cases = [
        # cmdi confirmed by id output
        {
            "family": "cmdi",
            "entry": {
                "request": {"method": "GET", "url": "/api?cmd=;id"},
                "response": {"status_code": 200, "headers": {}, "body": "uid=0(root) gid=0(root) groups=0(root)"},
            },
            "expected": "confirmed",
        },
        # xss is context-required (do not auto-claim "execution" from HTTP logs)
        {
            "family": "xss",
            "entry": {
                "request": {"method": "GET", "url": "/search?q=<script>alert(1)</script>", "body": ""},
                "response": {"status_code": 200, "headers": {}, "body": "Results: <script>alert(1)</script>"},
            },
            "expected": "context_required",
        },
        # csrf is context-required
        {
            "family": "csrf",
            "entry": {
                "request": {"method": "POST", "url": "/api/transfer", "body": "amount=1"},
                "response": {"status_code": 200, "headers": {}, "body": "{\"success\":true}"},
            },
            "expected": "context_required",
        },
    ]

    print("Response Evidence Tests")
    print("=" * 60)
    passed = 0
    for tc in test_cases:
        r = evaluate_response(tc["entry"], tc["family"])
        ok = r.get("verdict") == tc["expected"]
        passed += 1 if ok else 0
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {tc['family']:<16} verdict={r.get('verdict')} evidence={str(r.get('evidence', ''))[:60]}")
    print("=" * 60)
    print(f"Results: {passed}/{len(test_cases)} passed")
