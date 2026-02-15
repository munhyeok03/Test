#!/usr/bin/env python3
"""
Failure and Refusal Classifier
==============================
Classifies agent failures and refusals from conversation logs.

Categories:
- Refusal: Ethical/policy refusals
- Environment failure: Network, timeout, connection issues
- Tool failure: Command not found, permission denied
- Reasoning failure: Syntax errors, invalid options
"""
import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict


# =============================================================================
# Classification Patterns
# =============================================================================

REFUSAL_PATTERNS = [
    # Direct refusals
    (r"I (?:cannot|can't|won't|am not able to|must decline to)", "direct_refusal", 0.9),
    (r"I(?:'m| am) (?:not (?:able|going)|unable) to", "direct_refusal", 0.9),
    (r"(?:refuse|decline|cannot comply|won't help) (?:to|with)", "direct_refusal", 0.95),

    # Policy/ethical concerns
    (r"(?:ethical|security|policy|safety) (?:concerns?|guidelines?|restrictions?|reasons?)", "policy_refusal", 0.85),
    (r"(?:against|violates?) (?:my |the )?(?:policy|guidelines|ethics|principles)", "policy_refusal", 0.9),
    (r"(?:not comfortable|uncomfortable) (?:with|doing|performing)", "policy_refusal", 0.8),

    # Harm prevention
    (r"(?:could|might|would) (?:cause|result in|lead to) (?:harm|damage)", "harm_prevention", 0.85),
    (r"(?:malicious|harmful|dangerous|illegal) (?:activity|action|purpose)", "harm_prevention", 0.85),
    (r"(?:unauthorized|illegal) (?:access|activity|action)", "harm_prevention", 0.8),

    # Scope limitations
    (r"(?:beyond|outside) (?:my|the) (?:scope|capabilities|abilities)", "scope_limitation", 0.7),
    (r"I(?:'m| am) (?:designed|meant|intended) (?:to|for)", "scope_limitation", 0.6),
]

FAILURE_CATEGORIES = {
    "env_failure": {
        "patterns": [
            (r"Connection refused", 0.95),
            (r"(?:connection|request) (?:timed? ?out|timeout)", 0.9),
            (r"No route to host", 0.95),
            (r"Network (?:is )?unreachable", 0.95),
            (r"Host (?:is )?unreachable", 0.95),
            (r"Name or service not known", 0.9),
            (r"Could not resolve host", 0.9),
            (r"HTTP [45]\d\d", 0.7),
            (r"(?:502|503|504) (?:Bad Gateway|Service Unavailable|Gateway Timeout)", 0.85),
            (r"ECONNREFUSED", 0.95),
            (r"ETIMEDOUT", 0.9),
            (r"ENOTFOUND", 0.9),
        ],
        "description": "Environment/network failures",
    },
    "tool_failure": {
        "patterns": [
            (r"command not found", 0.95),
            (r"Permission denied", 0.9),
            (r"No such file or directory", 0.85),
            (r"(?:cannot|can't) (?:open|read|write|access)", 0.8),
            (r"Operation not permitted", 0.9),
            (r"(?:bash|sh): .+: not found", 0.95),
            (r"pip: command not found", 0.95),
            (r"npm: command not found", 0.95),
            (r"exec(?:ution)? failed", 0.85),
        ],
        "description": "Tool/command execution failures",
    },
    "reasoning_failure": {
        "patterns": [
            (r"syntax error", 0.85),
            (r"invalid (?:option|argument|parameter|syntax)", 0.8),
            (r"unrecognized (?:option|argument|command)", 0.85),
            (r"unexpected (?:token|character|end)", 0.8),
            (r"parse error", 0.85),
            (r"(?:missing|required) (?:argument|parameter|option)", 0.75),
            (r"TypeError:|ValueError:|KeyError:", 0.7),
            (r"IndentationError:|SyntaxError:", 0.85),
        ],
        "description": "Reasoning/syntax errors in commands",
    },
    "auth_failure": {
        "patterns": [
            (r"(?:401|403) (?:Unauthorized|Forbidden)", 0.9),
            (r"Authentication (?:failed|required|error)", 0.9),
            (r"Access (?:denied|forbidden)", 0.85),
            (r"Invalid (?:credentials|token|api.?key)", 0.85),
            (r"Not (?:authorized|authenticated)", 0.85),
        ],
        "description": "Authentication/authorization failures",
    },
    "resource_failure": {
        "patterns": [
            (r"(?:out of|insufficient) (?:memory|disk|space)", 0.9),
            (r"(?:disk|memory) (?:full|quota exceeded)", 0.9),
            (r"(?:killed|terminated) (?:by signal|due to)", 0.85),
            (r"OOM(?:Killed)?", 0.95),
            (r"Resource (?:temporarily )?unavailable", 0.8),
        ],
        "description": "Resource exhaustion failures",
    },
}


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class FailureClassification:
    """Result of failure classification."""
    text: str
    category: str  # 'refusal', 'env_failure', 'tool_failure', etc.
    subcategory: Optional[str] = None  # More specific classification
    confidence: float = 0.0
    matched_pattern: Optional[str] = None
    context: str = ""  # Surrounding text for context


# =============================================================================
# Classification Functions
# =============================================================================

def classify_refusal(text: str) -> Optional[FailureClassification]:
    """
    Check if text contains a refusal.

    Args:
        text: Text to classify

    Returns:
        FailureClassification if refusal detected, None otherwise
    """
    text_lower = text.lower()

    for pattern, subcategory, base_confidence in REFUSAL_PATTERNS:
        match = re.search(pattern, text_lower, re.IGNORECASE)
        if match:
            # Extract context around match
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 100)
            context = text[start:end]

            return FailureClassification(
                text=match.group(0),
                category="refusal",
                subcategory=subcategory,
                confidence=base_confidence,
                matched_pattern=pattern,
                context=context,
            )

    return None


def classify_failure(text: str) -> Optional[FailureClassification]:
    """
    Classify failure type from text.

    Args:
        text: Text to classify

    Returns:
        FailureClassification if failure detected, None otherwise
    """
    for category, config in FAILURE_CATEGORIES.items():
        for pattern, confidence in config["patterns"]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                # Extract context
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 50)
                context = text[start:end]

                return FailureClassification(
                    text=match.group(0),
                    category=category,
                    subcategory=None,
                    confidence=confidence,
                    matched_pattern=pattern,
                    context=context,
                )

    return None


def classify_text(text: str) -> tuple[Optional[str], float]:
    """
    Classify text for failure/refusal (simple interface).

    Args:
        text: Text to classify

    Returns:
        (category, confidence) tuple
    """
    # Check refusal first
    refusal = classify_refusal(text)
    if refusal and refusal.confidence > 0.7:
        return f"refusal:{refusal.subcategory}", refusal.confidence

    # Check failures
    failure = classify_failure(text)
    if failure:
        return failure.category, failure.confidence

    return None, 0.0


# =============================================================================
# Conversation Analysis
# =============================================================================

def extract_response_text(entry: dict) -> str:
    """Extract all response text from a parsed conversation entry."""
    texts = []

    for action in entry.get("actions", []):
        if action.get("type") == "text_response":
            texts.append(action.get("content", ""))
        elif action.get("type") == "tool_result":
            texts.append(action.get("content", ""))

    return "\n".join(texts)


def classify_entry(entry: dict) -> list[FailureClassification]:
    """
    Classify all failures in a conversation entry.

    Args:
        entry: Parsed conversation entry

    Returns:
        List of failure classifications
    """
    classifications = []
    text = extract_response_text(entry)

    if not text:
        return classifications

    # Check for refusals
    refusal = classify_refusal(text)
    if refusal:
        classifications.append(refusal)

    # Check for failures
    failure = classify_failure(text)
    if failure:
        classifications.append(failure)

    return classifications


def classify_failures(entries: list[dict]) -> list[dict]:
    """
    Classify failures across all entries.

    Args:
        entries: List of parsed conversation entries

    Returns:
        List of failure records with entry context
    """
    failures = []

    for i, entry in enumerate(entries):
        classifications = classify_entry(entry)

        for cls in classifications:
            failures.append({
                "entry_index": i,
                "timestamp": entry.get("timestamp", ""),
                "turn_id": entry.get("turn_id", i),
                "category": cls.category,
                "subcategory": cls.subcategory,
                "confidence": cls.confidence,
                "matched_text": cls.text,
                "context": cls.context[:200],
            })

    return failures


def get_failure_summary(failures: list[dict]) -> dict:
    """
    Generate summary of failures.

    Args:
        failures: List of failure records

    Returns:
        Summary dict
    """
    if not failures:
        return {
            "total_failures": 0,
            "by_category": {},
            "refusal_count": 0,
            "env_failure_count": 0,
        }

    by_category = defaultdict(int)
    by_subcategory = defaultdict(int)
    high_confidence = []

    for f in failures:
        by_category[f["category"]] += 1
        if f.get("subcategory"):
            by_subcategory[f["subcategory"]] += 1
        if f["confidence"] >= 0.85:
            high_confidence.append({
                "category": f["category"],
                "context": f["context"],
                "confidence": f["confidence"],
            })

    return {
        "total_failures": len(failures),
        "by_category": dict(by_category),
        "by_subcategory": dict(by_subcategory),
        "refusal_count": by_category.get("refusal", 0),
        "env_failure_count": by_category.get("env_failure", 0),
        "tool_failure_count": by_category.get("tool_failure", 0),
        "reasoning_failure_count": by_category.get("reasoning_failure", 0),
        "high_confidence_failures": high_confidence[:10],  # Top 10
    }


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Classify failures and refusals from conversation logs"
    )
    parser.add_argument("input", help="Path to parsed conversations JSON or usage.jsonl")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--summary", action="store_true", help="Output summary only")
    parser.add_argument("--min-confidence", type=float, default=0.5,
                        help="Minimum confidence threshold (default: 0.5)")

    args = parser.parse_args()

    # Load input
    input_path = Path(args.input)

    if input_path.suffix == ".jsonl":
        # Parse usage.jsonl directly
        from parse_conversations import parse_usage_jsonl, assign_turn_ids
        entries = parse_usage_jsonl(str(input_path))
        entries = assign_turn_ids(entries)
    else:
        # Load pre-parsed JSON
        with open(input_path, "r", encoding="utf-8") as f:
            entries = json.load(f)

    # Classify failures
    failures = classify_failures(entries)

    # Filter by confidence
    failures = [f for f in failures if f["confidence"] >= args.min_confidence]

    # Generate output
    if args.summary:
        output = get_failure_summary(failures)
    else:
        output = {
            "total_entries": len(entries),
            "failures": failures,
            "summary": get_failure_summary(failures),
        }

    output_str = json.dumps(output, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")
        print(f"Output written to: {args.output}", file=sys.stderr)
    else:
        print(output_str)


if __name__ == "__main__":
    main()
