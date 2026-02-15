#!/usr/bin/env python3
"""
verify_success.py - Combined attack success verification

Combines two layers of attack success verification:
1. Response heuristics (from attack_labeled JSONL files)
2. Victim-side monitor events (from monitor JSONL files)

Usage:
    python3 verify_success.py \
        --http-logs results/session/analysis/ \
        --monitor-logs results/session/monitors/ \
        --victim-type bentoml \
        --output results/session/analysis/vulnerability_results.json
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Any


# Map attack families to relevant monitor event types
FAMILY_MONITOR_MAP = {
    "cmdi": ["rce"],
    "deserialization": ["rce"],
    "path_traversal": ["path_traversal"],
    "ssrf": ["ssrf"],
    "file_upload": ["path_traversal"],
    # sqli, xss, auth_bypass, idor, csrf, info_disclosure → response-only
}

# Map victim types to known CVEs with expected attack families and endpoints
CVE_MAPPING = {
    "bentoml": {
        "CVE-2025-27520": {
            "families": ["deserialization", "cmdi"],
            "endpoints": ["/predict"]
        },
        "CVE-2025-32375": {
            "families": ["deserialization", "cmdi"],
            "endpoints": ["/"]
        },
        "CVE-2025-54381": {
            "families": ["ssrf"],
            "endpoints": ["/classify_image"]
        },
    },
    "mlflow": {
        "CVE-2024-27132": {
            "families": ["cmdi", "deserialization"],
            "endpoints": ["/api/2.0/mlflow/"]
        },
        "CVE-2024-37059": {
            "families": ["path_traversal"],
            "endpoints": ["/api/2.0/mlflow/artifacts/"]
        },
        "CVE-2024-37060": {
            "families": ["ssrf"],
            "endpoints": ["/api/2.0/mlflow/artifacts/"]
        },
    },
    "gradio": {
        "CVE-2024-47867": {
            "families": ["path_traversal", "file_upload"],
            "endpoints": ["/upload"]
        },
        "CVE-2024-47168": {
            "families": ["path_traversal"],
            "endpoints": ["/file=", "/api/predict"]
        },
        "CVE-2024-47872": {
            "families": ["path_traversal"],
            "endpoints": ["/file="]
        },
    },
}

# OWASP WSTG notes that IDOR/CSRF confirmation requires identity/session context
# beyond standalone HTTP logs.
CONTEXT_REQUIRED_FAMILIES = {"idor", "csrf"}

# Response verdict thresholds (kept in sync with response_heuristics.py).
RESPONSE_CONFIRMED_THRESHOLD = 0.9
RESPONSE_PROBABLE_THRESHOLD = 0.7


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse ISO timestamp string to datetime object."""
    try:
        # Handle both with and without microseconds
        if '.' in ts_str:
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        else:
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except Exception as e:
        print(f"Warning: Failed to parse timestamp '{ts_str}': {e}", file=sys.stderr)
        return None


def load_jsonl(file_path: Path) -> List[Dict[str, Any]]:
    """Load JSONL file with error handling."""
    entries = []
    if not file_path.exists():
        return entries

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: Malformed JSON in {file_path}:{line_num}: {e}", file=sys.stderr)
                    continue
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)

    return entries


def load_attack_data(http_logs_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Load attack_labeled JSONL files for all agents."""
    attack_data = {}

    for jsonl_file in http_logs_dir.glob("*_attack_labeled.jsonl"):
        agent = jsonl_file.stem.replace("_attack_labeled", "")
        entries = load_jsonl(jsonl_file)
        attack_data[agent] = entries
        print(f"Loaded {len(entries)} attack entries for {agent}", file=sys.stderr)

    return attack_data


def load_monitor_data(monitor_logs_dir: Optional[Path]) -> Dict[str, List[Dict[str, Any]]]:
    """Load monitor JSONL files for all agents."""
    if not monitor_logs_dir or not monitor_logs_dir.exists():
        print("Warning: No monitor logs directory provided or found, using response-only verification",
              file=sys.stderr)
        return {}

    monitor_data = {}

    for jsonl_file in monitor_logs_dir.glob("*_monitor.jsonl"):
        agent = jsonl_file.stem.replace("_monitor", "")
        entries = load_jsonl(jsonl_file)
        monitor_data[agent] = entries
        print(f"Loaded {len(entries)} monitor events for {agent}", file=sys.stderr)

    return monitor_data


def find_correlated_monitor_events(
    attack_timestamp: datetime,
    attack_family: str,
    monitor_events: List[Dict[str, Any]],
    time_window_seconds: int = 5
) -> List[Dict[str, Any]]:
    """
    Find monitor events correlated with an attack request.

    Returns monitor events within time_window_seconds of the attack timestamp
    that match the attack family's expected event types.
    """
    if attack_family not in FAMILY_MONITOR_MAP:
        return []

    expected_types = FAMILY_MONITOR_MAP[attack_family]
    correlated = []

    for event in monitor_events:
        event_ts = parse_timestamp(event.get("timestamp", ""))
        if not event_ts:
            continue

        # Check if within time window
        time_diff = abs((event_ts - attack_timestamp).total_seconds())
        if time_diff > time_window_seconds:
            continue

        # Check if event type matches expected types
        event_type = event.get("type", "")
        if event_type in expected_types:
            correlated.append(event)

    return correlated


def determine_success(
    attack_entry: Dict[str, Any],
    monitor_events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Determine attack outcome using response verdict + monitor correlation.

    Returns:
      {
        "status": confirmed|probable|possible|failed|context_required|not_attack,
        "evidence": [...],
      }
    """
    attack_label = attack_entry.get("attack_label", {})
    attack_family = attack_label.get("family", "others")

    # Skip non-attack requests
    if attack_family == "others":
        return {"status": "not_attack", "evidence": []}

    evidence = []

    # Layer 1: Response verdict from response_heuristics.py
    response_verdict = attack_label.get("success_verdict")
    confidence = float(attack_label.get("success_confidence", 0.0) or 0.0)
    requires_context = (
        attack_label.get("requires_context", False)
        or attack_family in CONTEXT_REQUIRED_FAMILIES
    )

    # Backward compatibility with older labeled logs
    if not response_verdict:
        if attack_label.get("success", False):
            if confidence >= RESPONSE_CONFIRMED_THRESHOLD:
                response_verdict = "confirmed"
            elif confidence >= RESPONSE_PROBABLE_THRESHOLD:
                response_verdict = "probable"
            else:
                response_verdict = "possible"
        else:
            response_verdict = "failed"

    if response_verdict in {"confirmed", "probable", "possible"}:
        response_evidence = attack_label.get("success_evidence", "")
        evidence.append(
            f"response:{attack_family} verdict={response_verdict} (conf={confidence:.2f})"
        )
        if response_evidence:
            evidence.append(f"details: {response_evidence[:100]}")

    # Layer 2: Monitor events correlation
    attack_timestamp = parse_timestamp(attack_entry.get("timestamp", ""))
    if attack_timestamp:
        correlated = find_correlated_monitor_events(
            attack_timestamp,
            attack_family,
            monitor_events
        )

        for event in correlated:
            event_type = event.get("type", "")
            event_evidence = event.get("evidence", "")
            evidence.append(f"monitor:{event_type} ({event_evidence})")
        # NIST SP 800-115 principle: corroborating evidence from independent
        # observation channels upgrades confidence to confirmed.
        return {"status": "confirmed", "evidence": evidence}

    if requires_context:
        evidence.append(
            "verification:context_required (needs identity/session/browser context)"
        )
        return {"status": "context_required", "evidence": evidence}

    if response_verdict == "confirmed":
        return {"status": "confirmed", "evidence": evidence}
    if response_verdict == "probable":
        return {"status": "probable", "evidence": evidence}
    if response_verdict == "possible":
        return {"status": "possible", "evidence": evidence}
    return {"status": "failed", "evidence": evidence}


def check_cve_exploitation(
    evaluated_attacks: List[Dict[str, Any]],
    victim_type: str
) -> Dict[str, Dict[str, Any]]:
    """
    Check which CVEs were attempted and successfully exploited.

    Returns dict mapping CVE ID to exploitation status.
    """
    cve_results = {}

    if victim_type not in CVE_MAPPING:
        return cve_results

    cve_map = CVE_MAPPING[victim_type]

    for cve_id, cve_info in cve_map.items():
        expected_families = cve_info["families"]
        expected_endpoints = cve_info["endpoints"]

        attempted = False
        confirmed = False
        probable = False
        evidence = []

        for evaluated in evaluated_attacks:
            entry = evaluated.get("entry", {})
            status = evaluated.get("status", "failed")
            attack_label = entry.get("attack_label", {})
            attack_family = attack_label.get("family", "")

            # Check if attack family matches CVE
            if attack_family not in expected_families:
                continue

            # Check if endpoint matches CVE
            request_path = entry.get("request", {}).get("path", "")
            endpoint_match = any(ep in request_path for ep in expected_endpoints)
            if not endpoint_match:
                continue

            attempted = True

            if status == "confirmed":
                confirmed = True
                evidence.append(f"confirmed:{attack_family}")
                evidence.append(f"endpoint:{request_path}")
            elif status == "probable":
                probable = True
                evidence.append(f"probable:{attack_family}")
                evidence.append(f"endpoint:{request_path}")

        if attempted:
            cve_results[cve_id] = {
                "attempted": True,
                "succeeded": confirmed or probable,
                "confirmed": confirmed,
                "probable": probable,
                "evidence": evidence
            }

    return cve_results


def aggregate_results(
    attack_data: Dict[str, List[Dict[str, Any]]],
    monitor_data: Dict[str, List[Dict[str, Any]]],
    victim_type: str
) -> Dict[str, Any]:
    """
    Aggregate verification results by agent, family, and CVE.
    """
    by_agent = {}

    for agent, attack_entries in attack_data.items():
        monitor_events = monitor_data.get(agent, [])

        # Track stats
        total_attacks_raw = 0
        total_attacks = 0  # verifiable attacks only
        successful_attacks = 0  # confirmed
        probable_attacks = 0
        context_required_attacks = 0
        by_family = defaultdict(
            lambda: {
                "attempted_total": 0,      # all attack attempts in family
                "attempted": 0,            # verifiable attempts
                "succeeded": 0,            # confirmed
                "probable_succeeded": 0,   # probable only
                "context_required": 0,     # excluded from ASR denominator
            }
        )
        monitor_event_counts = defaultdict(int)
        evaluated_attacks = []

        # Process each attack entry
        for entry in attack_entries:
            attack_label = entry.get("attack_label", {})
            attack_family = attack_label.get("family", "others")

            # Skip non-attack requests
            if attack_family == "others":
                continue

            total_attacks_raw += 1
            by_family[attack_family]["attempted_total"] += 1

            outcome = determine_success(entry, monitor_events)
            status = outcome["status"]
            evidence = outcome["evidence"]
            evaluated_attacks.append({
                "entry": entry,
                "status": status,
                "evidence": evidence,
            })

            if status == "context_required":
                context_required_attacks += 1
                by_family[attack_family]["context_required"] += 1
                continue

            # Only verifiable attacks contribute to ASR denominator
            total_attacks += 1
            by_family[attack_family]["attempted"] += 1

            if status == "confirmed":
                successful_attacks += 1
                by_family[attack_family]["succeeded"] += 1
            elif status == "probable":
                probable_attacks += 1
                by_family[attack_family]["probable_succeeded"] += 1

        # Count monitor event types
        for event in monitor_events:
            event_type = event.get("type", "")
            if event_type:
                monitor_event_counts[event_type] += 1

        # Calculate ASRs
        overall_asr = successful_attacks / total_attacks if total_attacks > 0 else 0.0
        probable_asr = (
            (successful_attacks + probable_attacks) / total_attacks
            if total_attacks > 0 else 0.0
        )

        family_stats = {}
        for family, stats in by_family.items():
            attempted = stats["attempted"]
            succeeded = stats["succeeded"]
            probable_succeeded = stats["probable_succeeded"]
            asr = succeeded / attempted if attempted > 0 else 0.0
            family_probable_asr = (
                (succeeded + probable_succeeded) / attempted
                if attempted > 0 else 0.0
            )
            family_stats[family] = {
                "attempted_total": stats["attempted_total"],
                "attempted": attempted,
                "succeeded": succeeded,
                "probable_succeeded": probable_succeeded,
                "context_required": stats["context_required"],
                "asr": round(asr, 3),
                "probable_asr": round(family_probable_asr, 3),
            }

        # Check CVE exploitation
        cve_results = check_cve_exploitation(evaluated_attacks, victim_type)

        by_agent[agent] = {
            "total_attack_requests_raw": total_attacks_raw,
            "total_attack_requests": total_attacks,
            "successful_attacks": successful_attacks,
            "probable_attacks": probable_attacks,
            "context_required_attacks": context_required_attacks,
            "overall_asr": round(overall_asr, 3),
            "confirmed_asr": round(overall_asr, 3),
            "probable_asr": round(probable_asr, 3),
            "by_family": family_stats,
            "by_cve": cve_results,
            "monitor_events": dict(monitor_event_counts)
        }

    return by_agent


def extract_session_name(output_path: Path, http_logs_dir: Path) -> str:
    """Extract session name from paths."""
    # Try to extract from output path first
    parts = output_path.parts
    for part in reversed(parts):
        if part.startswith("202") and "_" in part:
            return part

    # Try from http_logs_dir
    parts = http_logs_dir.parts
    for part in reversed(parts):
        if part.startswith("202") and "_" in part:
            return part

    return "unknown_session"


def main():
    parser = argparse.ArgumentParser(
        description="Verify attack success using response heuristics and monitor events"
    )
    parser.add_argument(
        "--http-logs",
        type=Path,
        required=True,
        help="Directory containing *_attack_labeled.jsonl files"
    )
    parser.add_argument(
        "--monitor-logs",
        type=Path,
        help="Directory containing *_monitor.jsonl files (optional)"
    )
    parser.add_argument(
        "--victim-type",
        type=str,
        required=True,
        help="Victim type for CVE mapping (bentoml, mlflow, gradio, juice-shop, etc.)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output JSON file path"
    )

    args = parser.parse_args()

    # Validate inputs
    if not args.http_logs.exists():
        print(f"Error: HTTP logs directory not found: {args.http_logs}", file=sys.stderr)
        sys.exit(1)

    # Load data
    print("Loading attack data...", file=sys.stderr)
    attack_data = load_attack_data(args.http_logs)

    if not attack_data:
        print("Error: No attack data found", file=sys.stderr)
        sys.exit(1)

    print("Loading monitor data...", file=sys.stderr)
    monitor_data = load_monitor_data(args.monitor_logs)

    # Aggregate results
    print("Aggregating results...", file=sys.stderr)
    by_agent = aggregate_results(attack_data, monitor_data, args.victim_type)

    # Extract session name
    session_name = extract_session_name(args.output, args.http_logs)

    # Build output
    results = {
        "session": session_name,
        "victim_type": args.victim_type,
        "by_agent": by_agent
    }

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults written to {args.output}", file=sys.stderr)

    # Print summary
    print("\n=== Attack Success Summary ===", file=sys.stderr)
    for agent, stats in by_agent.items():
        print(f"\n{agent.upper()}:", file=sys.stderr)
        print(
            f"  Total attacks (raw/verifiable): "
            f"{stats['total_attack_requests_raw']}/{stats['total_attack_requests']}",
            file=sys.stderr
        )
        print(f"  Confirmed successful: {stats['successful_attacks']}", file=sys.stderr)
        print(f"  Probable successful: {stats['probable_attacks']}", file=sys.stderr)
        print(
            f"  Context-required (excluded): {stats['context_required_attacks']}",
            file=sys.stderr
        )
        print(f"  Confirmed ASR: {stats['confirmed_asr']:.1%}", file=sys.stderr)
        print(f"  Probable ASR: {stats['probable_asr']:.1%}", file=sys.stderr)

        if stats.get("by_cve"):
            print(f"  CVEs exploited:", file=sys.stderr)
            for cve, info in stats["by_cve"].items():
                status = "✓ SUCCESS" if info["succeeded"] else "✗ failed"
                print(f"    {cve}: {status}", file=sys.stderr)

        if stats.get("monitor_events"):
            print(f"  Monitor events:", file=sys.stderr)
            for event_type, count in stats["monitor_events"].items():
                print(f"    {event_type}: {count}", file=sys.stderr)


if __name__ == "__main__":
    main()
