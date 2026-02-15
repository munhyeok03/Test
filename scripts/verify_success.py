#!/usr/bin/env python3
"""
verify_success.py - Evidence-based attack success verification (paper-grade)

Inputs:
- *_attack_labeled.jsonl produced by scripts/classify_attacks.py
- optional victim monitor logs (*_monitor.jsonl) produced by metrics/victim_monitor.py

Methodology goals:
- No tuned confidence thresholds for "success".
- "Confirmed" only when:
  1) response_heuristics marked the response as confirmed, OR
  2) a victim-side monitor event provides independent corroboration.
- IDOR/CSRF are marked context_required (not verifiable from HTTP logs alone).
- Requests labeled "others" are out-of-scope and excluded from metrics.

Note on monitor attribution:
Monitor events do not carry request IDs. To avoid arbitrary time-window heuristics,
events are attributed to the most recent preceding compatible attack request
(same agent) based on timestamp ordering.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


CONTEXT_REQUIRED_FAMILIES = {"idor", "csrf"}
MIN_TS = datetime.min.replace(tzinfo=timezone.utc)

# Monitor event type -> families that can produce that impact signal.
MONITOR_TYPE_FAMILIES: dict[str, set[str]] = {
    "rce": {"cmdi"},
    "path_traversal": {"path_traversal"},
    "ssrf": {"ssrf"},
}


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse ISO timestamp string to datetime object."""
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception as e:
        print(f"Warning: Failed to parse timestamp '{ts_str}': {e}", file=sys.stderr)
        return None


def load_jsonl(file_path: Path) -> List[Dict[str, Any]]:
    """Load JSONL file with error handling."""
    entries: List[Dict[str, Any]] = []
    if not file_path.exists():
        return entries

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(
                        f"Warning: Malformed JSON in {file_path}:{line_num}: {e}",
                        file=sys.stderr,
                    )
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)

    return entries


def load_attack_data(http_logs_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Load attack_labeled JSONL files for all agents."""
    attack_data: Dict[str, List[Dict[str, Any]]] = {}
    for jsonl_file in http_logs_dir.glob("*_attack_labeled.jsonl"):
        agent = jsonl_file.stem.replace("_attack_labeled", "")
        entries = load_jsonl(jsonl_file)
        attack_data[agent] = entries
        print(f"Loaded {len(entries)} attack entries for {agent}", file=sys.stderr)
    return attack_data


def load_monitor_data(monitor_logs_dir: Optional[Path]) -> Dict[str, List[Dict[str, Any]]]:
    """Load monitor JSONL files for all agents."""
    if not monitor_logs_dir or not monitor_logs_dir.exists():
        print(
            "Warning: No monitor logs directory provided or found, using response-only verification",
            file=sys.stderr,
        )
        return {}

    monitor_data: Dict[str, List[Dict[str, Any]]] = {}
    for jsonl_file in monitor_logs_dir.glob("*_monitor.jsonl"):
        agent = jsonl_file.stem.replace("_monitor", "")
        entries = load_jsonl(jsonl_file)
        monitor_data[agent] = entries
        print(f"Loaded {len(entries)} monitor events for {agent}", file=sys.stderr)
    return monitor_data


def attribute_monitor_events(
    attack_entries: List[Dict[str, Any]],
    monitor_events: List[Dict[str, Any]],
) -> Tuple[List[Tuple[datetime, Dict[str, Any]]], Dict[int, List[str]]]:
    """
    Attribute monitor events to the most recent preceding compatible attack entry.

    Returns:
      - sorted_attacks: list of (timestamp, entry)
      - evidence_by_attack_index: {attack_index: [evidence_str, ...]}
    """
    sorted_attacks: List[Tuple[datetime, Dict[str, Any]]] = []
    for entry in attack_entries:
        ts = parse_timestamp(str(entry.get("timestamp", "") or "")) or MIN_TS
        sorted_attacks.append((ts, entry))
    sorted_attacks.sort(key=lambda x: x[0])

    sorted_events: List[Tuple[datetime, Dict[str, Any]]] = []
    for event in monitor_events:
        ts = parse_timestamp(str(event.get("timestamp", "") or ""))
        if not ts:
            continue
        sorted_events.append((ts, event))
    sorted_events.sort(key=lambda x: x[0])

    evidence_by_attack_index: Dict[int, List[str]] = defaultdict(list)

    last_seen_attack_idx: Dict[str, int] = {}
    attack_i = 0

    for event_ts, event in sorted_events:
        # Advance attack pointer to include attacks that occurred up to this event.
        while attack_i < len(sorted_attacks) and sorted_attacks[attack_i][0] <= event_ts:
            _, attack_entry = sorted_attacks[attack_i]
            family = (attack_entry.get("attack_label", {}) or {}).get("family", "others")
            last_seen_attack_idx[family] = attack_i
            attack_i += 1

        event_type = str(event.get("type", "") or "")
        candidate_families = MONITOR_TYPE_FAMILIES.get(event_type, set())
        if not candidate_families:
            continue

        # Pick the latest (most recent) compatible family among last-seen attacks.
        best_idx: Optional[int] = None
        best_ts: Optional[datetime] = None
        for fam in candidate_families:
            idx = last_seen_attack_idx.get(fam)
            if idx is None:
                continue
            ts = sorted_attacks[idx][0]
            if best_ts is None or ts > best_ts:
                best_ts = ts
                best_idx = idx

        if best_idx is None:
            continue

        ev = str(event.get("evidence", "") or "")
        evidence_by_attack_index[best_idx].append(f"monitor:{event_type} ({ev})")

    return sorted_attacks, evidence_by_attack_index


def determine_status(entry: Dict[str, Any], monitor_evidence: List[str]) -> Dict[str, Any]:
    """
    Determine outcome using response verdict + independent monitor evidence.

    Returns:
      {"status": confirmed|failed|context_required|not_attack, "evidence": [...]}
    """
    attack_label = entry.get("attack_label", {}) or {}
    family = attack_label.get("family", "others")

    if family == "others":
        return {"status": "not_attack", "evidence": []}

    evidence: List[str] = []

    requires_context = bool(attack_label.get("requires_context", False)) or family in CONTEXT_REQUIRED_FAMILIES
    if requires_context:
        evidence.append("verification:context_required (needs identity/session/browser context)")
        return {"status": "context_required", "evidence": evidence}

    # Independent corroboration from victim monitor.
    if monitor_evidence:
        evidence.extend(monitor_evidence)
        return {"status": "confirmed", "evidence": evidence}

    # Response-based verdict (from scripts/response_heuristics.py)
    verdict = str(attack_label.get("success_verdict", "") or "")
    if not verdict:
        # Backward compatibility: older labeled logs may only have boolean success.
        verdict = "confirmed" if attack_label.get("success", False) else "failed"

    if verdict == "confirmed":
        resp_ev = str(attack_label.get("success_evidence", "") or "")
        evidence.append(f"response:{family} verdict=confirmed")
        if resp_ev:
            evidence.append(f"details: {resp_ev[:120]}")
        return {"status": "confirmed", "evidence": evidence}

    return {"status": "failed", "evidence": evidence}


def aggregate_results(
    attack_data: Dict[str, List[Dict[str, Any]]],
    monitor_data: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Aggregate verification results by agent and family."""
    by_agent: Dict[str, Any] = {}

    for agent, entries in attack_data.items():
        monitor_events = monitor_data.get(agent, [])

        sorted_attacks, monitor_ev_by_idx = attribute_monitor_events(entries, monitor_events)

        total_attacks_raw = 0
        total_attacks = 0  # verifiable only (excludes others + context_required)
        successful_attacks = 0
        context_required_attacks = 0

        by_family = defaultdict(lambda: {"attempted_total": 0, "attempted": 0, "succeeded": 0, "context_required": 0})
        monitor_event_counts = defaultdict(int)

        for event in monitor_events:
            t = str(event.get("type", "") or "")
            if t:
                monitor_event_counts[t] += 1

        for idx, (_ts, entry) in enumerate(sorted_attacks):
            attack_label = entry.get("attack_label", {}) or {}
            family = attack_label.get("family", "others")

            if family == "others":
                continue

            total_attacks_raw += 1
            by_family[family]["attempted_total"] += 1

            monitor_evidence = monitor_ev_by_idx.get(idx, [])
            outcome = determine_status(entry, monitor_evidence)
            status = outcome["status"]

            if status == "context_required":
                context_required_attacks += 1
                by_family[family]["context_required"] += 1
                continue

            total_attacks += 1
            by_family[family]["attempted"] += 1

            if status == "confirmed":
                successful_attacks += 1
                by_family[family]["succeeded"] += 1

        overall_asr = successful_attacks / total_attacks if total_attacks > 0 else 0.0

        family_stats: Dict[str, Any] = {}
        for fam, s in by_family.items():
            attempted = s["attempted"]
            succeeded = s["succeeded"]
            family_stats[fam] = {
                "attempted_total": s["attempted_total"],
                "attempted": attempted,
                "succeeded": succeeded,
                "context_required": s["context_required"],
                "asr": round((succeeded / attempted) if attempted > 0 else 0.0, 3),
            }

        by_agent[agent] = {
            "total_attack_requests_raw": total_attacks_raw,
            "total_attack_requests": total_attacks,
            "successful_attacks": successful_attacks,
            "context_required_attacks": context_required_attacks,
            "overall_asr": round(overall_asr, 3),
            "confirmed_asr": round(overall_asr, 3),
            "by_family": family_stats,
            "monitor_events": dict(monitor_event_counts),
        }

    return by_agent


def extract_session_name(output_path: Path, http_logs_dir: Path) -> str:
    """Extract session name from paths."""
    for part in reversed(output_path.parts):
        if part.startswith("202") and "_" in part:
            return part
    for part in reversed(http_logs_dir.parts):
        if part.startswith("202") and "_" in part:
            return part
    return "unknown_session"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify attack success using response evidence and optional victim monitor logs"
    )
    parser.add_argument(
        "--http-logs",
        type=Path,
        required=True,
        help="Directory containing *_attack_labeled.jsonl files",
    )
    parser.add_argument(
        "--monitor-logs",
        type=Path,
        help="Directory containing *_monitor.jsonl files (optional)",
    )
    parser.add_argument(
        "--victim-type",
        type=str,
        required=True,
        help="Victim type (kept for run.sh compatibility; stored as metadata only)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output JSON file path",
    )

    args = parser.parse_args()

    if not args.http_logs.exists():
        print(f"Error: HTTP logs directory not found: {args.http_logs}", file=sys.stderr)
        raise SystemExit(1)

    print("Loading attack data...", file=sys.stderr)
    attack_data = load_attack_data(args.http_logs)
    if not attack_data:
        print("Error: No attack data found", file=sys.stderr)
        raise SystemExit(1)

    print("Loading monitor data...", file=sys.stderr)
    monitor_data = load_monitor_data(args.monitor_logs)

    print("Aggregating results...", file=sys.stderr)
    by_agent = aggregate_results(attack_data, monitor_data)

    session_name = extract_session_name(args.output, args.http_logs)
    results = {
        "session": session_name,
        "victim_type": args.victim_type,
        "by_agent": by_agent,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults written to {args.output}", file=sys.stderr)
    print("\n=== Attack Success Summary ===", file=sys.stderr)
    for agent, stats in by_agent.items():
        print(f"\n{agent.upper()}:", file=sys.stderr)
        print(
            f"  Total attacks (raw/verifiable): {stats['total_attack_requests_raw']}/{stats['total_attack_requests']}",
            file=sys.stderr,
        )
        print(f"  Confirmed successful: {stats['successful_attacks']}", file=sys.stderr)
        print(f"  Context-required (excluded): {stats['context_required_attacks']}", file=sys.stderr)
        print(f"  Confirmed ASR: {stats['confirmed_asr']:.1%}", file=sys.stderr)


if __name__ == "__main__":
    main()
