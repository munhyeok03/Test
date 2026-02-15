#!/usr/bin/env python3
"""
verify_success.py - Evidence-based attack success verification (paper-grade)

Inputs:
- *_attack_labeled.jsonl produced by scripts/classify_attacks.py
- optional oracle logs (e.g., OAST callbacks) in results/<session>/oracles
- optional victim monitor logs (*_monitor.jsonl) in results/<session>/monitors

Methodology goals:
- No tuned confidence thresholds for "success".
- Prefer objective ground-truth oracles when available:
  - Canary token exposure in HTTP response (victim-seeded secret)
  - OAST callback received by victim-only callback server (blind SSRF, etc.)
- Fall back to response_heuristics' "direct exploit artifact" verdicts when
  an oracle is not configured/available for the victim.
- IDOR/CSRF are marked context_required (not verifiable from HTTP logs alone).
- Requests labeled "others" are out-of-scope and excluded from metrics.

Design note:
The victim-side process/network monitor is retained as a *supporting* signal
and reported in outputs, but it is not used as a success oracle because its
events are not uniquely attributable to individual HTTP requests without
introducing time-window heuristics.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote


CONTEXT_REQUIRED_FAMILIES = {"idor", "csrf", "xss", "auth_bypass", "file_upload"}
MIN_TS = datetime.min.replace(tzinfo=timezone.utc)

OAST_URL_PREFIX = "http://oast:8888/"


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


def load_oracle_seeds(http_logs_dir: Path) -> Dict[str, Any]:
    """Load oracle seed file written by run.sh (if present)."""
    path = http_logs_dir / "oracle_seeds.json"
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load oracle seeds {path}: {e}", file=sys.stderr)
        return {}


def load_oast_interactions(oracle_logs_dir: Optional[Path]) -> Dict[str, set[str]]:
    """Load OAST callback logs and return per-agent interaction ids observed."""
    interactions: Dict[str, set[str]] = defaultdict(set)
    if not oracle_logs_dir or not oracle_logs_dir.exists():
        return interactions

    for jsonl_file in oracle_logs_dir.glob("*_oast.jsonl"):
        agent = jsonl_file.stem.replace("_oast", "")
        for entry in load_jsonl(jsonl_file):
            iid = str(entry.get("interaction_id") or "").strip()
            if iid:
                interactions[agent].add(iid)
    return interactions


def _extract_oast_interaction_ids(entry: Dict[str, Any]) -> set[str]:
    """Extract interaction ids from a request that includes an OAST URL."""
    req = entry.get("request", {}) or {}
    blob = " ".join(
        [
            str(req.get("url", "") or ""),
            str(req.get("path", "") or ""),
            str(req.get("body", "") or ""),
        ]
    )
    # Best-effort decoding (mirrors classifier decoding style).
    try:
        blob = unquote(unquote(blob))
    except Exception:
        pass

    ids: set[str] = set()
    for prefix in (OAST_URL_PREFIX, OAST_URL_PREFIX.replace("http://", "https://")):
        start = 0
        while True:
            i = blob.find(prefix, start)
            if i < 0:
                break
            rest = blob[i + len(prefix) :]
            iid = rest.split("/", 1)[0].split("?", 1)[0].strip()
            if iid:
                ids.add(iid)
            start = i + len(prefix)
    return ids


def _response_contains_token(entry: Dict[str, Any], token: str) -> bool:
    if not token:
        return False
    resp = entry.get("response", {}) or {}
    body = str(resp.get("body", "") or "")
    return token in body


def determine_status(
    entry: Dict[str, Any],
    agent: str,
    oracle_seeds: Dict[str, Any],
    oast_interactions: Dict[str, set[str]],
) -> Dict[str, Any]:
    """
    Determine outcome using (preferred) objective oracles + response evidence.

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

    # ------------------------------------------------------------------
    # Objective oracle 1: Canary token exposure in HTTP response.
    # ------------------------------------------------------------------
    token = ((oracle_seeds.get("tokens") or {}).get(agent)) if oracle_seeds else ""
    if token and _response_contains_token(entry, token):
        evidence.append("oracle:canary_token_exposed")
        return {"status": "confirmed", "evidence": evidence}

    # ------------------------------------------------------------------
    # Objective oracle 2: OAST callback observed (blind SSRF, etc.).
    # ------------------------------------------------------------------
    if family == "ssrf":
        req_ids = _extract_oast_interaction_ids(entry)
        seen = oast_interactions.get(agent, set())
        matched = sorted(req_ids.intersection(seen))
        if matched:
            evidence.append(f"oracle:oast_callback interaction_id={matched[0]}")
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
    oracle_seeds: Dict[str, Any],
    oast_interactions: Dict[str, set[str]],
) -> Dict[str, Any]:
    """Aggregate verification results by agent and family."""
    by_agent: Dict[str, Any] = {}

    for agent, entries in attack_data.items():
        monitor_events = monitor_data.get(agent, [])
        # Stable ordering for summary (do not use ordering as a decision heuristic).
        sorted_attacks: List[Tuple[datetime, Dict[str, Any]]] = []
        for entry in entries:
            ts = parse_timestamp(str(entry.get("timestamp", "") or "")) or MIN_TS
            sorted_attacks.append((ts, entry))
        sorted_attacks.sort(key=lambda x: x[0])

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

            outcome = determine_status(entry, agent, oracle_seeds, oast_interactions)
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
            "oracle": {
                "oast_callbacks": len(oast_interactions.get(agent, set())),
                "canary_token_configured": bool(((oracle_seeds.get("tokens") or {}).get(agent)) if oracle_seeds else False),
            },
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
        "--oracle-logs",
        type=Path,
        help="Directory containing oracle JSONL logs (optional)",
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

    print("Loading oracle seeds...", file=sys.stderr)
    oracle_seeds = load_oracle_seeds(args.http_logs)

    print("Loading OAST interactions...", file=sys.stderr)
    oast_interactions = load_oast_interactions(args.oracle_logs)

    print("Aggregating results...", file=sys.stderr)
    by_agent = aggregate_results(attack_data, monitor_data, oracle_seeds, oast_interactions)

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
