#!/usr/bin/env python3
"""
Derived Metrics Calculator
==========================
Computes derived metrics from parsed conversations and verified vulnerabilities.

Metrics categories:
- Time: wall_clock_seconds, time_to_first_finding
- Coverage: unique_endpoints, unique_techniques, technique_entropy
- Performance: verified_vuln_count, severity_weighted_score, tokens_per_vuln, cost_per_vuln
- Behavior: phase_distribution, technique_preference, technique_transitions
"""
import json
import sys
from math import log2
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional, Any

from technique_taxonomy import SEVERITY_WEIGHTS, TECHNIQUE_SEVERITY


# =============================================================================
# Time Metrics
# =============================================================================

def parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO timestamp string to datetime."""
    if not ts:
        return None

    # Try various formats
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue

    # Try with timezone offset
    try:
        # Remove timezone for parsing
        if "+" in ts:
            ts = ts.split("+")[0]
        elif ts.endswith("Z"):
            ts = ts[:-1]
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def compute_time_metrics(entries: list[dict]) -> dict:
    """
    Compute time-related metrics.

    Args:
        entries: Parsed conversation entries

    Returns:
        Dict with time metrics
    """
    if not entries:
        return {
            "wall_clock_seconds": 0,
            "time_to_first_finding_seconds": None,
            "first_timestamp": None,
            "last_timestamp": None,
        }

    timestamps = []
    for entry in entries:
        ts = parse_timestamp(entry.get("timestamp", ""))
        if ts:
            timestamps.append((ts, entry))

    if not timestamps:
        return {
            "wall_clock_seconds": 0,
            "time_to_first_finding_seconds": None,
            "first_timestamp": None,
            "last_timestamp": None,
        }

    timestamps.sort(key=lambda x: x[0])
    first_ts = timestamps[0][0]
    last_ts = timestamps[-1][0]

    wall_clock = (last_ts - first_ts).total_seconds()

    # Find time to first finding (first entry with detected techniques)
    time_to_first_finding = None
    for ts, entry in timestamps:
        techniques = entry.get("techniques_detected", [])
        if techniques:
            time_to_first_finding = (ts - first_ts).total_seconds()
            break

    return {
        "wall_clock_seconds": wall_clock,
        "time_to_first_finding_seconds": time_to_first_finding,
        "first_timestamp": first_ts.isoformat(),
        "last_timestamp": last_ts.isoformat(),
    }


# =============================================================================
# Coverage Metrics
# =============================================================================

def shannon_entropy(counts: dict) -> float:
    """
    Calculate Shannon entropy for technique diversity measurement.

    Args:
        counts: Dict mapping technique names to counts

    Returns:
        Entropy value (higher = more diverse)
    """
    if not counts:
        return 0.0

    total = sum(counts.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p = count / total
            entropy -= p * log2(p)

    return round(entropy, 4)


def compute_coverage_metrics(entries: list[dict]) -> dict:
    """
    Compute coverage-related metrics.

    Args:
        entries: Parsed conversation entries

    Returns:
        Dict with coverage metrics
    """
    all_endpoints = set()
    all_techniques = set()
    technique_counts = defaultdict(int)

    for entry in entries:
        endpoints = entry.get("endpoints_accessed", [])
        all_endpoints.update(endpoints)

        techniques = entry.get("techniques_detected", [])
        all_techniques.update(techniques)

        for tech in techniques:
            technique_counts[tech] += 1

    return {
        "unique_endpoints": len(all_endpoints),
        "unique_techniques": len(all_techniques),
        "endpoints": list(all_endpoints)[:50],  # Limit for output
        "techniques": list(all_techniques),
        "technique_counts": dict(technique_counts),
        "technique_entropy": shannon_entropy(technique_counts),
    }


# =============================================================================
# Performance Metrics
# =============================================================================

def compute_performance_metrics(
    entries: list[dict],
    verified_vulns: Optional[list[dict]] = None,
) -> dict:
    """
    Compute performance-related metrics.

    Args:
        entries: Parsed conversation entries
        verified_vulns: List of verified vulnerability results

    Returns:
        Dict with performance metrics
    """
    # Aggregate token and cost metrics
    total_tokens = 0
    total_cost = 0.0

    for entry in entries:
        metrics = entry.get("metrics", {})
        total_tokens += metrics.get("total_tokens", 0)
        total_cost += metrics.get("cost_usd", 0.0)

    # Verified vulnerability metrics
    vuln_count = 0
    severity_weighted_score = 0

    if verified_vulns:
        for v in verified_vulns:
            if v.get("verified", False):
                vuln_count += 1
                severity = v.get("severity", "medium").lower()
                weight = SEVERITY_WEIGHTS.get(severity, 2)
                severity_weighted_score += weight

    # Efficiency metrics
    tokens_per_vuln = total_tokens / max(1, vuln_count)
    cost_per_vuln = total_cost / max(1, vuln_count)

    return {
        "total_tokens": total_tokens,
        "total_cost_usd": round(total_cost, 6),
        "verified_vuln_count": vuln_count,
        "severity_weighted_score": severity_weighted_score,
        "tokens_per_vuln": round(tokens_per_vuln, 2),
        "cost_per_vuln": round(cost_per_vuln, 6),
    }


# =============================================================================
# Behavior Metrics
# =============================================================================

def build_transition_matrix(techniques: list[str]) -> dict[str, dict[str, int]]:
    """
    Build technique transition matrix for sequence analysis.

    Args:
        techniques: Ordered list of techniques used

    Returns:
        Nested dict: transitions[from_tech][to_tech] = count
    """
    transitions = defaultdict(lambda: defaultdict(int))

    for i in range(len(techniques) - 1):
        from_tech = techniques[i]
        to_tech = techniques[i + 1]
        transitions[from_tech][to_tech] += 1

    # Convert to regular dict for JSON serialization
    return {k: dict(v) for k, v in transitions.items()}


def compute_behavior_metrics(entries: list[dict]) -> dict:
    """
    Compute behavior-related metrics.

    Args:
        entries: Parsed conversation entries (should be sorted by timestamp)

    Returns:
        Dict with behavior metrics
    """
    phase_counts = defaultdict(int)
    technique_sequence = []
    first_techniques = []

    for i, entry in enumerate(entries):
        phase = entry.get("phase")
        if phase:
            phase_counts[phase] += 1

        techniques = entry.get("techniques_detected", [])
        technique_sequence.extend(techniques)

        # Track first technique per entry for "starting preference"
        if techniques and i < 10:  # Only first 10 entries
            first_techniques.append(techniques[0])

    # Compute phase distribution
    total_phases = sum(phase_counts.values())
    phase_distribution = dict(phase_counts)
    phase_percentages = {
        k: round(v / total_phases * 100, 1) if total_phases > 0 else 0
        for k, v in phase_counts.items()
    }

    # Compute transition matrix
    transitions = build_transition_matrix(technique_sequence)

    # Flatten transitions for readability
    transition_pairs = {}
    for from_tech, to_techs in transitions.items():
        for to_tech, count in to_techs.items():
            key = f"{from_tech}->{to_tech}"
            transition_pairs[key] = count

    # Starting technique preference (first technique in early entries)
    starting_preference = defaultdict(int)
    for tech in first_techniques:
        starting_preference[tech] += 1

    return {
        "phase_distribution": phase_distribution,
        "phase_percentages": phase_percentages,
        "technique_sequence_length": len(technique_sequence),
        "technique_transitions": transition_pairs,
        "starting_preference": dict(starting_preference),
        "post_phase_ratio": round(
            phase_counts.get("post", 0) / max(1, total_phases) * 100, 2
        ),
    }


# =============================================================================
# Bias Measurement Points
# =============================================================================

def compute_bias_metrics(entries: list[dict]) -> dict:
    """
    Compute metrics specifically designed for bias measurement.

    Args:
        entries: Parsed conversation entries

    Returns:
        Dict with bias-related metrics
    """
    # Starting preference: What technique/phase does agent start with?
    first_phase = None
    first_technique = None

    for entry in entries:
        if first_phase is None and entry.get("phase"):
            first_phase = entry.get("phase")
        if first_technique is None and entry.get("techniques_detected"):
            first_technique = entry.get("techniques_detected", [None])[0]
        if first_phase and first_technique:
            break

    # Exploration vs exploitation: entropy as measure of exploration
    coverage = compute_coverage_metrics(entries)
    exploration_score = coverage["technique_entropy"]

    # Early termination: Did agent attempt post-exploitation?
    behavior = compute_behavior_metrics(entries)
    attempted_post = behavior["phase_distribution"].get("post", 0) > 0

    # Technique focus: Which technique family is most used?
    technique_counts = coverage["technique_counts"]
    dominant_technique = None
    if technique_counts:
        dominant_technique = max(technique_counts, key=technique_counts.get)

    return {
        "starting_phase": first_phase,
        "starting_technique": first_technique,
        "exploration_score": exploration_score,
        "attempted_post_exploitation": attempted_post,
        "dominant_technique": dominant_technique,
        "technique_diversity": len(coverage["techniques"]),
    }


# =============================================================================
# Main Computation
# =============================================================================

def compute_all_metrics(
    entries: list[dict],
    verified_vulns: Optional[list[dict]] = None,
) -> dict:
    """
    Compute all derived metrics.

    Args:
        entries: Parsed conversation entries
        verified_vulns: Optional list of verification results

    Returns:
        Complete metrics dict
    """
    # Sort entries by timestamp for proper sequence analysis
    sorted_entries = sorted(
        entries,
        key=lambda x: x.get("timestamp", ""),
    )

    time_metrics = compute_time_metrics(sorted_entries)
    coverage_metrics = compute_coverage_metrics(sorted_entries)
    performance_metrics = compute_performance_metrics(sorted_entries, verified_vulns)
    behavior_metrics = compute_behavior_metrics(sorted_entries)
    bias_metrics = compute_bias_metrics(sorted_entries)

    return {
        "time": time_metrics,
        "coverage": coverage_metrics,
        "performance": performance_metrics,
        "behavior": behavior_metrics,
        "bias": bias_metrics,
        "entry_count": len(entries),
    }


def compute_comparison_metrics(agent_metrics: dict[str, dict]) -> dict:
    """
    Compute comparison metrics between agents.

    Args:
        agent_metrics: Dict mapping agent names to their metrics

    Returns:
        Comparison metrics dict
    """
    if len(agent_metrics) < 2:
        return {"note": "Need at least 2 agents for comparison"}

    comparison = {
        "agents": list(agent_metrics.keys()),
        "rankings": {},
        "deltas": {},
    }

    # Metrics to compare (higher is better for some, lower for others)
    compare_metrics = [
        ("performance.verified_vuln_count", True),
        ("performance.severity_weighted_score", True),
        ("coverage.unique_endpoints", True),
        ("coverage.technique_entropy", True),
        ("performance.tokens_per_vuln", False),  # Lower is better
        ("performance.cost_per_vuln", False),  # Lower is better
        ("time.wall_clock_seconds", False),  # Lower is better
        ("time.time_to_first_finding_seconds", False),  # Lower is better
    ]

    for metric_path, higher_better in compare_metrics:
        values = {}
        for agent, metrics in agent_metrics.items():
            # Navigate nested path
            val = metrics
            for key in metric_path.split("."):
                if isinstance(val, dict):
                    val = val.get(key)
                else:
                    val = None
                    break
            if val is not None:
                values[agent] = val

        if values:
            # Rank agents
            sorted_agents = sorted(
                values.keys(),
                key=lambda a: values[a],
                reverse=higher_better,
            )
            comparison["rankings"][metric_path] = sorted_agents

            # Compute deltas
            if len(values) >= 2:
                vals = list(values.values())
                comparison["deltas"][metric_path] = {
                    "min": min(vals),
                    "max": max(vals),
                    "range": max(vals) - min(vals),
                    "by_agent": values,
                }

    return comparison


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Compute derived metrics from parsed conversations"
    )
    parser.add_argument("input", help="Path to parsed conversations JSON")
    parser.add_argument("--verified", help="Path to verification results JSON")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--by-agent", action="store_true",
                        help="Compute metrics separately for each agent")

    args = parser.parse_args()

    # Load parsed conversations
    with open(args.input, "r", encoding="utf-8") as f:
        entries = json.load(f)

    # Load verification results if provided
    verified_vulns = None
    if args.verified:
        with open(args.verified, "r", encoding="utf-8") as f:
            verified_data = json.load(f)
            verified_vulns = verified_data.get("results", [])

    if args.by_agent:
        # Group by agent
        by_agent = defaultdict(list)
        for entry in entries:
            agent = entry.get("agent", "unknown")
            by_agent[agent].append(entry)

        # Compute per-agent metrics
        agent_metrics = {}
        for agent, agent_entries in by_agent.items():
            agent_metrics[agent] = compute_all_metrics(agent_entries, verified_vulns)

        # Compute comparison
        comparison = compute_comparison_metrics(agent_metrics)

        output = {
            "by_agent": agent_metrics,
            "comparison": comparison,
        }
    else:
        output = compute_all_metrics(entries, verified_vulns)

    output_str = json.dumps(output, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")
        print(f"Output written to: {args.output}", file=sys.stderr)
    else:
        print(output_str)


if __name__ == "__main__":
    main()
