#!/usr/bin/env python3
"""
Unified Analysis Entry Point
============================
Main analysis script that integrates all metric collection and analysis modules.

Usage:
    python scripts/run_analysis.py \\
        --usage metrics/logs/usage.jsonl \\
        --victim-type juice-shop \\
        --victim-url http://localhost:3000 \\
        --output analysis_results.json
"""
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import defaultdict

# Import analysis modules
from parse_conversations import parse_usage_jsonl, assign_turn_ids, extract_conversation_summary
from vulnerability_verifier import VulnerabilityVerifier
from compute_metrics import compute_all_metrics, compute_comparison_metrics
from aggregate_metrics import aggregate
from failure_classifier import classify_failures, get_failure_summary


def run_full_analysis(
    usage_path: str,
    victim_type: str,
    victim_url: Optional[str] = None,
    agent_filter: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    include_failures: bool = True,
) -> dict:
    """
    Run full analysis pipeline on usage.jsonl.

    Args:
        usage_path: Path to usage.jsonl file
        victim_type: Type of victim (juice-shop, bentoml, etc.)
        victim_url: URL of victim server (for API verification)
        agent_filter: Optional agent type filter
        start_time: Optional start timestamp filter
        end_time: Optional end timestamp filter
        include_failures: Whether to include failure analysis

    Returns:
        Complete analysis results dict
    """
    results = {
        "generated_at": datetime.now().isoformat(),
        "parameters": {
            "usage_path": usage_path,
            "victim_type": victim_type,
            "victim_url": victim_url,
            "agent_filter": agent_filter,
            "start_time": start_time,
            "end_time": end_time,
        },
    }

    # Step 1: Parse conversations
    print("Step 1: Parsing conversations...", file=sys.stderr)
    entries = parse_usage_jsonl(
        usage_path,
        agent_filter=agent_filter,
        start_time=start_time,
        end_time=end_time,
    )

    if not entries:
        results["error"] = "No entries found matching criteria"
        return results

    entries = assign_turn_ids(entries)
    results["total_entries"] = len(entries)

    # Step 2: Group by agent
    print("Step 2: Grouping by agent...", file=sys.stderr)
    by_agent = defaultdict(list)
    for entry in entries:
        agent = entry.get("agent", "unknown")
        by_agent[agent].append(entry)

    results["agents"] = list(by_agent.keys())

    # Step 3: Conversation summary
    print("Step 3: Extracting conversation summary...", file=sys.stderr)
    results["conversation_summary"] = extract_conversation_summary(entries)

    # Step 4: Vulnerability verification
    print("Step 4: Running vulnerability verification...", file=sys.stderr)
    verification_results = {}

    for agent, agent_entries in by_agent.items():
        try:
            verifier = VulnerabilityVerifier(
                victim_type=victim_type,
                victim_url=victim_url,
                conversations=agent_entries,
            )
            agent_results = verifier.verify_all()
            verification_results[agent] = {
                "results": [
                    {
                        "vuln_id": r.vuln_id,
                        "technique": r.technique,
                        "severity": r.severity,
                        "verified": r.verified,
                        "evidence": r.evidence[:2],
                    }
                    for r in agent_results
                ],
                "summary": verifier.get_summary(agent_results),
            }
        except ValueError as e:
            verification_results[agent] = {"error": str(e)}

    results["vulnerability_verification"] = verification_results

    # Step 5: Compute derived metrics per agent
    print("Step 5: Computing derived metrics...", file=sys.stderr)
    agent_metrics = {}

    for agent, agent_entries in by_agent.items():
        # Get verified vulns for this agent
        verified_vulns = None
        if agent in verification_results and "results" in verification_results[agent]:
            verified_vulns = verification_results[agent]["results"]

        agent_metrics[agent] = compute_all_metrics(agent_entries, verified_vulns)

    results["metrics"] = {
        "by_agent": agent_metrics,
        "comparison": compute_comparison_metrics(agent_metrics) if len(agent_metrics) > 1 else None,
    }

    # Step 6: Aggregate raw metrics
    print("Step 6: Aggregating raw metrics...", file=sys.stderr)
    log_dir = str(Path(usage_path).parent)
    results["aggregate_metrics"] = aggregate(log_dir, start_time, end_time)

    # Step 7: Failure analysis (optional)
    if include_failures:
        print("Step 7: Analyzing failures...", file=sys.stderr)
        failure_results = {}

        for agent, agent_entries in by_agent.items():
            failures = classify_failures(agent_entries)
            failure_results[agent] = get_failure_summary(failures)

        results["failure_analysis"] = failure_results

    # Step 8: Generate bias measurement summary
    print("Step 8: Generating bias summary...", file=sys.stderr)
    results["bias_summary"] = generate_bias_summary(agent_metrics)

    return results


def generate_bias_summary(agent_metrics: dict) -> dict:
    """
    Generate summary of bias measurements across agents.

    Args:
        agent_metrics: Dict mapping agent names to their computed metrics

    Returns:
        Bias summary dict
    """
    if not agent_metrics:
        return {}

    summary = {
        "starting_preferences": {},
        "exploration_scores": {},
        "technique_preferences": {},
        "post_exploitation_attempts": {},
    }

    for agent, metrics in agent_metrics.items():
        bias = metrics.get("bias", {})

        # Starting preferences
        summary["starting_preferences"][agent] = {
            "phase": bias.get("starting_phase"),
            "technique": bias.get("starting_technique"),
        }

        # Exploration scores (higher = more diverse)
        summary["exploration_scores"][agent] = bias.get("exploration_score", 0)

        # Dominant technique
        summary["technique_preferences"][agent] = bias.get("dominant_technique")

        # Post-exploitation attempts
        summary["post_exploitation_attempts"][agent] = bias.get("attempted_post_exploitation", False)

    # Identify notable differences
    differences = []

    # Check exploration score variance
    scores = list(summary["exploration_scores"].values())
    if scores and max(scores) - min(scores) > 0.5:
        high_agent = max(summary["exploration_scores"], key=summary["exploration_scores"].get)
        low_agent = min(summary["exploration_scores"], key=summary["exploration_scores"].get)
        differences.append(
            f"Exploration diversity: {high_agent} ({max(scores):.2f}) vs {low_agent} ({min(scores):.2f})"
        )

    # Check technique preference differences
    prefs = summary["technique_preferences"]
    unique_prefs = set(v for v in prefs.values() if v)
    if len(unique_prefs) > 1:
        differences.append(
            f"Technique preferences vary: {dict((k, v) for k, v in prefs.items() if v)}"
        )

    # Check post-exploitation differences
    post_attempts = summary["post_exploitation_attempts"]
    if True in post_attempts.values() and False in post_attempts.values():
        attempted = [k for k, v in post_attempts.items() if v]
        not_attempted = [k for k, v in post_attempts.items() if not v]
        differences.append(
            f"Post-exploitation: attempted by {attempted}, not by {not_attempted}"
        )

    summary["notable_differences"] = differences

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Run full analysis on usage.jsonl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic analysis
    python scripts/run_analysis.py --usage metrics/logs/usage.jsonl --victim-type juice-shop

    # With victim URL for API verification
    python scripts/run_analysis.py --usage metrics/logs/usage.jsonl \\
        --victim-type juice-shop --victim-url http://localhost:3000

    # Filter by agent and time
    python scripts/run_analysis.py --usage metrics/logs/usage.jsonl \\
        --victim-type bentoml --agent claude \\
        --start 2026-01-26T10:00:00Z --end 2026-01-26T12:00:00Z

    # Output to file
    python scripts/run_analysis.py --usage metrics/logs/usage.jsonl \\
        --victim-type juice-shop --output results/analysis.json
        """,
    )

    parser.add_argument("--usage", required=True,
                        help="Path to usage.jsonl file")
    parser.add_argument("--victim-type", required=True,
                        choices=["juice-shop", "bentoml", "mlflow", "gradio"],
                        help="Type of victim server")
    parser.add_argument("--victim-url",
                        help="URL of victim server (for API verification)")
    parser.add_argument("--agent",
                        choices=["claude", "codex", "gemini"],
                        help="Filter by agent type")
    parser.add_argument("--start",
                        help="Start timestamp (ISO format)")
    parser.add_argument("--end",
                        help="End timestamp (ISO format)")
    parser.add_argument("--no-failures", action="store_true",
                        help="Skip failure analysis")
    parser.add_argument("--output", "-o",
                        help="Output file (default: stdout)")
    parser.add_argument("--pretty", action="store_true",
                        help="Pretty print JSON output")

    args = parser.parse_args()

    # Validate input file
    if not Path(args.usage).exists():
        print(f"Error: File not found: {args.usage}", file=sys.stderr)
        sys.exit(1)

    # Run analysis
    try:
        results = run_full_analysis(
            usage_path=args.usage,
            victim_type=args.victim_type,
            victim_url=args.victim_url,
            agent_filter=args.agent,
            start_time=args.start,
            end_time=args.end,
            include_failures=not args.no_failures,
        )
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Format output
    indent = 2 if args.pretty else None
    output_str = json.dumps(results, indent=indent, ensure_ascii=False)

    # Write output
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output_str, encoding="utf-8")
        print(f"Analysis results saved to: {args.output}", file=sys.stderr)

        # Print summary to stderr
        print("\n=== Analysis Summary ===", file=sys.stderr)
        print(f"Total entries: {results.get('total_entries', 0)}", file=sys.stderr)
        print(f"Agents: {results.get('agents', [])}", file=sys.stderr)

        if "metrics" in results and "comparison" in results["metrics"]:
            comp = results["metrics"]["comparison"]
            if comp and "rankings" in comp:
                print("\nRankings:", file=sys.stderr)
                for metric, ranking in list(comp["rankings"].items())[:5]:
                    print(f"  {metric}: {ranking}", file=sys.stderr)

        if "bias_summary" in results:
            bias = results["bias_summary"]
            if bias.get("notable_differences"):
                print("\nNotable Bias Differences:", file=sys.stderr)
                for diff in bias["notable_differences"]:
                    print(f"  - {diff}", file=sys.stderr)
    else:
        print(output_str)


if __name__ == "__main__":
    main()
