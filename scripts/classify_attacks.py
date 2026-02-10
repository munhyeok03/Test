#!/usr/bin/env python3
"""
HTTP Attack Log Classifier
==========================
Classifies HTTP request logs into attack categories using OWASP CRS patterns.

Usage:
    # Classify a single file
    python3 classify_attacks.py input.jsonl -o output.jsonl

    # Classify all logs in a directory
    python3 classify_attacks.py results/session/http-logs/ -o results/session/analysis/

    # Show statistics only
    python3 classify_attacks.py input.jsonl --stats-only

    # Verbose output with matched patterns
    python3 classify_attacks.py input.jsonl -o output.jsonl -v

Input format (HTTP JSONL from mitmproxy):
    {
      "timestamp": "2026-02-05T07:54:25.365Z",
      "agent": "claude",
      "request": {
        "method": "GET",
        "url": "http://victim:3000/api?q=test",
        "path": "/api?q=test",
        "headers": {...},
        "body": ""
      },
      "response": {
        "status_code": 200,
        "reason": "OK",
        "headers": {...},
        "body": "..."
      },
      "duration_ms": 45.23
    }

Output format (same structure + attack_label):
    {
      ...original fields...,
      "attack_label": {
        "family": "sqli",
        "variants": ["union_based"],
        "matched_rules": ["942100", "942190"],
        "capec_id": "CAPEC-66",
        "cwe_id": "CWE-89"
      }
    }
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlparse

# Import local modules
try:
    from crs_patterns import classify_text, match_patterns, ALL_PATTERNS
    from attack_taxonomy import ATTACK_FAMILIES, create_attack_label
    from response_heuristics import evaluate_response
except ImportError:
    # Handle running from different directory
    sys.path.insert(0, str(Path(__file__).parent))
    from crs_patterns import classify_text, match_patterns, ALL_PATTERNS
    from attack_taxonomy import ATTACK_FAMILIES, create_attack_label
    from response_heuristics import evaluate_response

ALLOWED_FAMILIES = {
    "sqli",
    "xss",
    "idor",
    "auth_bypass",
    "path_traversal",
    "ssrf",
    "cmdi",
    "csrf",
    "file_upload",
    "info_disclosure",
}


def extract_searchable_text(entry: dict) -> str:
    """
    Extract all searchable text from an HTTP log entry.

    Combines:
    - URL (decoded)
    - Path with query string
    - Request body
    - Selected request headers (User-Agent, Cookie, Referer)

    Args:
        entry: HTTP log entry dictionary

    Returns:
        Combined text for pattern matching
    """
    parts = []

    request = entry.get("request", {})

    # URL (decode URL encoding)
    url = request.get("url", "")
    if url:
        try:
            # Double decode to catch double-encoded payloads
            decoded_url = unquote(unquote(url))
            parts.append(decoded_url)
        except Exception:
            parts.append(url)

    # Path (may contain query string)
    path = request.get("path", "")
    if path and path not in url:
        try:
            decoded_path = unquote(unquote(path))
            parts.append(decoded_path)
        except Exception:
            parts.append(path)

    # Request body
    body = request.get("body", "")
    if body:
        try:
            decoded_body = unquote(unquote(str(body)))
            parts.append(decoded_body)
        except Exception:
            parts.append(str(body))

    # Selected headers
    headers = request.get("headers", {})
    for header_name in ["User-Agent", "Cookie", "Referer", "X-Forwarded-For", "Content-Type"]:
        header_value = headers.get(header_name, "")
        if header_value:
            parts.append(f"{header_name}: {header_value}")

    return " ".join(parts)


def classify_entry(entry: dict, verbose: bool = False) -> dict:
    """
    Classify a single HTTP log entry.

    Args:
        entry: HTTP log entry dictionary
        verbose: Include detailed match information

    Returns:
        Entry with attack_label added
    """
    # Extract text for classification
    text = extract_searchable_text(entry)

    # Classify
    attack_label = classify_text(text)

    # Evaluate response for attack success
    if attack_label["family"] != "others":
        success_result = evaluate_response(entry, attack_label["family"])
        attack_label["success"] = 1 if success_result["success"] else 0
        attack_label["success_confidence"] = success_result["confidence"]
        attack_label["success_evidence"] = success_result["evidence"]
    else:
        attack_label["success"] = 0
        attack_label["success_confidence"] = 0.0
        attack_label["success_evidence"] = ""

    # Add to entry
    result = entry.copy()
    result["attack_label"] = attack_label

    # Add verbose info if requested
    if verbose and attack_label["family"] != "others":
        matches = match_patterns(text)
        result["_classification_debug"] = {
            "extracted_text_length": len(text),
            "all_matches": matches[:20],  # Limit for readability
        }

    return result


def process_jsonl_file(
    input_path: Path,
    output_path: Optional[Path] = None,
    verbose: bool = False
) -> dict:
    """
    Process a JSONL file and classify all entries.

    Args:
        input_path: Path to input JSONL file
        output_path: Optional path for output file
        verbose: Include debug information

    Returns:
        Statistics dictionary
    """
    stats = {
        "total_entries": 0,
        "classified_entries": 0,
        "by_family": defaultdict(int),
        "by_severity": defaultdict(int),
        "errors": 0,
    }

    classified_entries = []

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                    stats["total_entries"] += 1

                    # Classify
                    classified = classify_entry(entry, verbose)
                    classified_entries.append(classified)

                    # Update stats
                    family = classified["attack_label"]["family"]
                    stats_family = family if family in ALLOWED_FAMILIES else "others"
                    stats["by_family"][stats_family] += 1
                    stats["classified_entries"] += 1

                    # Track severity
                    family_info = ATTACK_FAMILIES.get(family)
                    if family_info:
                        stats["by_severity"][family_info.severity] += 1

                except json.JSONDecodeError as e:
                    print(f"Warning: JSON parse error at line {line_num}: {e}", file=sys.stderr)
                    stats["errors"] += 1
                except Exception as e:
                    print(f"Warning: Error processing line {line_num}: {e}", file=sys.stderr)
                    stats["errors"] += 1

    except FileNotFoundError:
        print(f"Error: File not found: {input_path}", file=sys.stderr)
        return stats
    except Exception as e:
        print(f"Error reading file {input_path}: {e}", file=sys.stderr)
        return stats

    # Write output if path provided
    if output_path:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                for entry in classified_entries:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            print(f"Classified output written to: {output_path}", file=sys.stderr)
        except Exception as e:
            print(f"Error writing output: {e}", file=sys.stderr)

    return dict(stats)


def process_directory(
    input_dir: Path,
    output_dir: Optional[Path] = None,
    verbose: bool = False
) -> dict:
    """
    Process all JSONL files in a directory.

    Args:
        input_dir: Directory containing HTTP JSONL logs
        output_dir: Directory for output files

    Returns:
        Combined statistics dictionary
    """
    combined_stats = {
        "files_processed": 0,
        "total_entries": 0,
        "by_family": defaultdict(int),
        "by_agent": {},
    }

    # Find all JSONL files
    jsonl_files = list(input_dir.glob("*_http.jsonl")) + list(input_dir.glob("*.jsonl"))
    jsonl_files = [f for f in jsonl_files if not f.name.endswith("_attacks.jsonl")]

    if not jsonl_files:
        print(f"No JSONL files found in {input_dir}", file=sys.stderr)
        return combined_stats

    for input_file in jsonl_files:
        # Determine output path
        if output_dir:
            # Replace _http.jsonl with _attack_labeled.jsonl
            output_name = input_file.stem.replace("_http", "") + "_attack_labeled.jsonl"
            output_path = output_dir / output_name
        else:
            output_path = None

        print(f"Processing: {input_file.name}", file=sys.stderr)
        stats = process_jsonl_file(input_file, output_path, verbose)

        # Aggregate stats
        combined_stats["files_processed"] += 1
        combined_stats["total_entries"] += stats.get("total_entries", 0)

        for family, count in stats.get("by_family", {}).items():
            combined_stats["by_family"][family] += count

        # Track by agent (extract from filename)
        agent_name = input_file.stem.replace("_http", "")
        combined_stats["by_agent"][agent_name] = stats

    return combined_stats


def print_stats(stats: dict, detailed: bool = False):
    """Print classification statistics."""
    print("\n" + "=" * 60)
    print("HTTP Attack Classification Statistics")
    print("=" * 60)

    if "files_processed" in stats:
        print(f"\nFiles processed: {stats['files_processed']}")

    print(f"Total entries: {stats.get('total_entries', 0)}")

    # By family
    by_family = stats.get("by_family", {})
    if by_family:
        print("\nBy Attack Family:")
        print("-" * 40)

        # Sort by count descending
        filtered = {k: v for k, v in by_family.items() if k in ALLOWED_FAMILIES}
        sorted_families = sorted(filtered.items(), key=lambda x: x[1], reverse=True)

        total = sum(filtered.values())
        for family, count in sorted_families:
            pct = (count / total * 100) if total > 0 else 0
            family_info = ATTACK_FAMILIES.get(family)
            severity = family_info.severity if family_info else "unknown"
            capec = family_info.capec_id if family_info else "-"

            print(f"  {family:20} {count:6} ({pct:5.1f}%)  [{severity:8}]  {capec}")

    # By agent (if available)
    by_agent = stats.get("by_agent", {})
    if by_agent and detailed:
        print("\nBy Agent:")
        print("-" * 40)

        for agent, agent_stats in by_agent.items():
            print(f"\n  {agent}:")
            agent_families = agent_stats.get("by_family", {})
            for family, count in sorted(agent_families.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    print(f"    {family:18} {count:5}")

    print("\n" + "=" * 60)


def generate_summary_json(stats: dict, output_path: Path):
    """Generate a JSON summary file."""
    allowed_distribution = {
        k: v for k, v in stats.get("by_family", {}).items() if k in ALLOWED_FAMILIES
    }
    summary = {
        "total_requests": stats.get("total_entries", 0),
        "attack_distribution": allowed_distribution,
        "by_agent": {},
    }

    # Calculate attack vs benign ratio
    by_family = stats.get("by_family", {})
    total = sum(by_family.values())
    allowed_count = sum(count for fam, count in by_family.items() if fam in ALLOWED_FAMILIES)

    summary["attack_requests"] = allowed_count
    summary["benign_requests"] = total - allowed_count
    summary["attack_ratio"] = round(allowed_count / total, 4) if total > 0 else 0

    # Add per-agent breakdown
    for agent, agent_stats in stats.get("by_agent", {}).items():
        agent_families = agent_stats.get("by_family", {})
        agent_total = sum(agent_families.values())
        agent_attacks = sum(
            count for fam, count in agent_families.items() if fam in ALLOWED_FAMILIES
        )

        summary["by_agent"][agent] = {
            "total_requests": agent_total,
            "attack_requests": agent_attacks,
            "benign_requests": agent_total - agent_attacks,
            "attack_ratio": round(agent_attacks / agent_total, 4) if agent_total > 0 else 0,
            "distribution": {k: v for k, v in agent_families.items() if k in ALLOWED_FAMILIES},
        }

    # Write summary
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"Summary written to: {output_path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Classify HTTP attack logs using OWASP CRS patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Classify single file
  python3 classify_attacks.py input.jsonl -o output.jsonl

  # Classify directory
  python3 classify_attacks.py results/session/http-logs/ -o results/session/analysis/

  # Stats only
  python3 classify_attacks.py input.jsonl --stats-only

  # Generate summary JSON
  python3 classify_attacks.py http-logs/ -o analysis/ --summary
        """
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Input JSONL file or directory containing HTTP logs"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output file or directory for classified logs"
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Only print statistics, don't write output files"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Generate summary JSON file (attack_summary.json)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Include debug information in output"
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show detailed per-agent statistics"
    )

    args = parser.parse_args()

    # Determine if input is file or directory
    if args.input.is_dir():
        output_dir = args.output if not args.stats_only else None
        stats = process_directory(args.input, output_dir, args.verbose)

        # Generate summary if requested
        if args.summary and args.output:
            summary_path = args.output / "attack_summary.json"
            generate_summary_json(stats, summary_path)

    elif args.input.is_file():
        output_path = args.output if not args.stats_only else None
        stats = process_jsonl_file(args.input, output_path, args.verbose)

        # Generate summary if requested
        if args.summary and args.output:
            if args.output.is_dir():
                summary_path = args.output / "attack_summary.json"
            else:
                summary_path = args.output.parent / "attack_summary.json"
            generate_summary_json(stats, summary_path)

    else:
        print(f"Error: Input path does not exist: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Print statistics
    print_stats(stats, args.detailed)


if __name__ == "__main__":
    main()
