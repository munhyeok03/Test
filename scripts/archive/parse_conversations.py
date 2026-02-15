#!/usr/bin/env python3
"""
Vendor-Normalized Conversation Parser
=====================================
Parses usage.jsonl and normalizes vendor-specific message formats
(Claude, Codex, Gemini) into a unified schema for analysis.

Vendor-specific formats:
- Claude: content: [{type: "text"}, {type: "tool_use", name, input}]
- Codex: content: [{type: "input_text"}, {type: "function_call", name, arguments}]
- Gemini: content: "plain string" (tools extracted via regex)
"""
import json
import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Any
from collections import defaultdict

from technique_taxonomy import classify_action, detect_phase, detect_techniques


# =============================================================================
# URL Extraction Patterns
# =============================================================================

URL_PATTERNS = [
    # Full HTTP URLs
    r'https?://[^\s\'"<>\)\]]+',
    # curl commands
    r"curl\s+['\"]?(https?://[^\s'\"]+)",
    r'curl\s+(?:-[a-zA-Z]+\s+)*[\'"]?(https?://[^\s\'"]+)',
    # HTTP methods in logs
    r'(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s]+)',
]

# Victim-related URL filter
VICTIM_URL_PATTERN = re.compile(r'(victim|localhost|127\.0\.0\.1|0\.0\.0\.0)[:\/]', re.IGNORECASE)


def extract_urls(text: str, filter_victim: bool = True) -> list[str]:
    """
    Extract HTTP URLs from text.

    Args:
        text: Text to extract URLs from
        filter_victim: If True, only return victim-related URLs

    Returns:
        List of unique URLs
    """
    urls = set()

    for pattern in URL_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            url = match.strip("'\".,;:)")
            if filter_victim:
                if VICTIM_URL_PATTERN.search(url):
                    urls.add(url)
            else:
                urls.add(url)

    return list(urls)


def extract_endpoints(text: str) -> list[str]:
    """
    Extract API endpoints (paths) from text.

    Args:
        text: Text to extract endpoints from

    Returns:
        List of unique endpoint paths
    """
    endpoints = set()

    # Match paths after victim URLs
    path_pattern = r'(?:victim|localhost)[:\d]*/([^\s\'"<>\)]+)'
    matches = re.findall(path_pattern, text, re.IGNORECASE)
    for match in matches:
        path = "/" + match.strip("'\".,;:)")
        endpoints.add(path)

    # Match paths in HTTP method patterns
    method_pattern = r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/[^\s\'"]+)'
    matches = re.findall(method_pattern, text, re.IGNORECASE)
    for match in matches:
        endpoints.add(match.strip("'\".,;:)"))

    return list(endpoints)


# =============================================================================
# Vendor-Specific Parsers
# =============================================================================

def parse_claude_message(message: dict) -> list[dict]:
    """
    Parse Claude message format.

    Claude format:
    - content: [{type: "text", text: "..."}, {type: "tool_use", name: "Bash", input: {...}}]
    """
    actions = []
    content = message.get("content", [])

    if isinstance(content, str):
        # Simple text message
        actions.append({
            "type": "text_response",
            "content": content,
        })
        return actions

    if not isinstance(content, list):
        return actions

    for block in content:
        if not isinstance(block, dict):
            continue

        block_type = block.get("type", "")

        if block_type == "text":
            text = block.get("text", "")
            if text.strip():
                actions.append({
                    "type": "text_response",
                    "content": text,
                })

        elif block_type == "tool_use":
            tool_name = block.get("name", "unknown")
            tool_input = block.get("input", {})

            action = {
                "type": "tool_call",
                "tool_name": tool_name,
                "tool_input": tool_input,
            }

            # Extract raw command for Bash tool
            if tool_name == "Bash" and isinstance(tool_input, dict):
                action["raw_command"] = tool_input.get("command", "")

            actions.append(action)

        elif block_type == "tool_result":
            tool_use_id = block.get("tool_use_id", "")
            result_content = block.get("content", "")
            actions.append({
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": result_content if isinstance(result_content, str) else str(result_content),
            })

    return actions


def parse_codex_message(message: dict) -> list[dict]:
    """
    Parse Codex/OpenAI message format.

    Codex format:
    - content: [{type: "input_text", text: "..."}, {type: "function_call", name: "...", arguments: "..."}]
    - Or: content: string, function_call: {name: "...", arguments: "..."}
    """
    actions = []
    content = message.get("content", [])

    # Handle function_call at message level (older format)
    if "function_call" in message:
        fc = message["function_call"]
        actions.append({
            "type": "tool_call",
            "tool_name": fc.get("name", "unknown"),
            "tool_input": _parse_json_safe(fc.get("arguments", "{}")),
        })

    # Handle tool_calls at message level (newer format)
    if "tool_calls" in message:
        for tc in message.get("tool_calls", []):
            func = tc.get("function", {})
            actions.append({
                "type": "tool_call",
                "tool_name": func.get("name", "unknown"),
                "tool_input": _parse_json_safe(func.get("arguments", "{}")),
            })

    if isinstance(content, str):
        if content.strip():
            actions.append({
                "type": "text_response",
                "content": content,
            })
        return actions

    if not isinstance(content, list):
        return actions

    for block in content:
        if not isinstance(block, dict):
            if isinstance(block, str) and block.strip():
                actions.append({
                    "type": "text_response",
                    "content": block,
                })
            continue

        block_type = block.get("type", "")

        if block_type in ("input_text", "text"):
            text = block.get("text", "")
            if text.strip():
                actions.append({
                    "type": "text_response",
                    "content": text,
                })

        elif block_type == "function_call":
            tool_name = block.get("name", "unknown")
            arguments = block.get("arguments", "{}")

            action = {
                "type": "tool_call",
                "tool_name": tool_name,
                "tool_input": _parse_json_safe(arguments),
            }

            # Extract command if shell/bash function
            if tool_name.lower() in ("bash", "shell", "exec", "run"):
                inp = action["tool_input"]
                if isinstance(inp, dict):
                    action["raw_command"] = inp.get("command", inp.get("cmd", ""))

            actions.append(action)

    return actions


def parse_gemini_message(message: dict) -> list[dict]:
    """
    Parse Gemini message format.

    Gemini format:
    - content: "plain string" (tools embedded in text or separate field)
    - parts: [{text: "..."}, {functionCall: {name: "...", args: {...}}}]
    """
    actions = []
    content = message.get("content", "")
    parts = message.get("parts", [])

    # Handle parts array (Gemini API response format)
    if parts:
        for part in parts:
            if isinstance(part, dict):
                if "text" in part:
                    actions.append({
                        "type": "text_response",
                        "content": part["text"],
                    })
                if "functionCall" in part:
                    fc = part["functionCall"]
                    action = {
                        "type": "tool_call",
                        "tool_name": fc.get("name", "unknown"),
                        "tool_input": fc.get("args", {}),
                    }
                    if action["tool_name"].lower() in ("bash", "shell", "exec"):
                        args = action["tool_input"]
                        if isinstance(args, dict):
                            action["raw_command"] = args.get("command", args.get("cmd", ""))
                    actions.append(action)
            elif isinstance(part, str):
                actions.append({
                    "type": "text_response",
                    "content": part,
                })
        return actions

    # Handle plain string content
    if isinstance(content, str):
        if content.strip():
            actions.append({
                "type": "text_response",
                "content": content,
            })

            # Try to extract tool calls from text (Gemini sometimes embeds commands)
            command_patterns = [
                r"```(?:bash|shell|sh)\n(.*?)```",
                r"Running:\s*`([^`]+)`",
                r"Executing:\s*`([^`]+)`",
                r"\$ ([^\n]+)",
            ]
            for pattern in command_patterns:
                matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    cmd = match.strip()
                    if cmd:
                        actions.append({
                            "type": "tool_call",
                            "tool_name": "Bash",
                            "tool_input": {"command": cmd},
                            "raw_command": cmd,
                            "extracted_from_text": True,
                        })

    return actions


def _parse_json_safe(s: Any) -> Any:
    """Safely parse JSON string, returning original if fails."""
    if isinstance(s, (dict, list)):
        return s
    if isinstance(s, str):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s
    return s


# =============================================================================
# Agent Detection
# =============================================================================

def detect_agent(entry: dict) -> str:
    """
    Detect agent type from usage.jsonl entry.

    Args:
        entry: Single entry from usage.jsonl

    Returns:
        Agent type: 'claude', 'codex', 'gemini', or 'unknown'
    """
    # Check explicit agent field
    agent = entry.get("agent", "").lower()
    if agent in ("claude", "codex", "gemini"):
        return agent

    # Infer from model name
    model = entry.get("model", "").lower()

    if "claude" in model or "anthropic" in model:
        return "claude"
    elif "gpt" in model or "codex" in model or "openai" in model:
        return "codex"
    elif "gemini" in model or "palm" in model or "google" in model:
        return "gemini"

    # Infer from provider
    provider = entry.get("provider", "").lower()
    if "anthropic" in provider:
        return "claude"
    elif "openai" in provider:
        return "codex"
    elif "google" in provider or "vertex" in provider:
        return "gemini"

    return "unknown"


# =============================================================================
# Main Parser
# =============================================================================

def parse_entry(entry: dict) -> dict:
    """
    Parse a single usage.jsonl entry into normalized format.

    Args:
        entry: Single entry from usage.jsonl

    Returns:
        Normalized entry with actions, endpoints, techniques
    """
    agent = detect_agent(entry)
    timestamp = entry.get("timestamp", "")
    messages = entry.get("messages", [])
    response = entry.get("response", "")

    # Select parser based on agent
    parser_map = {
        "claude": parse_claude_message,
        "codex": parse_codex_message,
        "gemini": parse_gemini_message,
        "unknown": parse_claude_message,  # Default to Claude format
    }
    parser = parser_map.get(agent, parse_claude_message)

    # Parse all messages
    all_actions = []
    for msg in messages:
        if isinstance(msg, dict):
            actions = parser(msg)
            all_actions.extend(actions)

    # Parse response if present
    if response:
        if isinstance(response, str):
            all_actions.append({
                "type": "text_response",
                "content": response,
                "is_final_response": True,
            })
        elif isinstance(response, dict):
            all_actions.extend(parser(response))

    # Extract all text for URL/technique extraction
    all_text = []
    all_commands = []

    for action in all_actions:
        if action.get("type") == "text_response":
            all_text.append(action.get("content", ""))
        elif action.get("type") == "tool_call":
            all_text.append(str(action.get("tool_input", "")))
            if "raw_command" in action:
                all_commands.append(action["raw_command"])
                all_text.append(action["raw_command"])
        elif action.get("type") == "tool_result":
            all_text.append(action.get("content", ""))

    combined_text = "\n".join(all_text)
    combined_commands = "\n".join(all_commands)

    # Extract endpoints and URLs
    endpoints = extract_endpoints(combined_text)
    urls = extract_urls(combined_text)

    # Classify techniques
    classification = classify_action(combined_commands, combined_text)

    return {
        "timestamp": timestamp,
        "agent": agent,
        "model": entry.get("model", ""),
        "actions": all_actions,
        "endpoints_accessed": endpoints,
        "urls_accessed": urls,
        "phase": classification["phase"],
        "techniques_detected": [t["technique"] for t in classification["techniques"]],
        "technique_details": classification["techniques"],
        "metrics": {
            "prompt_tokens": entry.get("prompt_tokens", 0),
            "completion_tokens": entry.get("completion_tokens", 0),
            "total_tokens": entry.get("total_tokens", 0),
            "cost_usd": entry.get("cost_usd", 0.0),
            "latency_ms": entry.get("latency_ms", 0),
        },
    }


def parse_usage_jsonl(
    file_path: str,
    agent_filter: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> list[dict]:
    """
    Parse entire usage.jsonl file.

    Args:
        file_path: Path to usage.jsonl
        agent_filter: Optional agent type to filter ('claude', 'codex', 'gemini')
        start_time: Optional ISO timestamp to filter from
        end_time: Optional ISO timestamp to filter to

    Returns:
        List of parsed entries
    """
    entries = []
    path = Path(file_path)

    if not path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        return entries

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Warning: JSON decode error at line {line_num}: {e}", file=sys.stderr)
                continue

            # Apply time filter
            timestamp = entry.get("timestamp", "")
            if start_time and timestamp < start_time:
                continue
            if end_time and timestamp > end_time:
                continue

            # Apply agent filter
            if agent_filter:
                agent = detect_agent(entry)
                if agent != agent_filter.lower():
                    continue

            parsed = parse_entry(entry)
            parsed["line_number"] = line_num
            entries.append(parsed)

    return entries


def group_by_agent(entries: list[dict]) -> dict[str, list[dict]]:
    """Group parsed entries by agent type."""
    grouped = defaultdict(list)
    for entry in entries:
        agent = entry.get("agent", "unknown")
        grouped[agent].append(entry)
    return dict(grouped)


def assign_turn_ids(entries: list[dict]) -> list[dict]:
    """
    Assign turn IDs to entries, grouped by agent.

    Args:
        entries: List of parsed entries

    Returns:
        Entries with turn_id field added
    """
    agent_counters = defaultdict(int)

    for entry in entries:
        agent = entry.get("agent", "unknown")
        agent_counters[agent] += 1
        entry["turn_id"] = agent_counters[agent]

    return entries


def extract_conversation_summary(entries: list[dict]) -> dict:
    """
    Extract summary statistics from parsed conversations.

    Args:
        entries: List of parsed entries

    Returns:
        Summary dict with statistics
    """
    if not entries:
        return {"error": "No entries to summarize"}

    # Group by agent
    by_agent = group_by_agent(entries)

    summary = {
        "total_entries": len(entries),
        "agents": list(by_agent.keys()),
        "by_agent": {},
    }

    for agent, agent_entries in by_agent.items():
        all_endpoints = set()
        all_techniques = set()
        phase_counts = defaultdict(int)
        technique_counts = defaultdict(int)

        total_tokens = 0
        total_cost = 0.0

        for entry in agent_entries:
            all_endpoints.update(entry.get("endpoints_accessed", []))
            all_techniques.update(entry.get("techniques_detected", []))

            phase = entry.get("phase")
            if phase:
                phase_counts[phase] += 1

            for tech in entry.get("techniques_detected", []):
                technique_counts[tech] += 1

            metrics = entry.get("metrics", {})
            total_tokens += metrics.get("total_tokens", 0)
            total_cost += metrics.get("cost_usd", 0.0)

        # Get timestamps
        timestamps = [e.get("timestamp", "") for e in agent_entries if e.get("timestamp")]
        first_ts = min(timestamps) if timestamps else ""
        last_ts = max(timestamps) if timestamps else ""

        summary["by_agent"][agent] = {
            "entry_count": len(agent_entries),
            "unique_endpoints": len(all_endpoints),
            "unique_techniques": len(all_techniques),
            "endpoints": list(all_endpoints)[:20],  # Limit for readability
            "techniques": list(all_techniques),
            "phase_distribution": dict(phase_counts),
            "technique_counts": dict(technique_counts),
            "total_tokens": total_tokens,
            "total_cost_usd": round(total_cost, 6),
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
        }

    return summary


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Parse usage.jsonl with vendor normalization"
    )
    parser.add_argument("input", help="Path to usage.jsonl file")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--agent", choices=["claude", "codex", "gemini"],
                        help="Filter by agent type")
    parser.add_argument("--start", help="Start timestamp (ISO format)")
    parser.add_argument("--end", help="End timestamp (ISO format)")
    parser.add_argument("--summary", action="store_true",
                        help="Output summary only")
    parser.add_argument("--format", choices=["json", "jsonl"], default="json",
                        help="Output format (default: json)")

    args = parser.parse_args()

    # Parse entries
    entries = parse_usage_jsonl(
        args.input,
        agent_filter=args.agent,
        start_time=args.start,
        end_time=args.end,
    )

    if not entries:
        print("No entries found matching criteria", file=sys.stderr)
        sys.exit(1)

    # Assign turn IDs
    entries = assign_turn_ids(entries)

    # Generate output
    if args.summary:
        output = extract_conversation_summary(entries)
    else:
        output = entries

    # Format output
    if args.format == "jsonl" and not args.summary:
        output_str = "\n".join(json.dumps(e, ensure_ascii=False) for e in output)
    else:
        output_str = json.dumps(output, indent=2, ensure_ascii=False)

    # Write output
    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")
        print(f"Output written to: {args.output}", file=sys.stderr)
    else:
        print(output_str)


if __name__ == "__main__":
    main()
