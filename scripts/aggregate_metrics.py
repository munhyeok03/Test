#!/usr/bin/env python3
"""
LiteLLM 로그에서 메트릭 집계
===========================
LiteLLM 커스텀 로거의 usage.jsonl 파일을 파싱하여 모델별 토큰 사용량 및 호출 통계를 생성합니다.

Usage:
    python3 aggregate_metrics.py <log_dir> [--output <file>]

Input format (usage.jsonl):
    {"timestamp":"...","model":"...","provider":"...","success":true,
     "latency_ms":123.45,"prompt_tokens":100,"completion_tokens":50,
     "total_tokens":150,"cache_read_tokens":0,"cache_creation_tokens":0,"cost_usd":0.01}
"""
import json
import sys
import re
from math import sqrt
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Optional


def _parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO timestamp string to datetime."""
    if not ts:
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    try:
        if "+" in ts:
            ts = ts.split("+")[0]
        elif ts.endswith("Z"):
            ts = ts[:-1]
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _std_dev(values: list[float]) -> float:
    """Calculate standard deviation."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return sqrt(variance)


def parse_usage_jsonl(log_dir: str, start_time: Optional[str] = None, end_time: Optional[str] = None) -> list[dict]:
    """usage.jsonl 파일을 파싱합니다. 시간 범위 필터링 지원."""
    entries = []
    log_path = Path(log_dir)

    # Primary: usage.jsonl from custom logger
    usage_file = log_path / "usage.jsonl"
    if usage_file.exists():
        try:
            content = usage_file.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)

                    # Apply time filtering if specified
                    if start_time or end_time:
                        timestamp = entry.get("timestamp", "")
                        if start_time and timestamp < start_time:
                            continue
                        if end_time and timestamp > end_time:
                            continue

                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"Warning: Error reading {usage_file}: {e}", file=sys.stderr)

    return entries


def parse_proxy_log_fallback(log_dir: str) -> list[dict]:
    """Fallback: proxy.log에서 usage 정보 추출 시도 (이전 형식 호환)."""
    entries = []
    log_path = Path(log_dir)

    # Find proxy log files
    log_files = list(log_path.glob("*_proxy.log")) + list(log_path.glob("*.log"))

    for log_file in log_files:
        if log_file.name == "usage.jsonl":
            continue  # Skip, handled by primary parser

        try:
            content = log_file.read_text(encoding="utf-8", errors="ignore")

            # Try to find JSON objects with usage data
            for line in content.splitlines():
                # Look for litellm response logging patterns
                if '"usage"' in line and '"prompt_tokens"' in line:
                    try:
                        # Try to extract model and usage from various log formats
                        model_match = re.search(r'model["\s:=]+([a-zA-Z0-9\-\._]+)', line)
                        usage_match = re.search(
                            r'"usage"\s*:\s*\{([^}]+)\}', line
                        )

                        if model_match and usage_match:
                            usage_str = "{" + usage_match.group(1) + "}"
                            usage_data = json.loads(usage_str.replace("'", '"'))

                            entries.append({
                                "model": model_match.group(1),
                                "prompt_tokens": usage_data.get("prompt_tokens", 0),
                                "completion_tokens": usage_data.get("completion_tokens", 0),
                                "total_tokens": usage_data.get("total_tokens", 0),
                                "success": True,
                            })
                    except (json.JSONDecodeError, ValueError):
                        continue

        except Exception as e:
            print(f"Warning: Error reading {log_file}: {e}", file=sys.stderr)

    return entries


def aggregate(log_dir: str, start_time: Optional[str] = None, end_time: Optional[str] = None) -> dict:
    """로그 디렉토리에서 메트릭을 집계합니다. 시간 범위 필터링 지원."""
    metrics = defaultdict(lambda: {
        "calls": 0,
        "successful_calls": 0,
        "failed_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cache_read_tokens": 0,
        "cache_creation_tokens": 0,
        "total_cost_usd": 0.0,
        "latency_ms": [],
        "first_call": None,
        "last_call": None,
    })

    log_path = Path(log_dir)
    if not log_path.exists():
        return {"error": f"Log directory not found: {log_dir}", "models": {}}

    # Parse entries from usage.jsonl (primary) with time filtering
    entries = parse_usage_jsonl(log_dir, start_time, end_time)

    # Fallback to proxy log parsing if no entries found
    if not entries:
        print("No usage.jsonl entries found, trying fallback parsing...", file=sys.stderr)
        entries = parse_proxy_log_fallback(log_dir)

    if not entries:
        return {
            "generated_at": datetime.now().isoformat(),
            "log_directory": str(log_path.absolute()),
            "models": {},
            "totals": {
                "total_calls": 0,
                "total_input_tokens": 0,
                "total_output_tokens": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "total_errors": 0,
            },
            "note": "No usage data found in logs",
        }

    # Aggregate metrics by model
    for entry in entries:
        model = entry.get("model", "unknown")
        success = entry.get("success", True)

        metrics[model]["calls"] += 1
        if success:
            metrics[model]["successful_calls"] += 1
        else:
            metrics[model]["failed_calls"] += 1

        metrics[model]["input_tokens"] += entry.get("prompt_tokens") or 0
        metrics[model]["output_tokens"] += entry.get("completion_tokens") or 0
        metrics[model]["total_tokens"] += entry.get("total_tokens") or 0
        metrics[model]["cache_read_tokens"] += entry.get("cache_read_tokens") or 0
        metrics[model]["cache_creation_tokens"] += entry.get("cache_creation_tokens") or 0
        metrics[model]["total_cost_usd"] += entry.get("cost_usd") or 0.0

        # Latency tracking
        latency = entry.get("latency_ms") or 0
        if latency > 0:
            metrics[model]["latency_ms"].append(latency)

        # Timestamp tracking
        timestamp = entry.get("timestamp")
        if timestamp:
            if not metrics[model]["first_call"]:
                metrics[model]["first_call"] = timestamp
            metrics[model]["last_call"] = timestamp

    # Calculate final statistics
    result = {
        "generated_at": datetime.now().isoformat(),
        "log_directory": str(log_path.absolute()),
        "models": {},
    }

    for model, data in metrics.items():
        latencies = data["latency_ms"]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        min_latency = min(latencies) if latencies else 0
        max_latency = max(latencies) if latencies else 0
        p50_latency = sorted(latencies)[len(latencies) // 2] if latencies else 0
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) >= 20 else max_latency

        # === NEW: Additional metrics (P0 enhancements) ===
        # Wall clock duration
        wall_clock_seconds = None
        if data["first_call"] and data["last_call"]:
            try:
                first_dt = _parse_timestamp(data["first_call"])
                last_dt = _parse_timestamp(data["last_call"])
                if first_dt and last_dt:
                    wall_clock_seconds = (last_dt - first_dt).total_seconds()
            except Exception:
                pass

        # Tokens per call statistics
        tokens_per_call = []
        for entry in entries:
            if entry.get("model") == model:
                tokens = entry.get("total_tokens", 0)
                if tokens > 0:
                    tokens_per_call.append(tokens)

        tokens_per_call_avg = sum(tokens_per_call) / len(tokens_per_call) if tokens_per_call else 0
        tokens_per_call_std = _std_dev(tokens_per_call) if len(tokens_per_call) > 1 else 0

        # Cost efficiency (cost per 1M tokens)
        cost_efficiency = None
        if data["total_tokens"] > 0:
            cost_efficiency = (data["total_cost_usd"] / data["total_tokens"]) * 1_000_000

        # Cache hit ratio (Claude-specific)
        cache_hit_ratio = None
        if data["input_tokens"] > 0 and data["cache_read_tokens"] > 0:
            cache_hit_ratio = data["cache_read_tokens"] / data["input_tokens"]

        result["models"][model] = {
            "calls": data["calls"],
            "successful_calls": data["successful_calls"],
            "failed_calls": data["failed_calls"],
            "input_tokens": data["input_tokens"],
            "output_tokens": data["output_tokens"],
            "total_tokens": data["total_tokens"],
            "cache_read_tokens": data["cache_read_tokens"],
            "cache_creation_tokens": data["cache_creation_tokens"],
            "total_cost_usd": round(data["total_cost_usd"], 6),
            "avg_latency_ms": round(avg_latency, 2),
            "min_latency_ms": round(min_latency, 2),
            "max_latency_ms": round(max_latency, 2),
            "p50_latency_ms": round(p50_latency, 2),
            "p95_latency_ms": round(p95_latency, 2),
            "first_call": data["first_call"],
            "last_call": data["last_call"],
            # NEW metrics
            "wall_clock_seconds": round(wall_clock_seconds, 2) if wall_clock_seconds else None,
            "tokens_per_call_avg": round(tokens_per_call_avg, 2),
            "tokens_per_call_std": round(tokens_per_call_std, 2),
            "cost_per_million_tokens": round(cost_efficiency, 4) if cost_efficiency else None,
            "cache_hit_ratio": round(cache_hit_ratio, 4) if cache_hit_ratio else None,
        }

    # Calculate totals
    result["totals"] = {
        "total_calls": sum(m["calls"] for m in result["models"].values()),
        "total_successful_calls": sum(m["successful_calls"] for m in result["models"].values()),
        "total_failed_calls": sum(m["failed_calls"] for m in result["models"].values()),
        "total_input_tokens": sum(m["input_tokens"] for m in result["models"].values()),
        "total_output_tokens": sum(m["output_tokens"] for m in result["models"].values()),
        "total_tokens": sum(m["total_tokens"] for m in result["models"].values()),
        "total_cost_usd": round(sum(m["total_cost_usd"] for m in result["models"].values()), 6),
    }

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: aggregate_metrics.py <log_dir> [--output <file>] [--start <timestamp>] [--end <timestamp>]", file=sys.stderr)
        print("Example: aggregate_metrics.py ./metrics/logs/", file=sys.stderr)
        print("Example: aggregate_metrics.py ./metrics/logs/ --start 2026-01-26T10:00:00Z --end 2026-01-26T11:00:00Z", file=sys.stderr)
        sys.exit(1)

    log_dir = sys.argv[1]
    output_file = None
    start_time = None
    end_time = None

    # Parse --output flag
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_file = sys.argv[idx + 1]

    # Parse --start flag
    if "--start" in sys.argv:
        idx = sys.argv.index("--start")
        if idx + 1 < len(sys.argv):
            start_time = sys.argv[idx + 1]

    # Parse --end flag
    if "--end" in sys.argv:
        idx = sys.argv.index("--end")
        if idx + 1 < len(sys.argv):
            end_time = sys.argv[idx + 1]

    result = aggregate(log_dir, start_time, end_time)
    output = json.dumps(result, indent=2, ensure_ascii=False)

    if output_file:
        Path(output_file).write_text(output, encoding="utf-8")
        print(f"Metrics saved to: {output_file}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
