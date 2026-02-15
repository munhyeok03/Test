"""
mitmproxy addon for logging HTTP traffic to JSONL format.

Usage:
    mitmdump --mode reverse:http://victim:3000 -p 8080 -s http_logger.py

Environment variables:
    AGENT_NAME: Name of the agent (claude, codex, gemini)
    LOG_DIR: Directory to write logs (default: /logs)
"""
from mitmproxy import http
import json
import os
import uuid
from datetime import datetime, timezone


# Configuration from environment
AGENT_NAME = os.environ.get("AGENT_NAME", "unknown")
LOG_DIR = os.environ.get("LOG_DIR", "/logs")


def truncate_body(body: str | None, max_length: int = 50000) -> str | None:
    """Truncate body to max_length characters."""
    if body is None:
        return None
    if len(body) > max_length:
        return body[:max_length] + f"... [truncated, {len(body)} total chars]"
    return body


def safe_decode(content: bytes | None) -> str | None:
    """Safely decode bytes to string, handling binary content."""
    if content is None:
        return None
    try:
        return content.decode("utf-8", errors="replace")
    except Exception:
        return f"[binary data, {len(content)} bytes]"


def _ensure_trace_id(flow: http.HTTPFlow) -> str:
    """
    Attach a per-request trace identifier before forwarding to the victim.

    This enables deterministic correlation across:
    - HTTP request/response logs
    - victim-side oracle logs (when instrumented to read X-Request-ID)
    """
    trace_id = flow.metadata.get("trace_id")
    if trace_id:
        return str(trace_id)

    trace_id = str(uuid.uuid4())
    flow.metadata["trace_id"] = trace_id
    # Use a commonly supported request-id header.
    flow.request.headers["X-Request-ID"] = trace_id
    return trace_id


def request(flow: http.HTTPFlow) -> None:
    """Attach trace id as early as possible (before upstream request)."""
    try:
        _ensure_trace_id(flow)
    except Exception as e:
        import sys
        print(f"[http_logger] Error setting trace id: {e}", file=sys.stderr)


def response(flow: http.HTTPFlow) -> None:
    """Log completed HTTP request/response pairs."""
    try:
        trace_id = _ensure_trace_id(flow)

        # Build request info
        request_body = safe_decode(flow.request.content)
        response_body = safe_decode(flow.response.content) if flow.response else None

        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "agent": AGENT_NAME,
            "trace_id": trace_id,
            "request": {
                "method": flow.request.method,
                "url": flow.request.url,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "body": truncate_body(request_body)
            },
            "response": {
                "status_code": flow.response.status_code if flow.response else None,
                "reason": flow.response.reason if flow.response else None,
                "headers": dict(flow.response.headers) if flow.response else {},
                "body": truncate_body(response_body)
            },
            "duration_ms": round((flow.response.timestamp_end - flow.request.timestamp_start) * 1000, 2) if flow.response else None
        }

        # Write to agent-specific log file
        log_file = os.path.join(LOG_DIR, f"{AGENT_NAME}_http.jsonl")
        os.makedirs(LOG_DIR, exist_ok=True)

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    except Exception as e:
        # Log errors to stderr but don't crash the proxy
        import sys
        print(f"[http_logger] Error logging request: {e}", file=sys.stderr)


def error(flow: http.HTTPFlow) -> None:
    """Log HTTP errors (connection failures, timeouts, etc.)."""
    try:
        trace_id = _ensure_trace_id(flow)

        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "agent": AGENT_NAME,
            "trace_id": trace_id,
            "request": {
                "method": flow.request.method,
                "url": flow.request.url,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "body": truncate_body(safe_decode(flow.request.content))
            },
            "error": str(flow.error) if flow.error else "Unknown error",
            "response": None
        }

        log_file = os.path.join(LOG_DIR, f"{AGENT_NAME}_http.jsonl")
        os.makedirs(LOG_DIR, exist_ok=True)

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    except Exception as e:
        import sys
        print(f"[http_logger] Error logging error: {e}", file=sys.stderr)
