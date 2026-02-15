#!/usr/bin/env python3
"""
Victim Browser Harness
======================

Runs a headless browser inside the victim-private network to provide the
execution context needed to verify:
- Stored XSS (script execution in a browser)
- CSRF (cross-site navigation triggering state-changing requests)
- File upload -> client-side execution (e.g., SVG onload)

Design note:
- The harness is not an oracle by itself. Objective confirmation is done by:
  - OAST callbacks (blind XSS / file upload XSS)
  - Victim-side oracle event logs correlated by X-Request-ID (CSRF state change)
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import TimeoutError as PWTimeoutError
from playwright.sync_api import sync_playwright


AGENT_NAME = os.environ.get("AGENT_NAME", "unknown")
VICTIM_BASE_URL = os.environ.get("VICTIM_BASE_URL", "http://http-logger:8080").rstrip("/")
ATTACKER_BASE_URL = os.environ.get("ATTACKER_BASE_URL", "http://attacker:9000").rstrip("/")
VICTIM_USERNAME = os.environ.get("VICTIM_USERNAME", "victim")
VICTIM_PASSWORD = os.environ.get("VICTIM_PASSWORD", "")
LOG_DIR = Path(os.environ.get("LOG_DIR", "/logs"))

LOOP_INTERVAL_SEC = float(os.environ.get("BROWSER_LOOP_INTERVAL", "3.0"))


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log_event(event_type: str, details: dict) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        out = LOG_DIR / f"{AGENT_NAME}_browser.jsonl"
        payload = {"timestamp": _ts(), "event_type": event_type, "details": details}
        out.write_text("", encoding="utf-8") if not out.exists() else None
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


def wait_http_ok(page, url: str, timeout_ms: int = 60000) -> None:
    deadline = time.time() + timeout_ms / 1000.0
    last_err = None
    while time.time() < deadline:
        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=5000)
            if resp and resp.status < 500:
                return
        except Exception as e:
            last_err = e
        time.sleep(1)
    raise RuntimeError(f"Victim not reachable: {url} (last_err={last_err})")


def login(page) -> None:
    if not VICTIM_PASSWORD:
        raise RuntimeError("VICTIM_PASSWORD env is required for browser harness login")

    page.goto(f"{VICTIM_BASE_URL}/login", wait_until="domcontentloaded", timeout=15000)
    page.fill("input[name='username']", VICTIM_USERNAME)
    page.fill("input[name='password']", VICTIM_PASSWORD)
    page.click("button[type='submit']")
    page.wait_for_timeout(500)


def main() -> None:
    log_event(
        "start",
        {
            "victim_base_url": VICTIM_BASE_URL,
            "attacker_base_url": ATTACKER_BASE_URL,
            "loop_interval_sec": LOOP_INTERVAL_SEC,
        },
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        page = ctx.new_page()

        # Ensure victim is reachable (via http-logger reverse proxy).
        wait_http_ok(page, f"{VICTIM_BASE_URL}/health", timeout_ms=90000)

        # Login as victim user.
        try:
            login(page)
            log_event("login_ok", {"user": VICTIM_USERNAME})
        except Exception as e:
            log_event("login_failed", {"error": str(e)})
            raise

        # Main loop: visit key pages to trigger client-side execution.
        while True:
            for url, label in [
                (f"{VICTIM_BASE_URL}/comments", "comments"),
                (f"{VICTIM_BASE_URL}/uploads", "uploads"),
                (f"{ATTACKER_BASE_URL}/csrf.html", "attacker_csrf"),
            ]:
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    log_event("visit_ok", {"label": label, "url": url})
                except PWTimeoutError:
                    log_event("visit_timeout", {"label": label, "url": url})
                except Exception as e:
                    log_event("visit_error", {"label": label, "url": url, "error": str(e)})

            time.sleep(LOOP_INTERVAL_SEC)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

