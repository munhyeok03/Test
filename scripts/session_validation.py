#!/usr/bin/env python3
"""
Generate run-session integrity report for downstream reproducibility checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Set


KNOWN_ORACLE_CHANNELS = {"canary", "oast", "response", "victim_oracle", "browser"}
TARGET_FAMILIES = {
    "sqli",
    "xss",
    "cmdi",
    "path_traversal",
    "auth_bypass",
    "idor",
    "ssrf",
    "csrf",
    "file_upload",
    "info_disclosure",
}
MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent
    / "victims"
    / "paper-victim"
    / "ground_truth_manifest.json"
)


def _read_json(path: Path, default=None):
    if default is None:
        default = {}
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _iter_jsonl(path: Path):
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line_num, raw_line in enumerate(f, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                yield raw_line_num, json.loads(raw_line)
            except json.JSONDecodeError:
                continue


def _count_jsonl_lines(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                total += 1
    return total


def _hash_file(path: Path) -> str:
    if not path.exists():
        return ""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _parse_oracle_tokens(oracle_type: str) -> Set[str]:
    tokens: Set[str] = set()
    raw = str(oracle_type or "").strip().lower().replace("-", "_").replace("victim_oracle", "__victim_oracle__")
    for token in raw.split("_or_"):
        token = str(token).strip().replace("__victim_oracle__", "victim_oracle")
        if token and token in KNOWN_ORACLE_CHANNELS:
            tokens.add(token)
    return tokens


def _build_oracle_requirements(agent_data: Dict[str, Any]) -> Set[str]:
    by_rule = (agent_data or {}).get("by_rule") or {}
    required: Set[str] = set()
    for rule_data in by_rule.values():
        if not isinstance(rule_data, dict):
            continue
        if int(rule_data.get("attempted", 0) or 0) <= 0:
            continue
        required.update(_parse_oracle_tokens(str(rule_data.get("oracle_type") or "")))
    return required


def _collect_http_headers(session_dir: Path) -> Dict[str, Any]:
    report: Dict[str, Any] = {}
    http_dir = session_dir / "http-logs"
    if not http_dir.exists():
        return report
    for path in sorted(http_dir.glob("*_http.jsonl")):
        agent = path.stem.replace("_http", "")
        sample_total = 0
        with_trace_id = 0
        with_xrid = 0
        with_version = 0
        for _, entry in _iter_jsonl(path):
            sample_total += 1
            if sample_total >= 20:
                break
            if entry.get("trace_id"):
                with_trace_id += 1
            if entry.get("logger_version"):
                with_version += 1
            headers = (entry.get("request") or {}).get("headers") or {}
            if ("X-Request-ID" in headers) or ("X-Request-Id" in headers):
                with_xrid += 1
        report[agent] = {
            "sampled": sample_total,
            "with_trace_id": with_trace_id,
            "with_x_request_id_header": with_xrid,
            "with_logger_version": with_version,
        }
    return report


def _load_manifest_rules(path: Path) -> Set[str]:
    data = _read_json(path, {})
    if not isinstance(data, dict):
        return set()

    rules = set()
    for rule in data.get("endpoint_rules") or []:
        if not isinstance(rule, dict):
            continue
        item_id = str(rule.get("item_id") or "").strip()
        if item_id:
            rules.add(item_id)
    return rules


def _collect_attack_label_audit(analysis_dir: Path, manifest_rules: Set[str]) -> Dict[str, Any]:
    """Check attack_label consistency against GT families and manifest rule IDs."""
    by_file: Dict[str, Any] = {}
    by_family = defaultdict(int)
    totals = {
        "attack_requests": 0,
        "out_of_scope_requests": 0,
        "unknown_family": 0,
        "missing_rule_id": 0,
        "unmapped_rule_id": 0,
    }

    for path in sorted(analysis_dir.glob("*_attack_labeled.jsonl")):
        agent = path.stem.replace("_attack_labeled", "")
        families = defaultdict(int)
        agent_totals = {
            "attack_requests": 0,
            "out_of_scope_requests": 0,
            "unknown_family": 0,
            "missing_rule_id": 0,
            "unmapped_rule_id": 0,
            "families": {},
        }

        for _line_no, entry in _iter_jsonl(path):
            attack_label = entry.get("attack_label") or {}
            family = str(attack_label.get("family") or "").strip() or "others"

            if family == "others":
                agent_totals["out_of_scope_requests"] += 1
                totals["out_of_scope_requests"] += 1
                continue

            if family not in TARGET_FAMILIES:
                agent_totals["unknown_family"] += 1
                totals["unknown_family"] += 1
                continue

            agent_totals["attack_requests"] += 1
            totals["attack_requests"] += 1
            families[family] += 1
            by_family[family] += 1

            gt = attack_label.get("ground_truth") or {}
            rule_id = str(gt.get("rule_id") or "").strip()
            if not rule_id:
                agent_totals["missing_rule_id"] += 1
                totals["missing_rule_id"] += 1
                continue
            if manifest_rules and rule_id not in manifest_rules:
                agent_totals["unmapped_rule_id"] += 1
                totals["unmapped_rule_id"] += 1

        agent_totals["families"] = dict(families)
        by_file[agent] = agent_totals

    return {
        "files": by_file,
        "totals": totals,
        "families": dict(by_family),
    }


def _collect_oracle_audit(session_dir: Path, vuln_by_agent: Dict[str, Any]) -> Dict[str, Any]:
    oracle_dir = session_dir / "oracles"
    report: Dict[str, Any] = {}
    for agent, agent_vuln in vuln_by_agent.items():
        required_channels = _build_oracle_requirements(agent_vuln)
        oast_path = oracle_dir / f"{agent}_oast.jsonl"
        victim_oracle_path = oracle_dir / f"{agent}_victim_oracle.jsonl"
        browser_path = oracle_dir / f"{agent}_browser.jsonl"

        oracle_info = {
            "required_channels": sorted(required_channels),
            "actual_files": {},
        }

        files = {
            "oast": oast_path,
            "victim_oracle": victim_oracle_path,
            "browser": browser_path,
        }
        for key, p in files.items():
            oracle_info["actual_files"][key] = {
                "exists": p.exists(),
                "lines": _count_jsonl_lines(p) if p.exists() else 0,
            }

        missing = []
        if "oast" in required_channels and not oracle_info["actual_files"]["oast"]["lines"]:
            missing.append("oast")
        if "victim_oracle" in required_channels and not oracle_info["actual_files"]["victim_oracle"]["lines"]:
            missing.append("victim_oracle")
        if "browser" in required_channels and not oracle_info["actual_files"]["browser"]["lines"]:
            missing.append("browser")
        if missing:
            oracle_info["required_missing"] = sorted(missing)
        else:
            oracle_info["required_missing"] = []
        report[agent] = oracle_info
    return report


def _collect_attack_summary(session_dir: Path) -> Dict[str, Any]:
    summary_path = session_dir / "analysis" / "attack_summary.json"
    summary = _read_json(summary_path, {})
    if not summary:
        return {"present": False}
    total_by_agents = 0
    by_agent = summary.get("by_agent") or {}
    for agent_data in by_agent.values():
        if isinstance(agent_data, dict):
            total_by_agents += int(agent_data.get("total_requests", 0) or 0)
    return {
        "present": True,
        "total_requests": int(summary.get("total_requests", 0) or 0),
        "sum_by_agent_total_requests": total_by_agents,
        "consistent": total_by_agents == int(summary.get("total_requests", 0) or 0) or not by_agent,
        "by_agent": list(by_agent.keys()),
    }


def _collect_vulnerability_results(session_dir: Path) -> Dict[str, Any]:
    vr_path = session_dir / "analysis" / "vulnerability_results.json"
    vr = _read_json(vr_path, {})
    if not vr:
        return {"present": False}
    by_agent = vr.get("by_agent") or {}
    return {
        "present": True,
        "agents": sorted(by_agent.keys()),
        "oracle_keys_present": {a: bool((data or {}).get("oracle")) for a, data in by_agent.items()},
        "per_agent": by_agent,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate session validation report for one run.")
    parser.add_argument("session_dir", type=Path, help="results/<session_timestamp>")
    parser.add_argument("--victim", default="", help="victim type for manifest checks")
    args = parser.parse_args()

    session_dir = args.session_dir
    if not session_dir.exists():
        raise SystemExit(f"Session directory not found: {session_dir}")

    analysis_dir = session_dir / "analysis"
    manifest = _read_json(MANIFEST_PATH, {})
    manifest_rules = _load_manifest_rules(MANIFEST_PATH) if isinstance(manifest, dict) else set()
    report: Dict[str, Any] = {
        "session": session_dir.name,
        "session_dir": str(session_dir),
        "victim_type": args.victim or "unknown",
        "http_logs": _collect_http_headers(session_dir),
        "attack_label_audit": _collect_attack_label_audit(analysis_dir, manifest_rules),
    }

    report["attack_summary"] = _collect_attack_summary(session_dir)
    vr = _collect_vulnerability_results(session_dir)
    report["vulnerability_results"] = vr

    report["paper_victim_manifest"] = {
        "path": str(MANIFEST_PATH),
        "exists": MANIFEST_PATH.exists(),
    }
    if MANIFEST_PATH.exists():
        report["paper_victim_manifest"].update(
            {
                "sha256": _hash_file(MANIFEST_PATH),
                "rule_count": len(manifest_rules),
                "version": manifest.get("version"),
            }
        )

    gt_evidence_path = analysis_dir / "paper_victim_ground_truth_evidence.json"
    report["paper_victim_ground_truth_evidence"] = {
        "present": gt_evidence_path.exists(),
        "size_bytes": gt_evidence_path.stat().st_size if gt_evidence_path.exists() else 0,
    }

    by_agent = (vr.get("per_agent", {}) if isinstance(vr, dict) else {})
    report["oracle_validation"] = _collect_oracle_audit(session_dir, by_agent)

    checks: list[str] = []
    if not report["attack_summary"].get("present", False):
        checks.append("attack_summary_missing")
    if not vr.get("present"):
        checks.append("vulnerability_results_missing")
    if args.victim == "paper-victim" and not report["paper_victim_manifest"]["exists"]:
        checks.append("paper_victim_manifest_missing")
    if args.victim == "paper-victim" and not report["paper_victim_ground_truth_evidence"]["present"]:
        checks.append("paper_victim_ground_truth_evidence_missing")

    # paper-victim relies on an always-on browser harness to provide execution context for
    # stored XSS / CSRF / client-side file upload validation. The browser harness should
    # emit at least a startup event to `<session>/oracles/<agent>_browser.jsonl`.
    if args.victim == "paper-victim":
        oracle_dir = session_dir / "oracles"
        agents_seen = sorted(
            set(list((report.get("http_logs") or {}).keys()) + list((report.get("attack_label_audit") or {}).get("files", {}).keys()))
        )
        for agent in agents_seen:
            p = oracle_dir / f"{agent}_browser.jsonl"
            if (not p.exists()) or (_count_jsonl_lines(p) <= 0):
                checks.append(f"paper_victim_browser_log_missing:{agent}")

    audit_totals = report["attack_label_audit"]["totals"]
    if args.victim == "paper-victim":
        if int(audit_totals.get("missing_rule_id", 0) or 0) > 0:
            checks.append("paper_victim_attack_label_missing_rule_id")
        if int(audit_totals.get("unmapped_rule_id", 0) or 0) > 0:
            checks.append("paper_victim_attack_label_unmapped_rule_id")

    report["validation_checks"] = {
        "status": "ok" if not checks else "warn",
        "issues": checks,
        "count": len(checks),
    }

    out_path = analysis_dir / "session_validation.json"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[validation] wrote {out_path}")


if __name__ == "__main__":
    main()
