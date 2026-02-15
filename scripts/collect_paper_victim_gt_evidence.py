#!/usr/bin/env python3
"""
Collect paper-victim ground-truth-mapped evidence for post-experiment tables.

Outputs:
  - A JSON file with per-rule/per-agent attempt/success status.
  - A Markdown file containing ready-to-insert tables for papers/appendices.
"""

from __future__ import annotations

import argparse
import json
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


PAPER_VICTIM_GT_PATH = (
    Path(__file__).resolve().parent.parent
    / "victims"
    / "paper-victim"
    / "ground_truth_manifest.json"
)


def _load_json(path: Path, default=None):
    if default is None:
        default = {}
    if not path.exists():
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _manifest_snapshot(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"exists": False, "path": str(path), "sha256": None}

    try:
        data = path.read_bytes()
        return {
            "exists": True,
            "path": str(path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        }
    except Exception:
        return {"exists": False, "path": str(path), "sha256": None}


def _load_jsonl_lines(path: Path):
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line_num, raw_line in enumerate(f, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                yield json.loads(raw_line)
            except json.JSONDecodeError:
                print(f"Warning: malformed JSON in {path}:{raw_line_num}")


def _extract_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (int, float, bool)):
        return str(v)
    return str(v)


def _md_escape(v: Any) -> str:
    t = _extract_text(v).replace("\n", " ")
    return t.replace("|", "\\|")


def _rule_id_for_entry(entry: Dict[str, Any], family: str) -> str:
    gt = (entry.get("ground_truth") or {})
    rule_id = str(gt.get("rule_id") or "").strip()
    if rule_id:
        return rule_id
    return f"{family}:unmapped"


def _collect_attempts(analysis_dir: Path) -> Dict[str, Dict[str, Dict[str, int]]]:
    attempts: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(lambda: defaultdict(int))
    for path in sorted(analysis_dir.glob("*_attack_labeled.jsonl")):
        agent = path.stem.replace("_attack_labeled", "")
        for entry in _load_jsonl_lines(path):
            attack_label = entry.get("attack_label", {}) or {}
            family = str(attack_label.get("family") or "")
            if not family or family == "others":
                continue
            rule_id = _rule_id_for_entry(attack_label, family)
            attempts[agent][rule_id] += 1
    return attempts


def _collect_vuln_by_rule(vuln_data: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    by_agent: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for agent, data in (vuln_data.get("by_agent") or {}).items():
        by_rule = data.get("by_rule") or {}
        if not isinstance(by_rule, dict):
            by_rule = {}
        agent_rules: Dict[str, Dict[str, Any]] = {}
        for rule_id, info in by_rule.items():
            if not isinstance(info, dict):
                continue
            agent_rules[str(rule_id)] = {
                "attempted_total": int(info.get("attempted_total") or 0),
                "attempted_verifiable": int(info.get("attempted_verifiable") or 0),
                "attempted": int(info.get("attempted") or 0),
                "succeeded": int(info.get("succeeded") or 0),
                "context_required": int(info.get("context_required") or 0),
                "asr": float(info.get("asr") or 0.0),
                "status_counts": (info.get("status_counts") or {}),
                "failure_reason_counts": (info.get("failure_reason_counts") or {}),
                "oracle_used": (info.get("oracle_used") or {}),
            }
        by_agent[str(agent)] = agent_rules
    return by_agent


def _collect_vuln_totals(vuln_data: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    summary: Dict[str, Dict[str, int]] = {}
    for agent, data in (vuln_data.get("by_agent") or {}).items():
        if not isinstance(data, dict):
            continue
        by_family = (data.get("by_family") or {})
        attempted_verified = 0
        if isinstance(by_family, dict):
            for fam in by_family.values():
                if isinstance(fam, dict):
                    attempted_verified += int(fam.get("attempted_verifiable") or 0)

        summary[str(agent)] = {
            "attempted": int(
                data.get("total_attack_requests_raw") or data.get("total_attack_requests") or 0
            ),
            "solved": int(data.get("solved_challenges") or data.get("successful_attacks") or 0),
            "context_required": int(data.get("context_required_attacks") or 0),
            "attempted_verified": int(attempted_verified),
            "unmapped_rule_attempts": int(data.get("unmapped_rule_attempts") or 0),
            "verification_status_counts": (data.get("verification") or {}).get("status_counts") or {},
            "verification_failure_reasons": (data.get("verification") or {}).get("failure_reason_counts") or {},
        }

        # Keep backward compatibility for older payloads.
        if summary[str(agent)]["attempted_verified"] == 0:
            summary[str(agent)]["attempted_verified"] = int(data.get("attempted_verifiable") or 0)
    return summary


def _build_rule_records(
    manifest: Dict[str, Any],
    attempts: Dict[str, Dict[str, int]],
    vuln_by_rule: Dict[str, Dict[str, Dict[str, Any]]],
    agent_order: List[str],
) -> List[Dict[str, Any]]:
    rules = manifest.get("endpoint_rules") or []
    rule_order: List[str] = []
    rule_by_id: Dict[str, Dict[str, Any]] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_id = str(rule.get("item_id") or "").strip()
        if not rule_id:
            continue
        rule_order.append(rule_id)
        rule_by_id[rule_id] = rule

    # Preserve unmapped attempts as a synthetic line for traceability.
    unmapped_rules = set()
    for agent_counts in attempts.values():
        for rule_id in agent_counts.keys():
            if rule_id not in rule_by_id and rule_id.endswith(":unmapped"):
                unmapped_rules.add(rule_id)
    for rid in sorted(unmapped_rules):
        rule_order.append(rid)
        rule_by_id[rid] = {
            "item_id": rid,
            "path": "",
            "match": "",
            "methods": [],
            "family": "unmapped",
            "oracle_type": "unmapped",
            "taxonomy": {},
            "source": {"name": "unmapped", "rationale": "not mapped in manifest"},
        }
    for rule_set in vuln_by_rule.values():
        for rid in rule_set.keys():
            if rid in rule_by_id:
                continue
            rule_order.append(rid)
            rule_by_id[rid] = {
                "item_id": rid,
                "path": "",
                "match": "",
                "methods": [],
                "family": "unmapped",
                "oracle_type": "unmapped",
                "taxonomy": {},
                "source": {"name": "unmapped", "rationale": "not in manifest"},
            }

    records: List[Dict[str, Any]] = []
    for rid in rule_order:
        rule = rule_by_id[rid]
        taxonomy = rule.get("taxonomy") or {}
        source = rule.get("source") or {}
        ref = {
            "name": source.get("name") or "",
            "rationale": source.get("rationale") or "",
            "links": [],
        }
        if isinstance(source.get("links"), list):
            ref["links"] = source["links"]
        elif isinstance(manifest.get("reference_links"), list):
            ref["links"] = manifest.get("reference_links", [])

        per_agent: Dict[str, Dict[str, Any]] = {}
        total_attempted = 0
        total_succeeded = 0

        for agent in agent_order:
            attempted = int(attempts.get(agent, {}).get(rid, 0))
            by_rule = vuln_by_rule.get(agent, {}).get(rid, {})
            succeeded = int(by_rule.get("succeeded", 0))

            # No per-rule verifier data in older payloads -> keep attempted from logs and
            # solved=0 (conservative; prevents false positives in table exports).
            if succeeded > attempted:
                succeeded = attempted

            asr = (succeeded / attempted) if attempted > 0 else 0.0
            total_attempted += attempted
            total_succeeded += succeeded
            per_agent[agent] = {
                "attempted": attempted,
                "succeeded": succeeded,
                "asr": round(asr, 3),
                "match": "verified" if by_rule else "unverified",
                "status_counts": by_rule.get("status_counts", {}),
                "failure_reasons": by_rule.get("failure_reason_counts", {}),
                "oracle_used": by_rule.get("oracle_used", {}),
            }

        records.append(
            {
                "rule_id": rid,
                "family": str(rule.get("family") or ""),
                "path": str(rule.get("path") or ""),
                "match": str(rule.get("match") or ""),
                "methods": rule.get("methods") or [],
                "oracle_type": str(rule.get("oracle_type") or ""),
                "taxonomy": {
                    "cwe": taxonomy.get("cwe") if isinstance(taxonomy, dict) else None,
                    "capec": taxonomy.get("capec") if isinstance(taxonomy, dict) else None,
                    "wstg": taxonomy.get("wstg") if isinstance(taxonomy, dict) else None,
                },
                "reference": ref,
                "summary": {
                    "attempted": total_attempted,
                    "succeeded": total_succeeded,
                    "asr": round((total_succeeded / total_attempted) if total_attempted > 0 else 0.0, 3),
                },
                "by_agent": per_agent,
            }
        )
    return records


def _build_markdown(records: List[Dict[str, Any]], manifest: Dict[str, Any], agent_order: List[str], session: str) -> str:
    version = _extract_text(manifest.get("version"))
    source_links = manifest.get("source", {}).get("links") if isinstance(manifest.get("source"), dict) else None
    if not isinstance(source_links, list):
        source_links = []
    manifest_hash = _extract_text(manifest.get("snapshot", {}).get("sha256"))

    lines: List[str] = []
    lines.append("# paper-victim Ground-Truth Evidence (Session: " + session + ")")
    lines.append("")
    lines.append(f"- Manifest version: {version}")
    if manifest_hash:
        lines.append(f"- Manifest SHA256: `{manifest_hash}`")
    if source_links:
        lines.append("- Baseline references: " + ", ".join(_extract_text(x) for x in source_links))
    lines.append("")
    lines.append("## Rule catalogue and outcomes")
    lines.append("")
    header = "| Rule ID | Family | Path | Oracle | CWE | CAPEC | WSTG |"
    sep = "| --- | --- | --- | --- | --- | --- | --- |"
    lines.append(header)
    lines.append(sep)
    for row in records:
        taxonomy = row.get("taxonomy") or {}
        lines.append(
            "| "
            + " | ".join(
                [
                    _md_escape(row["rule_id"]),
                    _md_escape(row["family"]),
                    _md_escape(row["path"]),
                    _md_escape(row["oracle_type"]),
                    _md_escape(taxonomy.get("cwe")),
                    _md_escape(taxonomy.get("capec")),
                    _md_escape(taxonomy.get("wstg")),
                ]
            )
            + " |"
        )

    lines.append("")
    lines.append("## Per-agent attempt/success table")
    lines.append("")

    lines.append("| Rule ID | Family | " + " | ".join(
        [f"{a} Attempts | {a} Success | {a} ASR | {a} Verified" for a in agent_order]
    ) + " |")
    lines.append("| " + " | ".join(["---"] * (2 + (len(agent_order) * 4))) + " |")
    for row in records:
        cols = [_md_escape(row["rule_id"]), _md_escape(row["family"])]
        for agent in agent_order:
            stats = (row["by_agent"] or {}).get(agent, {})
            cols.append(_md_escape(stats.get("attempted", 0)))
            cols.append(_md_escape(stats.get("succeeded", 0)))
            cols.append(_md_escape(stats.get("asr", 0.0)))
            cols.append(_md_escape(stats.get("match", "")))
        lines.append("| " + " | ".join(cols) + " |")

    lines.append("")
    lines.append("## Rule summary")
    lines.append("| Rule ID | Total Attempts | Total Success | ASR |")
    lines.append("| --- | --- | --- | --- |")
    for row in records:
        lines.append(
            f"| {_md_escape(row['rule_id'])} | "
            f"{_md_escape(row['summary']['attempted'])} | "
            f"{_md_escape(row['summary']['succeeded'])} | "
            f"{_md_escape(row['summary']['asr'])} |"
        )
    lines.append("")
    return "\n".join(lines)


def collect(session_dir: Path, output_json: Optional[Path], output_md: Optional[Path]) -> Dict[str, Any]:
    analysis_dir = session_dir / "analysis"
    vuln_path = analysis_dir / "vulnerability_results.json"
    manifest = _load_json(PAPER_VICTIM_GT_PATH, {})
    manifest_snapshot = _manifest_snapshot(PAPER_VICTIM_GT_PATH)
    attempts = _collect_attempts(analysis_dir)
    vuln_data = _load_json(vuln_path, {})
    vuln_by_rule = _collect_vuln_by_rule(vuln_data)
    agent_order = sorted(set(list(attempts.keys()) + list(vuln_by_rule.keys())))
    rule_records = _build_rule_records(manifest, attempts, vuln_by_rule, agent_order)

    agent_summary = _collect_vuln_totals(vuln_data)
    for agent, a in sorted(attempts.items()):
        if agent not in agent_summary:
            agent_summary[agent] = {"attempted": 0, "solved": 0, "context_required": 0, "attempted_verified": 0}
        agent_summary[agent]["attempted"] = max(
            agent_summary[agent]["attempted"],
            sum(a.values()),
        )
        agent_summary[agent]["rules_matched"] = sum(1 for _r, cnt in a.items() if cnt > 0)

    # Include per-session GT provenance and coverage checks for reproducibility.
    mapped_rules = set(str(r.get("item_id") or "").strip() for r in manifest.get("endpoint_rules", []) if isinstance(r, dict))
    attempted_rules = {rid for agent_attempts in attempts.values() for rid in agent_attempts.keys()}
    unmapped_rules = {rid for rid in attempted_rules if rid not in mapped_rules and rid.endswith(":unmapped")}

    manifest_coverage = {
        "manifest_rules": len(mapped_rules),
        "attempted_rules": len(attempted_rules),
        "unmapped_rules": sorted(unmapped_rules),
        "has_unmapped_rules": len(unmapped_rules) > 0,
    }

    result: Dict[str, Any] = {
        "session": session_dir.name,
        "victim_type": "paper-victim",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifest": {
            "version": manifest.get("version"),
            "victim": manifest.get("victim"),
            "notes": manifest.get("notes"),
            "source": manifest.get("source"),
            "reference_links": manifest.get("reference_links") or [],
            "snapshot": manifest_snapshot,
        },
        "coverage": manifest_coverage,
        "agents": agent_summary,
        "rules": rule_records,
    }

    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    if output_md:
        md = _build_markdown(rule_records, manifest, agent_order, session_dir.name)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        with open(output_md, "w", encoding="utf-8") as f:
            f.write(md + "\n")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect paper-victim GT evidence for downstream analysis tables."
    )
    parser.add_argument("session_dir", type=Path, help="Session directory (e.g., results/20260215_123456)")
    parser.add_argument("--output-json", type=Path, help="Output JSON path", required=False)
    parser.add_argument("--output-markdown", type=Path, help="Output markdown path", required=False)

    args = parser.parse_args()
    if not args.session_dir.exists():
        raise SystemExit(f"Session directory not found: {args.session_dir}")

    collect(args.session_dir, args.output_json, args.output_markdown)


if __name__ == "__main__":
    main()
