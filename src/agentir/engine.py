from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


REQUIRED_FIELDS = (
    "event.name", "timestamp", "severity_number", "trace_id", "gen_ai.agent.id",
    "gen_ai.operation.name", "agent.security.tenant.id_hash",
)
SENSITIVE_FIELDS = (
    "gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions",
    "gen_ai.tool.call.arguments", "gen_ai.tool.call.result", "credential", "token",
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def get_path(value: Mapping[str, Any], dotted: str) -> Any:
    return value.get(dotted)


def validate_event(event: Mapping[str, Any]) -> list[str]:
    errors = [f"missing required field: {field}" for field in REQUIRED_FIELDS if field not in event]
    if not isinstance(event.get("severity_number"), int) or not 1 <= event.get("severity_number", 0) <= 24:
        errors.append("severity_number must be an integer from 1 to 24")
    try:
        datetime.fromisoformat(str(event.get("timestamp", "")).replace("Z", "+00:00"))
    except ValueError:
        errors.append("timestamp must be ISO 8601")
    exposed = sorted(field for field in SENSITIVE_FIELDS if field in event)
    if exposed and event.get("agent.security.content.capture") != "explicit_opt_in":
        errors.append(f"sensitive content requires explicit opt-in: {', '.join(exposed)}")
    tenant = event.get("agent.security.tenant.id_hash", "")
    if tenant and not str(tenant).startswith("sha256:"):
        errors.append("tenant identifier must be hashed with sha256")
    return errors


def predicate_matches(actual: Any, operator: str, expected: Any) -> bool:
    if operator == "eq":
        return actual == expected
    if operator == "neq":
        return actual != expected
    if operator == "in":
        return actual in expected
    if operator == "contains":
        return expected in actual if actual is not None else False
    if operator == "gt":
        return actual is not None and float(actual) > float(expected)
    if operator == "exists":
        return (actual is not None) is bool(expected)
    raise ValueError(f"unsupported operator: {operator}")


def match_rule(event: Mapping[str, Any], rule: Mapping[str, Any]) -> bool:
    return all(predicate_matches(get_path(event, condition["field"]), condition["op"], condition.get("value")) for condition in rule["conditions"])


def detect(events: Iterable[Mapping[str, Any]], rules: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for event in events:
        errors = validate_event(event)
        if errors:
            findings.append({"rule_id": "AGENTIR-SCHEMA", "severity": "high", "title": "Invalid security event", "event_id": event.get("event.id"), "errors": errors})
            continue
        for rule in rules:
            if match_rule(event, rule):
                findings.append({
                    "rule_id": rule["id"], "severity": rule["severity"], "title": rule["title"],
                    "event_id": event.get("event.id"), "trace_id": event["trace_id"],
                    "agent_id": event["gen_ai.agent.id"], "timestamp": event["timestamp"],
                    "mitre_atlas": rule.get("mitre_atlas", []), "owasp_agentic": rule.get("owasp_agentic", []),
                })
    return findings


def forensic_package(events: list[Mapping[str, Any]], findings: list[Mapping[str, Any]]) -> dict[str, Any]:
    ordered = sorted(events, key=lambda item: item["timestamp"])
    severities = Counter(item["severity"] for item in findings)
    agents = sorted({item["gen_ai.agent.id"] for item in events})
    traces = sorted({item["trace_id"] for item in events})
    return {
        "package_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "summary": {"events": len(events), "findings": len(findings), "agents": len(agents), "traces": len(traces), "findings_by_severity": dict(severities)},
        "scope": {"agents": agents, "traces": traces},
        "timeline": [{"timestamp": e["timestamp"], "event_id": e.get("event.id"), "event_name": e["event.name"], "agent_id": e["gen_ai.agent.id"], "decision": e.get("agent.security.authorization.decision"), "containment": e.get("agent.security.containment.action")} for e in ordered],
        "findings": findings,
        "evidence": [{"event_id": e.get("event.id"), "sha256": digest(e)} for e in ordered],
        "claim_boundary": "Synthetic replay package unless the source system and collection authority state otherwise",
    }


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_rules(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["rules"]
