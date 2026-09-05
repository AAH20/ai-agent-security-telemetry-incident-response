from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


FIELD_MAP = {
    "event.name": "event_name",
    "gen_ai.operation.name": "gen_ai_operation_name",
    "gen_ai.tool.name": "gen_ai_tool_name",
    "agent.security.authorization.decision": "agent_security_authorization_decision",
    "agent.security.approval.present": "agent_security_approval_present",
    "agent.security.input.trust": "agent_security_input_trust",
    "agent.security.injection.signal": "agent_security_injection_signal",
    "agent.security.action.reversibility": "agent_security_action_reversibility",
    "agent.security.delegation.status": "agent_security_delegation_status",
    "agent.security.token.proof_valid": "agent_security_token_proof_valid",
    "agent.security.tenant.crossing": "agent_security_tenant_crossing",
    "agent.security.tool.registered": "agent_security_tool_registered",
    "agent.security.memory.persisted": "agent_security_memory_persisted",
    "agent.security.memory.source_trust": "agent_security_memory_source_trust",
    "agent.security.config.changed": "agent_security_config_changed",
    "agent.security.tool.fanout": "agent_security_tool_fanout",
    "agent.security.containment.result": "agent_security_containment_result",
}


def _literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    return str(value)


def expression(condition: Mapping[str, Any], syntax: str) -> str:
    field = condition["field"] if syntax == "esql" else FIELD_MAP.get(condition["field"], condition["field"].replace(".", "_"))
    op, value = condition["op"], condition.get("value")
    operators = {"eq": "==", "neq": "!=", "gt": ">"}
    if op in operators:
        return f"{field} {operators[op]} {_literal(value)}"
    if op == "in":
        return f"{field} in ({', '.join(_literal(x) for x in value)})"
    if op == "contains":
        return f"{field} contains {_literal(value)}"
    if op == "exists":
        return f"{field} is {'not null' if value else 'null'}"
    raise ValueError(op)


def generate_rules(rules: list[Mapping[str, Any]], output: Path) -> None:
    formats = {"esql": [], "victorialogs": [], "opensearch": [], "sigma": [], "wazuh": []}
    for rule in rules:
        esql = " AND ".join(expression(c, "esql") for c in rule["conditions"])
        logs = " AND ".join(expression(c, "logs") for c in rule["conditions"])
        formats["esql"].append(f"// {rule['id']} {rule['title']}\nFROM agent-security-* | WHERE {esql}\n")
        formats["victorialogs"].append(f"# {rule['id']} {rule['title']}\n{logs}\n")
        formats["opensearch"].append({"id": rule["id"], "title": rule["title"], "query_string": {"query": esql.replace("==", ":")}})
        formats["sigma"].append({"title": rule["title"], "id": rule["id"], "status": "experimental", "logsource": {"category": "application", "product": "agentir"}, "detection": {"selection": {c["field"]: c.get("value") for c in rule["conditions"] if c["op"] == "eq"}, "condition": "selection"}, "level": rule["severity"]})
        formats["wazuh"].append(f"<rule id=\"{900000 + int(rule['id'].split('-')[-1])}\" level=\"{15 if rule['severity']=='critical' else 10}\"><field name=\"agentir.rule_id\">{rule['id']}</field><description>{rule['title']}</description></rule>")
    output.mkdir(parents=True, exist_ok=True)
    (output / "elastic.esql").write_text("\n".join(formats["esql"]) + "\n")
    (output / "victorialogs.logsql").write_text("\n".join(formats["victorialogs"]) + "\n")
    (output / "opensearch.json").write_text(json.dumps(formats["opensearch"], indent=2) + "\n")
    (output / "sigma.json").write_text(json.dumps(formats["sigma"], indent=2) + "\n")
    (output / "wazuh.xml").write_text("<group name=\"agentir\">\n" + "\n".join(formats["wazuh"]) + "\n</group>\n")
