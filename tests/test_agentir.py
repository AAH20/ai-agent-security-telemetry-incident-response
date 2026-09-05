import json
import tempfile
import unittest
from pathlib import Path

from agentir.engine import detect, forensic_package, load_jsonl, load_rules, validate_event
from agentir.generators import generate_rules


ROOT = Path(__file__).parents[1]
RULES = load_rules(ROOT / "detections/rules.json")


class AgentIRTests(unittest.TestCase):
    def test_twenty_rules_are_present(self):
        self.assertEqual(len(RULES), 20)
        self.assertEqual(len({r["id"] for r in RULES}), 20)

    def test_five_incidents_trigger_expected_detections(self):
        expected = {
            "01-indirect-prompt-injection": {"AGENTIR-006", "AGENTIR-008"},
            "02-delegation-amplification": {"AGENTIR-005"},
            "03-credential-replay": {"AGENTIR-002"},
            "04-memory-poisoning": {"AGENTIR-015"},
            "05-destructive-action": {"AGENTIR-007", "AGENTIR-014"},
        }
        for name, required in expected.items():
            events = load_jsonl(ROOT / f"incidents/{name}/events.jsonl")
            found = {item["rule_id"] for item in detect(events, RULES)}
            self.assertTrue(required.issubset(found), f"{name}: {required - found}")

    def test_sensitive_content_requires_explicit_opt_in(self):
        event = load_jsonl(ROOT / "incidents/01-indirect-prompt-injection/events.jsonl")[0]
        event["gen_ai.input.messages"] = [{"content": "secret"}]
        self.assertTrue(any("explicit opt-in" in error for error in validate_event(event)))

    def test_schema_error_becomes_finding(self):
        event = {"event.name": "gen_ai.security.invalid"}
        findings = detect([event], RULES)
        self.assertEqual(findings[0]["rule_id"], "AGENTIR-SCHEMA")

    def test_forensic_hash_detects_event_change(self):
        events = load_jsonl(ROOT / "incidents/02-delegation-amplification/events.jsonl")
        package = forensic_package(events, detect(events, RULES))
        original = package["evidence"][0]["sha256"]
        events[0]["agent.security.authorization.decision"] = "allow"
        changed = forensic_package(events, detect(events, RULES))["evidence"][0]["sha256"]
        self.assertNotEqual(original, changed)

    def test_generators_emit_five_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            generate_rules(RULES, output)
            self.assertEqual({p.name for p in output.iterdir()}, {"elastic.esql", "victorialogs.logsql", "opensearch.json", "sigma.json", "wazuh.xml"})
            self.assertIn("AGENTIR-020", (output / "elastic.esql").read_text())


if __name__ == "__main__":
    unittest.main()
