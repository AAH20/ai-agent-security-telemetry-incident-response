# Detection Portability Contract

The canonical source is `detections/rules.json`. A rule identifies its conditions, severity and threat-framework mappings independently of a destination product.

Generated rules are starting points. Before production use, verify:

- Destination product and version
- Field mappings and data types
- Boolean and null syntax
- Timestamp and correlation behavior
- Escaping and case sensitivity
- Rule identifiers and severity translation
- Index, stream and tenant scope
- False-positive and false-negative results
- Alert routing and containment authority

`sigma.json` preserves a Sigma-shaped detection document without claiming official Sigma validation. ES|QL, OpenSearch, Wazuh and VictoriaLogs output likewise requires native product testing.

## Evidence levels

- `GENERATED`: mechanically translated from the canonical rule.
- `PARSED`: accepted by the destination parser.
- `EXECUTED`: run against a synthetic positive and negative fixture.
- `VERIFIED`: independently reproduced with retained evidence.

The repository must never label generated output as verified.

## OpenTelemetry boundary

Reuse official `gen_ai.*`, general event and error attributes when their published semantics match. AgentIR-specific fields remain under `agent.security.*` until an accepted upstream convention exists. Avoid creating synonyms for established attributes.

Content-bearing GenAI fields can expose prompts, messages, tool arguments or results. AgentIR requires explicit opt-in for those fields and recommends source-side filtering, classification-aware retention and restricted forensic access.
