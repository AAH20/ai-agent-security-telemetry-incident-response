# AI Agent Security Telemetry and Incident Response

[![AgentIR Verification](https://github.com/AAH20/ai-agent-security-telemetry-incident-response/actions/workflows/verify.yml/badge.svg)](https://github.com/AAH20/ai-agent-security-telemetry-incident-response/actions/workflows/verify.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**AgentIR** provides open security events, portable detections and forensic incident-response packages for **AI agent security**, **AI agent monitoring**, **AI agent observability**, **MCP security**, **LLM security monitoring** and **OpenTelemetry GenAI** environments.

It turns agent activity into security evidence that SOC analysts, identity teams, GRC reviewers, customers and executives can use.

> **Release boundary:** v0.1 uses synthetic incidents and an independent event convention layered on existing OpenTelemetry GenAI fields. It does not claim that the added `agent.security.*` attributes are official OpenTelemetry semantic conventions.

## What ships in v0.1

- AI-agent security-event JSON Schema
- Privacy-aware validation that rejects sensitive content without explicit opt-in
- Twenty declarative detection rules
- Five replayable incident fixtures
- Deterministic detection engine
- Tamper-evident event hashes
- Timeline and forensic-package generator
- Elastic ES|QL generator
- OpenSearch query generator
- Sigma-compatible JSON generator
- Wazuh rule generator
- VictoriaLogs LogsQL generator
- GitHub Action for detection regression
- Docker incident replay
- Security, response, business and unit-economics KPIs

## Security event flow

```text
Agent and MCP telemetry
          │
          ▼
OpenTelemetry GenAI attributes
          │
          ▼
AgentIR security events
          │
     ┌────┴─────────┐
     ▼              ▼
Detections      Evidence hashes
     │              │
     └────┬─────────┘
          ▼
Timeline and forensic package
          │
     ┌────┼──────────┐
     ▼    ▼          ▼
   SOC   GRC    Trust Center
```

## Run the incident lab

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v

agentir replay incidents/01-indirect-prompt-injection/events.jsonl \
  --output reports/injection.json

agentir generate --output reports/generated-rules
```

Or:

```bash
docker compose run --build indirect-prompt-injection
```

## Five replayable incidents

| Incident | Expected detections and response |
|---|---|
| Indirect prompt injection | Untrusted privileged use and tenant crossing; deny and revoke token |
| Delegation amplification | Child exceeds parent authority; deny delegation |
| Credential replay | Audience or possession proof fails; deny and revoke |
| Memory poisoning | Untrusted content enters persistent memory; quarantine memory |
| Destructive action | Irreversible action lacks approval; deny and invoke kill switch |

Fixtures contain no real customer data or exploit secrets.

## Twenty detection classes

The initial rules cover shared credentials, audience mismatch, expired-token acceptance, revoked delegation, authority amplification, tenant crossing, missing approval, untrusted privileged input, intent divergence, unregistered MCP tools, changed tool definitions, approval bypass, sensitive-data exfiltration, destructive retrieved instructions, memory poisoning, removed trust labels, replayed denied instructions, runtime configuration change, excessive tool fan-out and failed containment.

All rules start as `experimental`. Generated formats require validation against the target product version, field mapping and production data before deployment.

## Privacy by default

The event contract requires identifiers, decisions and evidence hashes. It does not require prompt text, outputs, credentials or tool arguments. Sensitive GenAI content fields trigger validation failure unless the event records `agent.security.content.capture=explicit_opt_in`.

Recommended defaults:

- Hash tenant, principal, delegation and intent identifiers where correlation permits.
- Exclude credentials and tokens entirely.
- Record classifications and hashes instead of content.
- Apply source-side redaction before export.
- Separate security retention from model-debug retention.
- Restrict forensic access and audit every retrieval.

## Portable detections

```bash
agentir generate --output generated
```

This produces `elastic.esql`, `opensearch.json`, `sigma.json`, `wazuh.xml` and `victorialogs.logsql`. These outputs demonstrate portable intent, not vendor certification. See [portability contract](docs/PORTABILITY.md).

## GitHub Action

```yaml
- uses: AAH20/ai-agent-security-telemetry-incident-response@v1
  with:
    events: incidents/01-indirect-prompt-injection/events.jsonl
    output: reports/agentir-forensic-package.json
```

## Forensic package

Each package retains:

- Affected agent and trace identifiers
- Ordered security timeline
- Authorization and containment decisions
- Detection findings
- MITRE ATLAS and OWASP Agentic mappings
- SHA-256 evidence hashes
- Explicit synthetic/production claim boundary

The initial package supports reconstruction and integrity comparison. Trusted timestamping and public-key signatures belong to the signing layer and are not simulated.

## KPIs and economics

See [KPIs and unit economics](docs/KPIS_AND_UNIT_ECONOMICS.md). Release gates include zero unauthorized actions, full privileged-action logging, complete agent-to-principal attribution, successful critical-scenario detection, successful token revocation and verified containment.

## Portfolio role

| Project | Role |
|---|---|
| AgentIAM | Identity, delegation and authorization evidence |
| GRC Claw | Policy, approval and action receipts |
| AgentIR | Runtime telemetry, detection, containment and forensics |
| AgentProof | Adversarial security testing |
| AI Agent Security Trust Center | Customer and auditor assurance distribution |
| Wazuh/Elastic and OpenSearch control planes | SIEM analytics and executive risk enrichment |

## Roadmap

- **v0.2:** OpenTelemetry SDK instrumentation and Collector processor
- **v0.3:** validated Sigma, Elastic, OpenSearch, Wazuh and VictoriaLogs integration tests
- **v0.4:** AgentIAM receipt and Trust Center export
- **v0.5:** multi-event correlation, baselines and approval-drift detection
- **v0.6:** Kubernetes incident lab and bounded containment adapters
- **v1.0:** reviewed semantic-convention proposal and production evidence packs

## License

Apache-2.0. OpenTelemetry, OWASP, MITRE and vendor names belong to their respective owners.
