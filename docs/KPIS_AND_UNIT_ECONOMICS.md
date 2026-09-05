# AgentIR KPIs and Unit Economics

## Visibility

| KPI | Formula | Target |
|---|---|---:|
| Registered-agent coverage | active agents emitting valid events / registered agents | ≥98% |
| Tool-call visibility | observed tool calls / independently known tool calls | ≥98% |
| Identity correlation | actions correlated to agent and principal / actions | 100% |
| Delegation-chain coverage | privileged actions with complete delegation lineage / privileged actions | 100% |
| Privileged-action logging | logged privileged actions / privileged actions | 100% |
| Sensitive-content violations | events capturing sensitive content without approved opt-in | 0 |
| Invalid-event rate | schema-invalid events / received events | <1% |

## Detection and response

| KPI | Formula | Target |
|---|---|---:|
| Critical-scenario detection | detected mandatory scenarios / executed scenarios | 100% |
| Median time to detect | median(first malicious event to finding) | <60 seconds |
| False-negative rate | undetected confirmed incidents / confirmed incidents | 0% for mandatory suite |
| False-positive rate | invalid findings / reviewed findings | <5% after tuning |
| Detection regression pass | passing rules / enabled rules | 100% |
| Unauthorized action success | successful unauthorized actions / attempts | 0% |
| Token-revocation success | denied post-revocation calls / calls | 100% |
| Kill-switch success | safely stopped agents / kill-switch attempts | 100% |
| Median containment time | median(first finding to verified containment) | <5 minutes |
| Verified recovery | restored and independently checked services / recoveries | 100% |

## Forensic quality

| KPI | Formula | Target |
|---|---|---:|
| Incident reconstruction | packages reconstructing identity, intent, policy and result / packages | 100% |
| Evidence integrity | artifacts passing hash/signature verification / artifacts | 100% |
| Timeline completeness | expected material events present / expected material events | ≥99% |
| Principal attribution | actions mapped to accountable authority / actions | 100% |
| Evidence preparation time | median confirmed incident to review-ready package | <15 minutes |
| Control feedback closure | incident control gaps closed and verified / identified gaps | Higher |

## Operational and executive measures

- Security events per 1,000 agent tasks
- Incidents per 10,000 agent tasks
- Detection cost per million events
- Storage bytes per agent task
- Investigation minutes per reviewed alert
- Mean time to acknowledge, contain and recover
- Repeat incidents by root cause
- Open critical findings by age
- Privileged agents by autonomy level
- Expected-loss exposure by business service
- Customers and contribution margin at risk

## Customer cost model

```text
Annual AgentIR cost = instrumentation engineering
                    + telemetry ingestion
                    + storage and retention
                    + detection execution
                    + investigation labor
                    + containment infrastructure
                    + rule maintenance

Cost per monitored agent = annual AgentIR cost / active monitored agents

Cost per million events = ingestion + processing + storage + query cost

Cost per verified incident = detection + analyst investigation
                           + containment + recovery + evidence preparation

Investigation value = incidents
                    × (baseline hours - AgentIR hours)
                    × loaded analyst cost

Expected-loss reduction = baseline incident probability × baseline impact
                        - residual probability × residual impact

Finance-validated revenue protection = at-risk contract contribution margin
                                     × probability incident causes delay, loss or churn
                                     × containment attribution

ROI = (investigation value + avoided evidence preparation
     + expected-loss reduction + validated revenue protection
     - annual AgentIR cost) / annual AgentIR cost
```

## Attribution guardrails

Revenue protection requires a named customer or contract, documented security dependency, incident timeline, credible counterfactual, Finance-approved contribution margin and attribution owner. Report influenced pipeline separately. Never use total contract value in place of contribution margin or add expected-loss reduction twice.

Publish conservative, base and upside assumptions for event volume, retention, analyst rates, incident frequency, loss magnitude and attribution. Measure year-one implementation separately from steady-state operation.

## Provider economics

Track ingestion and detection compute per million events, hot and archive storage, rule-maintenance hours, reviewer time, support cost per 100 agents, gross margin per tenant, expansion revenue per monitored agent, retention and acquisition payback.
