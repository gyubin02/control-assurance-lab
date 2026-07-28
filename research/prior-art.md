# Prior-art boundary

This is a working comparison, not a claim that a feature absent from public
documentation is absent from a commercial product.

## Systems that already cover the broad loop

| Area | Examples | What they already do | Boundary relevant here |
|---|---|---|---|
| Adversary emulation | [MITRE CALDERA](https://caldera.readthedocs.io/en/stable/), [Atomic Red Team](https://www.atomicredteam.io/docs/atomic-red-team), [Stratus Red Team](https://stratus-red-team.cloud/) | Execute ATT&CK-mapped or cloud attack actions, retain command and operation records, and provide cleanup lifecycles | They are action/execution foundations, not claim-level causal attribution or audit-control models |
| Open-source BAS / security-control validation | [OpenAEV](https://docs.openaev.io/latest/usage/security-control-validation/) | Scenarios, multi-step injects, prevention/detection/vulnerability/human-response expectations, EDR/SIEM collectors, remediation and retest | A generic BAS dashboard would duplicate this work |
| Commercial BAS / exposure validation | [AttackIQ](https://www.attackiq.com/solutions/security-control-validation/), [SafeBreach](https://www.safebreach.com/validate-breach-and-attack-simulation/), [Picus](https://www.picussecurity.com/use-case/security-control-validation) | Continuous simulation, control correlation, attack paths, remediation guidance, retest, risk and audit reporting | Public material does not expose a portable experimental semantics that independently verifies control-specific attribution |
| Attack and asset graphs | [BloodHound CE](https://github.com/SpecterOps/BloodHound), [Cartography](https://cartography-cncf.github.io/cartography/) | Identity or cloud-asset relationships and pathfinding | A graph alone does not show that a control operated or caused an observed outcome |
| Configuration and policy validation | [Prowler](https://github.com/prowler-cloud/prowler), [Powerpipe](https://powerpipe.io/docs) | Configuration checks, requirement mappings, pass/fail reports, remediation, historical comparison | Desired-state agreement is not the same as an observed adversarial outcome |
| Machine-readable assessment evidence | [NIST OSCAL](https://pages.nist.gov/OSCAL/), [Compliance Trestle](https://github.com/oscal-compass/compliance-trestle), [Compliance-to-Policy](https://github.com/oscal-compass/compliance-to-policy-go) | Catalogs, assessment plans/results, observations, findings, risks, POA&M, and policy-result conversion | OSCAL is a data model, not an adversarial experiment engine |
| Assurance cases | [NCSC Principles Based Assurance](https://www.ncsc.gov.uk/information/principles-based-assurance) | Claims, arguments, supporting or rebutting evidence | Claims and evidence are necessary but do not themselves define controlled intervention experiments |

## Standards and research that constrain the design

- [NIST IR 8011 Vol. 1 Rev. 1 initial public draft](https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8011v1r1.ipd.pdf) already describes attack and defend steps, security capabilities, actual-versus-desired state testing, data quality, timeliness, sensitivity, specificity, root-cause analysis, collectors, orchestration, repositories, and dashboards. This project must not claim those concepts as inventions.
- [NIST's RMF Assess step](https://csrc.nist.gov/Projects/risk-management/about-rmf/assess-step) asks whether controls are implemented correctly, operate as intended, and produce the desired outcome. Those are different questions and should remain different verdict dimensions.
- [NIST's work on metamorphic testing for cybersecurity](https://csrc.nist.gov/pubs/journal/2016/06/metamorphic-testing-for-cybersecurity/final) shows that relations between executions can provide an oracle when a result is otherwise difficult to classify.
- Existing causal-inference work models a security control as a treatment and estimates effects from observational data. See the ACSAC 2020 presentation, [Effect of Security Controls on Patching](https://www.acsac.org/2020/files/web/5a-1_effect_security_controls_patching.pdf). Controlled replay in a disposable twin is a different setting, but the word *causal* still requires explicit assumptions and checks.
- [Lula 2's retrospective](https://github.com/defenseunicorns/lula#learning-from-lula-1) reports that OSCAL complexity and automation-only compliance made practical collaboration difficult. The human-facing format here should therefore remain plain YAML/JSON/Markdown, with OSCAL as an adapter.

## Candidate contribution

The candidate contribution is not the platform breadth. It is a testable
experimental contract:

1. Compare matched runs with a verified intervention at one named enforcement point.
2. Preserve a benign positive control so that outage is not mistaken for prevention.
3. Observe the expected mechanism, not only the final impact.
4. Keep per-claim failure visible when another control masks the business impact.
5. Treat missing, stale, contradictory, or uncorrelated evidence as first-class outcomes.
6. Produce a portable bundle from which another evaluator can recalculate the verdict.

This contribution remains a hypothesis until benchmarked against configuration-only,
single-run, and outcome-only baselines.

