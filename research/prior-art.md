# Prior-art boundary

Survey date: 2026-07-29.

This note draws a careful line around the project. It records what established
standards and public systems already do, then states the smaller question this
repository can actually test. Absence from the material surveyed here is not proof
that an idea has never appeared elsewhere or inside a commercial product.

## What is not new

Detection, response, and recovery are an established incident-response lifecycle.
[NIST SP 800-61 Rev. 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf)
already covers event correlation, incident-status validation, investigation-record
provenance, containment, restore validation, confirmation of normal operation, and
recovery closure. This project does not propose a replacement lifecycle.

Security-control validation platforms already execute adversarial actions and compare
the results with expected security behavior. In particular:

- [OpenAEV distinguishes inject execution from expectation
  results](https://docs.openaev.io/latest/usage/inject-status/). A command completing
  successfully is not itself evidence that a security control succeeded.
- Its [automatic
  expectations](https://docs.openaev.io/latest/usage/expectations/validation/) and
  [collectors](https://docs.openaev.io/latest/usage/collectors/) already cover
  detection, prevention, bounded collection windows, and aggregation from multiple
  tools.
- Its [security-control validation
  model](https://docs.openaev.io/latest/usage/security-control-validation/) already
  organizes expectations by control domain.

Machine-readable assessment records are also established. The
[OSCAL Assessment Results model](https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/)
represents assessment logs, observations, findings, risks, evidence, and remediation
history. The current
[v1.2.2 reference](https://pages.nist.gov/OSCAL-Reference/models/v1.2.2/assessment-results/json-reference/)
is extensible enough to carry project-specific properties and links. OSCAL does not
define this repository's inference rules, but it is incorrect to say that OSCAL
cannot represent the underlying records.

Relations across paired or transformed executions are prior art in
[metamorphic testing](https://csrc.nist.gov/pubs/journal/2016/06/metamorphic-testing-for-cybersecurity/final).
Actual-versus-desired automated control testing, along with timeliness, sensitivity,
specificity, data quality, and root-cause analysis, is already discussed in
[NIST IR 8011 Vol. 1 Rev. 1](https://csrc.nist.gov/pubs/ir/8011/v1/r1/ipd).
Content addressing, append-only records, and provenance are established engineering
patterns as well.

## The distinction under test

Control Assurance Lab is a bounded experimental-verification profile, not a new BAS
platform. Its reference corpus uses three separate, predeclared experiments for one
synthetic confidentiality incident: detection, response, and recovery. Each
experiment crosses four binary factors and starts each cell from a fresh fixture.

From the raw synthetic evidence, the verifier keeps four outputs separate:

1. whether the named control's local mechanism worked;
2. what happened at the downstream path boundary;
3. whether the experiment and its evidence are valid enough for a conclusion; and
4. which delivery events have already been admitted into the incident history.

This separation is the point. An unrelated alert, a principal quarantine, or a
release guard may improve the downstream outcome without converting a failed named
control into a pass. A clean restore and retest may establish a safe current
operational state without deleting a delivery that was evidenced earlier.

The disclosure ledger is append-only under the verifier's rules. It establishes an
admitted delivery event only. It does not establish who retained a copy, prove
attacker possession, or make a mutable directory externally immutable. This wording
follows the narrower boundary in
[NIST SP 1800-28B §1.1](https://www.nccoe.nist.gov/publication/1800-28/VolB/index.html):
after unauthorized disclosure, there is no guaranteed method to retrieve every copy.

The branches used to study an intervention are separately executed matched
comparisons. They are observed proxies for a counterfactual, not simultaneously
observable counterfactual worlds. A comparison may support a scoped mechanism claim
only after the declared manipulation, equivalence, sham, cleanup, and evidence checks
pass.

## Falsifiable hypothesis

On the frozen 48-cell lifecycle suite—three independent `2 × 2 × 2 × 2`
experiments—and a predeclared evidence-corruption set, the evaluator should:

1. identify every seeded named-control failure in the masking cells;
2. preserve a supported downstream outcome beside that local failure;
3. emit no false `SUPPORTED` local-control verdict;
4. return `UNKNOWN` or `CONFLICTING`, rather than `PASS`, when required coverage,
   correlation, freshness, or provenance is absent;
5. never reduce an admitted disclosure history after restore, rotation, or a clean
   retest; and
6. produce the same semantic verdicts in an independent verifier.

Each deliberately shallow baseline—action-status-only, alert-existence-only,
downstream-outcome-only, and current-state-only—must misclassify at least one
predeclared counterexample.

The benchmark will report masked-failure recall, fault-localization accuracy,
false-supported rate, invalid-evidence rejection rate, disclosure-monotonicity
violations, and cross-verifier agreement. These are finite tests over a synthetic
corpus, not claims about arbitrary production systems.

## Closest public comparison points

The closest public benchmark found in this survey is
[MITRE ATT&CK Evaluations Enterprise
2025](https://attackevals.mitre.org/results/enterprise?evaluation=er7&result_type=DETECTION&scenarios=1%2C2&view=cohort).
It publishes step-level detection and protection results, benign noise, false-positive
behavior, and both initial and configuration-change runs without replacing the
original result. It does not supply this project's technical response and recovery
state model or its monotone admitted-delivery invariant.

The closest reusable telemetry corpus found is
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets). It provides
portable malicious and benign data for replay and analytic validation, but not
matched control interventions with response and recovery ground truth.

The defensible research claim is therefore deliberately conditional:

> In the official and public material surveyed above, no benchmark was found that
> combines separately executed matched interventions across detection, response, and
> recovery with named-control non-masking, evidence-validity outcomes, and monotone
> prior-disclosure semantics in one independently recomputable bundle.

The public 48-cell corpus, corruption suite, and second verifier must exist before
that claim is treated as a result rather than a design hypothesis.
