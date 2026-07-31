# Before this touches a financial network

The interesting part of a control test is not making an attack step run. It is
being able to explain, after the fact, exactly what was allowed to run, what it
observed, who produced the evidence, and why a failed collector could not turn
into a green control result.

That is also the boundary for a pilot. We will not ask an institution to trust a
laboratory result as a production claim.

## Where the project is today

The checked-in case is **R0: a deterministic research system**. It executes a
synthetic financial scenario, preserves raw receipts, and exposes a target
control that a downstream control masked. Its evidence bundle is
content-addressed and independently checked in Python, Node, and the browser.

R0 is useful for evaluating the experiment model. It is not approved for
production data or an operating network. A digest alone does not identify the
collector, prevent replay, create immutable custody, or grant regulatory
compliance.

The repository now also contains R2-shaped reference components: Entra OIDC
roles, fresh-MFA maker/checker changes, tenant-bound PostgreSQL services,
Elastic Security and Defender XDR read paths, workload-identity/PAM adapters,
S3 Object Lock custody, Vault Transit signing, and a locked Kubernetes release
contract. Their presence does not promote the public case to R2. No institution
has supplied the live identities, networks, retention policy, HA/DR evidence,
privacy corpus, external anchor, or acceptance record required by the gates
below. Until that happens, the public demonstrated result remains R0.

## One engine, one first deployment profile

The experiment and evidence engine has no Korean regulator, bank network, or
local product name built into its trust decisions. Claims, leases, signatures,
receipts, and lifecycle verdicts remain portable.

This document is narrower: it defines the first environment in which we are
willing to test that engine with an institution. Korean financial-sector
requirements shape the pilot's identity controls, network placement, evidence
retention, privacy review, and approval gates. A deployment elsewhere would
replace that profile and its control mapping, not fork the evidence engine.

## The first deployment we would propose

The first institutional pilot is **R2: an isolated, read-only non-production or
disaster-recovery exercise**. It has no standing path into a production segment
and no ability to mutate a business system.

```text
control plane
    |
    | signed, expiring, single-use job lease
    v
connector zone                         evidence plane
-------------------------------        --------------------------------
egress-only mTLS collector  ---------> quarantine ingress
typed read-only capability             |  verifier A (Python)
no inbound listener                    |  verifier B (Node)
no general shell                       |  disagreement => quarantine
no raw credential in evidence          v
                                   admission ledger
                                       |
                              WORM custody + external anchor
                                       |
                                   read model / UI
```

The collector receives one typed capability for one job. It does not receive a
general-purpose shell or a reusable cloud credential. Evidence is minimized
before it leaves the connector zone, signed over the exact bytes, and admitted
only after the job lease, signer policy, sequence, and bundle semantics agree.
An acknowledgement is not returned until the custody write and replay
checkpoint are durable.

## Promotion is a technical decision

| Level | Permitted use | Promotion gate |
|---|---|---|
| **R0** | Synthetic research corpus | Deterministic replay, raw-evidence reconstruction, independent verifier agreement |
| **R1** | Hardened offline appliance | Signed collector identity, external trust policy, key rotation and revocation, replay-safe admission, recoverable custody |
| **R2** | Isolated non-production/DR, read-only | Institutional SSO and MFA, RBAC, connector isolation, privacy test corpus, failure and restore exercise |
| **R3** | Limited production, read-only | Security architecture approval, minimal data-source grants, HA/SLO evidence, monitored pilot and agreed rollback |
| **R4** | Pre-approved mutation tests | Two-person authorization, typed mutation allowlist, maintenance window, preflight backup, automatic rollback and kill switch |

No calendar date promotes a release. The gate either has evidence or it does not.

## Non-negotiable acceptance tests

### Identity and custody

- Removing, replacing, or duplicating a required signature must fail. Reordering
  the same DSSE signature set does not change its trust meaning, but it does
  produce a different envelope digest and custody record.
- Unknown, expired, not-yet-valid, and revoked signing keys must fail against an
  external deny-by-default trust policy.
- A job nonce is 256-bit, audience-bound, expiring, and consumed once.
- `(collector, key, epoch, sequence)` and the job identity are durable replay
  keys. A crash cannot make either reusable.
- Every admission has a trusted receipt linked to the preceding receipt. The
  original evidence is retained in WORM-capable storage and periodically bound
  to an external anchor.
- A disaster-recovery exercise must validate old signatures, revoked-key
  history, anchors, replay state, and rebuilt indexes—not merely restore files.

### Access and separation of duties

- Human access uses the institution's identity provider, MFA, and privileged
  access workflow. There are no shared operator accounts.
- Policy author, job approver, connector operator, and evidence reviewer are
  separate roles. A mutation-capable job requires two distinct approvers.
- Secrets are short-lived and brokered at execution time. They never enter a
  bundle, log line, support export, or browser response.
- Authorization decisions and break-glass use are written to a separate audit
  destination that the application role cannot rewrite.

### Connector containment

- Connectors initiate outbound mTLS; the control plane cannot open an inbound
  shell into the protected segment.
- Read and mutation capabilities are different binaries and identities.
- The runtime is non-root with a read-only root filesystem, restricted system
  calls, an explicit destination allowlist, and a fail-closed network policy.
- Queue growth, verifier disagreement, expired policy, clock uncertainty, or
  failed cleanup stops new work. None of these conditions can degrade to
  “collect now, verify later.”

### Data minimization

- Each collector has an allowlist schema. An unknown field is rejected, not
  silently copied.
- Tokens, cookies, passwords, private keys, and raw customer rows are prohibited
  evidence classes.
- Where identity correlation is necessary, the pilot uses scoped HMAC
  pseudonyms and signed query/result receipts rather than exporting source
  values.
- A seeded privacy corpus must prove that secrets and direct identifiers do not
  survive collection, error handling, quarantine, or support diagnostics.

### Verifiability and failure behavior

- The 144-run lifecycle benchmark and C01–C20 corruption corpus are release
  gates, not screenshots.
- Python and Node must produce the same status and semantic result. Disagreement
  is quarantined.
- File-count, byte, depth, JSON, and time limits are exercised with adversarial
  inputs. A limit terminates I/O rather than merely adding a warning.
- Power loss is injected before and after custody, replay checkpoint, and
  acknowledgement. Recovery must never admit the same job twice or lose an
  acknowledged bundle.
- Load, dependency outage, clock skew, key rotation, partial storage failure,
  and verifier crash have measured SLO and recovery results.

## Immediate stop conditions

The pilot stops if any of the following occurs:

- a collector asks for a capability outside its signed job;
- evidence contains a prohibited data class;
- signer policy, time, sequence, or one-time lease cannot be established;
- the two verifiers disagree;
- immutable custody or its external anchor is unavailable;
- cleanup, rollback, or the audit destination cannot be confirmed; or
- an operator is asked to bypass a gate to keep the demonstration moving.

The preserved outcome is `QUARANTINED` or `INDETERMINATE`. It is never converted
to a pass by a downstream business outcome.

## Regulatory ground, not a compliance claim

The architecture and evidence fields are intended to support an institution's
own risk assessment and audit work. Specific control mapping still belongs to
the institution's security, privacy, audit, and legal owners.

Sources were checked on 2026-07-29. The two rules below were then listed as
effective from 2026-07-15 and 2026-07-01 respectively; a real pilot must repeat
that check rather than treat this note as a frozen compliance interpretation.
The design inputs include:

- Korea's current
  [Electronic Financial Supervision Regulation](https://www.law.go.kr/LSW/admRulLsInfoP.do?admRulId=21828&efYd=0),
  especially the official texts for
  [Article 14](https://www.law.go.kr/LSW/admRulSideInfoP.do?admRulSeq=2100000274812&chrClsCd=010201&dashNo=&docCls=jo&joBrNo=00&joNo=0014&urlMode=admRulScJoRltInfoR),
  [Article 15](https://www.law.go.kr/LSW/admRulSideInfoP.do?admRulSeq=2100000274812&chrClsCd=010201&dashNo=&docCls=jo&joBrNo=00&joNo=0015&urlMode=admRulScJoRltInfoR), and
  [Article 23](https://www.law.go.kr/LSW/admRulSideInfoP.do?admRulSeq=2100000274812&chrClsCd=010201&dashNo=&docCls=jo&joBrNo=00&joNo=0023&urlMode=admRulScJoRltInfoR);
- the current PIPC
  [Standards for Measures to Ensure the Security of Personal Information](https://www.law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000281400&chrClsCd=010201);
- Financial Security Institute publications on
  [zero trust](https://www.fsec.or.kr/bbs/detail?bbsNo=11678&menuNo=69) and
  [software supply-chain risk](https://www.fsec.or.kr/bbs/detail?bbsNo=11749&menuNo=69),
  together with its
  [financial-sector cloud-use guide](https://www.fsec.or.kr/bbs/detail?bbsNo=11691&menuNo=222).

Passing this project's tests is not certification under any of those sources.
It means the pilot has machine-checkable evidence for a deliberately narrower
set of claims.
