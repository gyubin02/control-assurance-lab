# Security

Please do not open a public issue for a vulnerability that could put another
user at risk.

Use GitHub's **Report a vulnerability** button on this repository's Security
tab. Include the affected commit, the smallest reproduction you can provide,
and the boundary you believe the result crosses. Synthetic evidence is
preferred; do not attach production credentials or customer data.

This project is pre-1.0. Security fixes are made on the default branch and
called out in the next release. There is not yet a separate long-term support
branch.

The repository is a research system, not a hosted service. It contains
reference adapters for S3 Object Lock custody, Azure Key Vault operations, and
Vault Transit signing, together with role, journal, and deployment contracts.
It does not provision an institution's AWS or Azure account, Vault cluster,
database or cluster HA, retention policy, key ceremony, or external
transparency anchor. Absence of those operator-owned services is a documented
deployment boundary, not a vulnerability in this source tree.

Behavior that contradicts a stated guarantee, accepts evidence that should
fail closed, crosses a tenant or role boundary, or exposes secrets is in scope.
