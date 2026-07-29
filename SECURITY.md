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

The repository is a research system, not a hosted service. Its documented
nonclaims—such as no WORM storage, external transparency anchor, HA consensus,
or institutional KMS integration—are not vulnerabilities by themselves.
Behavior that contradicts a stated guarantee, accepts evidence that should
fail closed, or exposes secrets is in scope.
