# 0001 — Core language (provisional)

Status: provisional until the first scenario and evidence bundle are complete.

## Decision

Use Python 3.12 for the experiment model, runner, evaluator, benchmark, and API.
Keep the web interface in a separate TypeScript application when the API is stable.

## Why this is the current choice

- The work is dominated by orchestration, structured evidence, security-tool adapters,
  and statistical evaluation rather than a high-throughput data plane.
- Python has mature libraries for typed schemas, testing, data analysis, subprocess and
  container orchestration, OSCAL conversion, and security-tool integration.
- A typed Pydantic boundary can reject malformed experiment records before they reach
  the evaluator.
- The benchmark will be easier to inspect in the same language as its analysis.

## Alternatives not selected yet

- **Go:** attractive for a portable runner and concurrency, but would split experiment
  analysis and most security adapters across languages too early.
- **TypeScript for everything:** would share types with the interface, but is weaker for
  the planned benchmark/statistical work and many security integrations.
- **Python-generated shell scripts:** quick for a demo but too difficult to validate,
  replay, and constrain safely.

## Revisit condition

Reconsider a small Go execution agent only if measurements show that Python process
startup, isolation, or distribution is a practical problem. Do not add it merely to
make the architecture look larger.

