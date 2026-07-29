# Contributing

Start by reproducing the checked-in case:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'

assurance-lab verify examples/masked-export.cab
pytest -q
```

This project treats a result as a claim about a particular control, not merely
about the final outcome. A change to an evaluator or scenario should therefore
make four things clear:

1. which named control is under test;
2. which observation belongs to that control;
3. which downstream or fallback control may mask it; and
4. which benign action must continue to work.

Keep raw observations in the evidence bundle and derive summaries from them.
Do not add credentials, customer records, production logs, or a bundle that
cannot be shared publicly. A missing, stale, conflicting, or unbound artifact
must not become a positive result.

Before opening a pull request, run:

```bash
ruff check .
mypy src tests
pytest -q
(cd verifier-js && npm test)
node --test web/app.test.js
```

Add a decision note when a change moves a trust boundary, alters the meaning of
a verdict, or deliberately narrows a guarantee. Small fixes do not need one.

Please use the private reporting path in [SECURITY.md](SECURITY.md) for a
vulnerability. Public issues are appropriate for ordinary bugs, documentation
gaps, and proposals that do not put another user at risk.
