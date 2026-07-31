# Contributing

Start by reproducing the checked-in case:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install \
  --only-binary=:all: --require-hashes -r requirements/ci.lock
python -m pip install --no-deps --no-build-isolation -e .

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
for lock in requirements/ci.lock requirements/runtime.lock requirements/container-build.lock; do
  pip-audit --requirement "$lock" --require-hashes \
    --disable-pip --strict --progress-spinner off
done
ruff check .
mypy src tests
pytest -q
(cd verifier-js && npm test)
node verifier-js/src/cli.js examples/masked-export.cab
node --test web/app.test.js
node --test src/assurance_lab/control_plane/static/model.test.mjs
python -m hatchling build --target wheel --target sdist --directory dist
python scripts/check-distributions.py dist
```

The workflow also provisions isolated PostgreSQL 17 databases with distinct
migration, control, authentication, reconciler, registrar, worker, PAM, and
recovery logins. It separately builds and runs the production Dockerfile as an
unprivileged read-only container. A unit-only local pass does not replace
those jobs.

`web/case.json` and the README image are derived from the checked-in example.
If the example changes, update the JSON from the verifier rather than editing
it:

```bash
assurance-lab verify examples/masked-export.cab --json > /tmp/case.json
install -m 0644 /tmp/case.json web/case.json
pytest -q tests/test_exhibit_cli.py tests/test_public_surface.py
```

To refresh the screenshot, serve the repository locally, then capture the
verified browser state:

```bash
python -m http.server 8000
# In another terminal:
node scripts/capture-readme-hero.mjs \
  --url http://127.0.0.1:8000/web/ \
  --out docs/assets/readme-hero.png
```

Review the image and both derived-file diffs. Do not accept a screenshot that
was captured before the browser verified the manifest and its payloads.

Add a decision note when a change moves a trust boundary, alters the meaning of
a verdict, or deliberately narrows a guarantee. Small fixes do not need one.

Please use the private reporting path in [SECURITY.md](SECURITY.md) for a
vulnerability. Public issues are appropriate for ordinary bugs, documentation
gaps, and proposals that do not put another user at risk.
