# Field notes sample

This Flask app is intentionally vulnerable. It exists so you can run auditsift
against a pull request before merging. Do not deploy it, and do not copy the
handlers into another service.

```bash
auditsift scan examples/flask-notes
auditsift audit examples/flask-notes --offline --fail-on high --out results
```

The audit should exit 1. The SARIF file is `results/auditsift.sarif`.
