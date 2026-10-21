# auditsift

Asking a coding agent to "review this for security issues" usually returns a wall of plausible findings. Many of them are false positives. Severity is inconsistent, file and line evidence is missing, and there is nothing a CI job can parse. Running a flagship model over every pull request makes the habit too expensive to keep.

auditsift is a local-first audit pipeline for that gap. It maps the attack surface, runs fast offline rules, and — only if you opt in — asks one model to explain each candidate and a second model to confirm or reject it against the code you actually have. What survives is JSON, SARIF 2.1.0, and a short Markdown summary, plus a token ledger so the cheap-model setup is visible.

## What auditsift does

| Phase | What it does | Needs a key? |
| --- | --- | --- |
| `map` | Languages, entry points, routes, dependency manifests, and redacted secret-like strings. | No |
| `scan` | Offline rules: hardcoded secrets, SQL built with string interpolation, `shell=True` / `os.system` with external input, `eval`/`exec`, `pickle` and `yaml.load`, weak hashes and ciphers, disabled TLS verification, path traversal, permissive CORS. | No |
| `triage` | Sends only the candidate snippet to an OpenAI-compatible chat API for an impact statement and a fix. | Yes |
| `verify` | A second call, which can be a cheaper model, must confirm or reject the candidate. A confirm counts only when the model quotes a snippet that is actually in the code. Rejected findings are dropped and counted. Verify does not see the triage write-up. | Yes |
| `report` | JSON, SARIF 2.1.0, and Markdown. `--fail-on high` exits 1 so CI can block the merge. | No |

`audit` runs the phases in order. `scan` stops after the rules. `--diff <ref>` keeps only findings on lines `git diff` changed, including untracked files.

Secrets are redacted before they are written to a report or sent to a model. Offline commands do not open a network connection.

## Quickstart

Python 3.10 or newer. The runtime dependencies are the standard library.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Offline scan. No API key and no network.
auditsift scan examples/flask-notes

# Inventory the attack surface.
auditsift map examples/flask-notes

# Full audit without models, and fail the process if anything high remains.
auditsift audit examples/flask-notes --offline --fail-on high --out results
```

`examples/flask-notes` is a small Flask service with deliberate bugs (SQL interpolation, a shell call, `pickle`, `yaml.load`, a path join on a route parameter, `verify=False`, and others). It is a sample, not an app to deploy. The command above exits 1. The directory `results/` contains:

- `auditsift.json` — findings, rejected findings, inventory, and the token ledger
- `auditsift.sarif` — SARIF 2.1.0 for GitHub code scanning
- `auditsift.md` — the short summary

To include triage and verify, copy `.env.example` to `.env` and set a real key. auditsift reads `.env` without overriding variables that are already exported.

```bash
export ATMOROUTER_API_KEY=ar-your-key-here
auditsift audit examples/flask-notes --fail-on high --out results
```

Audit a pull request instead of the whole tree. The ref is compared with the working tree, so committed branch changes and unstaged edits are both visible:

```bash
auditsift audit . --diff origin/main --fail-on high --out results
```

Exit codes: `0` when the gate is clear or no gate was set, `1` when a kept finding is at or above `--fail-on`, `2` when the path or the git ref cannot be read.

### CI

`.github/workflows/ci.yml` runs ruff and pytest on Python 3.10 and 3.12.

`.github/workflows/sarif.yml` is the code-scanning example. It audits the sample app, uploads SARIF even when the gate fails, and is set to `workflow_dispatch` so you can run it from the Actions tab. For a repository you actually want to protect, use the same steps on pull requests:

```yaml
name: auditsift sarif

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install auditsift
        run: pip install .

      - name: Audit the pull request diff
        id: audit
        run: >
          auditsift audit .
          --diff origin/${{ github.base_ref }}
          --offline --fail-on high --out results

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/auditsift.sarif
```

`--offline` keeps the required check free. Add the API key as a secret and drop `--offline` when you want triage and verify on the diff. The upload step uses `if: always()` so GitHub still receives the SARIF file when the severity gate fails the job.

## Sample output

This is `auditsift scan examples/flask-notes` against the sample app. Credential values are not printed. JSON and SARIF runs print the same cost ledger on stderr so the token line stays visible when stdout is a machine-readable document.

```text
auditsift  examples/flask-notes
13 findings kept, 0 rejected

high     AS-SECRET   examples/flask-notes/app.py:14  Hardcoded credential (assigned credential).
          impact: Anyone who can read the repository can reuse the credential.
          fix: Read the value from the environment or a secret store, and rotate the leaked one.
high     AS-SECRET   examples/flask-notes/app.py:15  Hardcoded credential (assigned credential).
          impact: Anyone who can read the repository can reuse the credential.
          fix: Read the value from the environment or a secret store, and rotate the leaked one.
high     AS-SQLI     examples/flask-notes/app.py:28  SQL query is built with string interpolation.
          impact: An attacker who controls the interpolated value can change the query.
          fix: Use a parameterized query and pass values as bound parameters.
high     AS-DESER    examples/flask-notes/app.py:35  Untrusted data can reach an unsafe loader.
          impact: A crafted payload can execute code while it is being loaded.
          fix: Use yaml.safe_load, or a format such as JSON that does not construct objects.
high     AS-DESER    examples/flask-notes/app.py:41  Untrusted data can reach yaml.load.
          impact: A crafted payload can execute code while it is being loaded.
          fix: Use yaml.safe_load, or a format such as JSON that does not construct objects.
high     AS-PATH     examples/flask-notes/app.py:47  Filesystem path includes external input (name).
          impact: ../ segments can escape the directory the handler meant to serve.
          fix: Resolve the path and reject it unless it stays inside a fixed root.
high     AS-SSRF     examples/flask-notes/app.py:53  Outbound request target includes external input (target).
          impact: The server can be turned into a proxy for internal addresses.
          fix: Allow only known hosts, or drop the user-supplied URL entirely.
high     AS-TLS      examples/flask-notes/app.py:53  TLS certificate verification is disabled.
          impact: A network attacker can impersonate the remote host.
          fix: Leave verification on. Pin a certificate only if you have a concrete reason.
high     AS-SHELL    examples/flask-notes/app.py:60  Shell command is built from external input.
          impact: Metacharacters in the input can run extra commands.
          fix: Call the program with an argument list and shell=False.
high     AS-CRYPTO   examples/flask-notes/app.py:67  Weak hash or cipher.
          impact: The construction is cheaper to attack than the password or token it protects.
          fix: Use a password hash (scrypt, bcrypt, or argon2) or SHA-256 for checksums.
high     AS-EVAL     examples/flask-notes/app.py:74  eval or exec runs dynamic code.
          impact: If any part of the string is attacker-controlled, they can run code.
          fix: Replace eval/exec with a parser for the specific grammar you actually accept.
medium   AS-CORS     examples/flask-notes/app.py:16  CORS policy reflects every origin.
          impact: A browser on another site can call authenticated endpoints.
          fix: List the origins you actually ship, and do not combine * with credentials.
low      AS-DEBUG    examples/flask-notes/app.py:78  Debug mode is enabled.
          impact: Interactive debuggers and extra traces leak internals on a crash.
          fix: Turn debug off outside local development.

cost estimate
  map      local                         0 in /      0 out  (0 calls)
  scan     local                         0 in /      0 out  (0 calls)
  triage   local                         0 in /      0 out  (0 calls)
  verify   local                         0 in /      0 out  (0 calls)

notes
  triage and verify did not run
```

With a key, the triage and verify rows name the model and the tokens that call actually used. A confirmed finding carries `verdict: "confirmed"` and an `evidence` quote copied from the snippet. A rejected one is absent from SARIF and listed under `rejected` in the JSON, with a one-line count in the summary.

A trimmed SARIF result for the SQL finding (the real message also includes the impact and fix):

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "auditsift", "rules": [] } },
      "results": [
        {
          "ruleId": "AS-SQLI",
          "level": "error",
          "message": { "text": "SQL query is built with string interpolation." },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "examples/flask-notes/app.py" },
                "region": { "startLine": 28, "startColumn": 1 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## AtmoRouter

Per-PR audits get expensive when every finding is reasoned about by a flagship model. auditsift keeps that part small: the offline scan produces a handful of candidate snippets, then triage and verify each see only those snippets. Point both phases at a cheap AI API gateway and the review stays affordable enough to run on every pull request.

[AtmoRouter](https://atmorouter.dev) is an OpenRouter alternative: one OpenAI-compatible endpoint, one API key, and a catalog of models at different prices. auditsift's default base URL is `https://atmorouter.dev/v1`. Set a triage model and a cheaper verify model and both calls go through that same key. Rejected findings never reach the SARIF upload, so you are not paying flagship prices to restate false positives.

The Anthropic-compatible messages API is available with `AUDITSIFT_API_STYLE=anthropic` if you would rather send `POST /v1/messages`. Any other OpenAI-compatible host works by overriding the base URL and key.

Powered by [AtmoRouter](https://atmorouter.dev).

## Configuration

| Variable | Default | Role |
| --- | --- | --- |
| `ATMOROUTER_API_KEY` | empty | Key for the default gateway. `.env.example` uses `ar-your-key-here`. |
| `AUDITSIFT_API_KEY` | empty | Wins over `ATMOROUTER_API_KEY` when both are set. |
| `AUDITSIFT_BASE_URL` | `https://atmorouter.dev/v1` | OpenAI-compatible base URL. |
| `AUDITSIFT_TRIAGE_MODEL` | `openai/gpt-4o-mini` | Model that writes impact and fix. |
| `AUDITSIFT_VERIFY_MODEL` | `openai/gpt-4.1-nano` | Second, cheaper model that confirms or rejects. |
| `AUDITSIFT_API_STYLE` | `openai` | `openai` or `anthropic`. |
| `AUDITSIFT_TIMEOUT` | `45` | Seconds per completion. |

`--max-llm` (default 40) caps how many candidates are sent to triage, and separately how many are sent to verify. The rest stay in the report as unverified offline findings. Rule severity is the severity CI sees; triage does not downgrade it.

```bash
auditsift map [path]
auditsift scan [path] [--diff REF] [--format text|json|sarif|md] [--fail-on LEVEL] [--out DIR]
auditsift audit [path] [--diff REF] [--offline] [--max-llm N] [--format ...] [--fail-on LEVEL] [--out DIR]
auditsift report REPORT.json [--format md|text|json|sarif] [--out FILE]
auditsift serve
```

## Cursor and Claude Code

`auditsift serve` speaks MCP over stdio: one JSON-RPC message per line. The tools are `auditsift_map`, `auditsift_scan`, and `auditsift_audit`. Map and scan are offline. `auditsift_audit` calls the models only when the argument `use_llm` is true and a key is configured, so an agent does not spend tokens by default.

Cursor MCP config:

```json
{
  "mcpServers": {
    "auditsift": {
      "command": "auditsift",
      "args": ["serve"]
    }
  }
}
```

Claude Code:

```bash
claude mcp add auditsift -- auditsift serve
```

A typical agent turn is `auditsift_scan` on the repo (or on a diff ref), then `auditsift_audit` with `use_llm: true` only for the candidates you are willing to pay to explain.

## License

MIT. See [LICENSE](LICENSE).
