# Hermes Code Review

Fail-closed independent code review for immutable staged Git candidates in [Hermes Agent](https://github.com/NousResearch/hermes-agent).

## What it guarantees

- Reviews exactly `HEAD + INDEX_TREE`; a changed HEAD or index produces `STALE`.
- Rejects tracked unstaged files and non-ignored untracked files.
- Uses one configured reviewer identity; there is no silent provider/model fallback.
- Blocks sensitive paths and secret-like material before any remote request.
- Enforces per-request and daily token budgets.
- Splits large staged diffs into deterministic file chunks bound to one immutable candidate.
- Requires strict JSON findings with valid `file:line` for P0/P1.
- Signs the final receipt with a local HMAC key and records redacted metrics.

Model review is an additional gate, not a replacement for tests, lint, type checks, or security scanners.

## Install as a Hermes plugin

```bash
hermes plugins install https://github.com/Jieoz/hermes-code-review.git
hermes plugins enable hermes-code-review --no-allow-tool-override
```

Restart Hermes through the deployment's controlled restart entrypoint after enabling. The plugin registers:

- `review_git_candidate`
- `code_review_status`

It does **not** override `delegate_task` or patch `/opt/hermes` source files.

## Automatic agent gate

Hermes agents should invoke `review_git_candidate` proactively after deterministic
tests/builds are green and before any commit, push, merge, tag, Release, or other
high-risk handoff. The caller must stage only the intended candidate and provide
the acceptance criteria plus concrete test/static evidence. A changed candidate
invalidates the verdict and must be reviewed again.

Do not spend this gate on read-only investigation, early work-in-progress edits,
or documentation-only changes. It is the final independent gate, not a substitute
for implementation tests.

**`code_review_status` is never a release gate.** Only a signed substantive
`review_git_candidate` PASS for the unchanged staged candidate can authorize the
handoff.

The fixed invocation path is:

```text
test/build/static gates
  -> stage explicit intended paths
  -> require no tracked unstaged or non-ignored untracked files
  -> review_git_candidate(repo, requirements, evidence)
  -> require signed PASS + safe_to_commit=true
  -> re-check HEAD + INDEX_TREE before commit/release
```

## Configuration

The fixed route reuses a named worker from `main_token_reserve.workers`:

```yaml
delegation:
  lanes:
    critic:
      worker: independent_reviewer
      fallback: fail

main_token_reserve:
  workers:
    independent_reviewer:
      enabled: true
      provider: custom
      model: your-review-model
      base_url: https://review.example/v1
      api_mode: chat_completions
      api_key_file: /opt/data/secrets/reserve_keys/independent_reviewer

code_review:
  max_source_bytes: 350000
  max_input_tokens: 120000
  daily_input_tokens: 1000000
  max_output_tokens: 4096
  daily_output_tokens: 100000
```

Credential files must be regular files under `/opt/data/secrets/reserve_keys` with mode `0600`. Credentials, base URLs, and authorization headers are excluded from receipts and metrics.

## CLI

An installed wheel provides the `hermes-code-review` console command. A drop-in
plugin checkout can expose the same fixed command without package installation:

```bash
ln -sfn /absolute/plugin/checkout/scripts/hermes-code-review \
  ~/.local/bin/hermes-code-review
```

```bash
hermes-code-review status
hermes-code-review review-git \
  --repo /path/to/repo \
  --requirements 'Describe the intended behavior and release criteria.' \
  --evidence 'pytest, lint, type-check and security-scan results'
```

`status` is deliberately local and free: it validates the approved route,
credential-file contract, and circuit-breaker state without spending a reviewer
request. Only a substantive candidate review proves end-to-end reviewer service.

Exit codes:

- `0`: signed PASS and `safe_to_commit=true`
- `2`: reviewer BLOCKED the candidate
- `3`: infrastructure, policy, budget, route, or stale failure
- `4`: invalid receipt signature

Verify a persisted result before release:

```bash
hermes-code-review verify-receipt review.json \
  --key-file /opt/data/secrets/code_review_receipt.key
```

## Large candidates

A candidate larger than `max_source_bytes` is split only on staged file boundaries. Each chunk is reviewed by the same fixed route and bound to the same HEAD/index. A single file larger than the cap fails closed instead of being partially reviewed. Any chunk failure blocks the aggregate result.

## Quality benchmark

`corpus/known_defects.json` contains blind P1 samples for command injection, fail-open authentication, path traversal, and index TOCTOU. The deterministic evaluator reports exact-case recall. Live benchmark results are release evidence but are not run in public CI because they require a private reviewer credential.

## Development

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/python -m pytest
```

See [docs/architecture.md](docs/architecture.md) for trust boundaries and receipt semantics.
