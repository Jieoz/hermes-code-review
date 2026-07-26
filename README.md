# Hermes Code Review

Fail-closed independent code review for immutable staged Git candidates in [Hermes Agent](https://github.com/NousResearch/hermes-agent).

## What it guarantees

- Reviews exactly `HEAD + INDEX_TREE`; a changed HEAD or index produces `STALE`.
- Rejects tracked unstaged files and non-ignored untracked files.
- Uses an explicit ordered reviewer pool restricted to approved model/transport identities; every route must be outside the configured author model families and every reviewer route must use a different model family.
- Never shops for a PASS: a valid `BLOCKED` verdict is final and cannot trigger fallback.
- Blocks sensitive paths and secret-like material before any remote request.
- Applies shared 1,000,000-input / 200,000-output daily caps by default and protects 200,000 input plus 40,000 output tokens for final releases; operators may override these values explicitly.
- Reviews the complete staged diff as one semantic unit. Oversized candidates fail closed instead of producing context-losing partial PASSes.
- Requires strict JSON findings with valid `file:line` for P0/P1.
- Binds receipts to requirements and evidence hashes, then signs them locally with HMAC.
- Reuses an existing verified PASS only when candidate, route, requirements, and evidence all match exactly.

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
or documentation-only changes. Early dissent belongs in a separate read-only
design critic with no receipt or release authority; this plugin remains the one
final independent gate.

**`code_review_status` is never a release gate.** Only a signed substantive
`review_git_candidate` PASS for the unchanged staged candidate can authorize the
handoff.

The fixed invocation path is:

```text
test/build/static gates
  -> stage explicit intended paths
  -> require no tracked unstaged or non-ignored untracked files
  -> review_git_candidate(repo, requirements, evidence)
     (remote input is the frozen diff; concurrent Git changes make the verdict stale)
  -> require signed PASS + safe_to_commit=true
  -> re-check HEAD + INDEX_TREE before commit/release
```

## Configuration

The ordered pool reuses named workers from `main_token_reserve.workers`. It is
explicit configuration, not an automatic or open fallback pool. Multiple providers
may serve an approved reviewer model so one API circuit cannot halt the gate:

```yaml
main_token_reserve:
  workers:
    grok_review:
      enabled: true
      provider: custom
      model: grok-4.5
      base_url: https://primary-review.example/v1
      api_mode: chat_completions
      api_key_file: /opt/data/secrets/reserve_keys/grok_review
    kimi_review:
      enabled: true
      provider: custom
      model: kimi-k3
      base_url: https://fallback-review.example/v1
      api_mode: chat_completions
      api_key_file: /opt/data/secrets/reserve_keys/kimi_review

code_review:
  workers: [grok_review, kimi_review]
  author_model_families: [gpt, claude]
  max_source_bytes: 200000
  max_input_tokens: 120000
  max_output_tokens: 8192
  daily_input_tokens: 1000000
  daily_output_tokens: 200000
  release_input_reserve: 200000
  release_output_reserve: 40000
```

Per-route transport knobs (not part of reviewer identity / `route_sha`) may be set
on a worker when a relay needs special handling:

```yaml
hybgzs_grok45:
  model: grok-4.5
  api_mode: chat_completions
  review_json_mode: false          # omit API response_format; prompt still requires strict JSON
  review_temperature: null         # omit unsupported temperature; strict parser is unchanged
  review_max_attempts: 2           # bounded same-route retry before pool fallback
  review_backoff_cap_seconds: 20   # cap retry spacing for exhausted channels
cunai_k3:
  model: kimi-k3
  api_mode: chat_completions
  review_json_mode: false
  review_temperature: null
  review_reasoning_effort: low     # finish before this relay's hard upstream timeout
```

- `review_json_mode: false` still fail-closes on invalid verdicts; it only allows a
  best-effort bare-JSON recovery (strip markdown fences / leading whitespace) before
  the strict schema check.
- Higher `review_max_attempts` scales the local circuit threshold so a single request
  cannot open its own circuit purely by using its configured retries.

`max_input_tokens` and `max_output_tokens` are per-request payload bounds. Daily
limits are shared across the whole ordered pool, so fallback never creates a
second allowance. Both input and output keep protected release reserves;
routine reviews cannot consume them. Explicit zero still means unlimited, but
omission uses the bounded defaults above.

Approved identities are currently `gpt-5.6-sol/chat_completions`,
`claude-opus-4-8/anthropic_messages`, `grok-4.5/chat_completions`, and
`kimi-k3/chat_completions`. Approval only permits configuration; the mandatory
`author_model_families` exclusion and reviewer-family uniqueness checks decide
which identities may actually sign in one deployment.
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
  --evidence 'pytest, lint, type-check and security-scan results' \
  --release-gate
```

`--release-gate` allows a final tag, Release, or deployment review to consume
the protected release reserve. Ordinary review cannot consume it.

`gate_role` makes project seniority explicit:

- `load_bearing` (default): reviewer infrastructure failure blocks handoff.
- `secondary`: retryable reviewer infrastructure failure reports
  `blocks_handoff=false`; a concrete `BLOCKED`, privacy/policy failure, stale
  candidate, or secret finding still blocks.

Use `secondary` only when a project has a stronger executable gate, such as an
exact-SHA headless-Chromium replay that loads the real MV3 production code.
Compiled or cross-platform candidates normally keep `load_bearing`.

`status` is deliberately local and free: it validates every configured approved
route, credential-file contract, circuit state, and observed usage without
spending a reviewer request. Only a substantive candidate review proves end-to-end
reviewer service.

When **every** route's local circuit is open, `status` does not collapse to an
opaque failure. It returns `status: ALL_ROUTES_UNAVAILABLE` with each route's
identity, budget, per-route `open_until`, and a top-level `retry_after_seconds`
giving the soonest cooldown lapse. This lets the caller schedule a single spaced
retry instead of blind-polling — a reviewer infrastructure outage must never
blind the operator to *when* it clears, and never justifies a retry-storm against
an unchanged candidate.

The fallback is attempted only after retryable transport/server/rate-limit/circuit
failure, or after one same-route retry still produces an invalid strict verdict.
Privacy, budget, policy, stale-candidate, and valid `BLOCKED` outcomes never trigger
fallback. The returned receipt identifies the reviewer that actually produced it.

## Signed PASS reuse

Before making a remote request, the plugin may reuse a persisted signed PASS only
when all of these match exactly: `HEAD`, `INDEX_TREE`, staged diff SHA, approved
route identity, reviewer model, requirements SHA, and evidence SHA. The signature
is verified before reuse. Any changed requirement, evidence, code, route, invalid
signature, or non-PASS verdict forces a new review.

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

A candidate larger than `max_source_bytes` fails closed before any reviewer
request. File-boundary chunking was deliberately removed because independently
passing chunks cannot prove cross-file reference, protocol, or lifecycle
consistency. Split the work into independently deliverable candidates or use a
higher-capacity preapproved route; never relabel partial review as whole-candidate
PASS.

## Quality benchmark

`corpus/known_defects.json` contains blind P1 samples for command injection, fail-open authentication, path traversal, and index TOCTOU. The deterministic evaluator reports exact-case recall. Live benchmark results are release evidence but are not run in public CI because they require a private reviewer credential.

## Development

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/python -m pytest
```

See [docs/architecture.md](docs/architecture.md) for trust boundaries and receipt semantics.
