# Architecture

## Trust boundary

The local Hermes process owns Git inspection, secret scanning, usage accounting, candidate identity, result validation, persistence, signing, and metrics. The remote reviewer receives only:

- staged unified diff bytes;
- explicit acceptance criteria;
- deterministic test/evidence text;
- a non-secret receipt containing HEAD, index tree, diff SHA, route fingerprint,
  reviewer model, requirements SHA, and evidence SHA.

It receives no terminal, Docker, SSH, filesystem, GitHub, or secret-file access.

## Candidate state machine

1. Resolve the explicit ordered reviewer pool and validate every model/transport identity.
2. Reject dirty tracked worktree files and non-ignored untracked files.
3. Freeze `HEAD`, `git write-tree`, staged diff SHA, and staged paths. Those bytes and paths are the immutable review object. A best-effort guard checks Git immediately before transport, and Git is re-frozen before accepting a verdict. Concurrent changes cannot alter the already-built outbound body; they make the verdict stale and unusable. The plugin deliberately does not hold Git's index lock across a network request.
4. Run local privacy and per-request payload-size preflight.
5. Reuse an exact verified signed PASS, or review the complete diff once. An oversized candidate fails closed before transport.
6. Validate strict verdict shape and all P0/P1 `file:line` references.
7. Re-freeze HEAD and index. Any mismatch becomes `STALE`.
8. Build the aggregate receipt, sign it locally, and atomically persist it.
9. Allow release only when the signature verifies and `safe_to_commit=true`.

## Agent invocation contract

The release owner invokes this gate proactively after all deterministic checks and
before commit/push/release. The gate covers only the staged HEAD + index tree it
receives. Any code, test, documentation, packaging, or staging change invalidates
the prior verdict. Read-only investigation and incomplete work are intentionally
outside the gate so substantive reviewer requests are spent only on final candidates.

## Route identity

The route fingerprint hashes only provider name, model, normalized API mode, and canonical endpoint. It never hashes or serializes API keys, authorization headers, or key-file contents.

Reviewer workers are explicitly ordered in configuration and restricted to a local
model/transport allowlist. Every route must be outside `author_model_families`,
and no two routes may share a model family. Provider diversity without cognitive
model diversity is not treated as independent review.
Fallback is permitted only for infrastructure classes (including one exhausted
same-route invalid-verdict retry). A valid `BLOCKED`, privacy failure, policy
failure, or stale candidate is final and cannot select another
reviewer. Fallback therefore improves availability without shopping for a PASS.

Per-route transport knobs (`review_json_mode`, `review_max_attempts`,
`review_backoff_cap_seconds`) shape request body construction and same-route retry
timing without changing reviewer identity. They are excluded from `route_sha`.
When JSON mode is disabled, response recovery may extract a bare JSON object from
fenced/padded text, but the extracted value still must pass the full strict
verdict schema.

The usage ledger atomically reserves and reconciles primary and fallback traffic
for observability. It has no local daily cap and cannot block a normal review.
Aggregate quota enforcement belongs to the configured provider/account. Local
limits exist only for one request (`max_source_bytes`, `max_input_tokens`, and
`max_output_tokens`) so impossible payloads fail before transport.

## Full-context review

The gate never turns several partial model judgements into a whole-candidate
PASS. `max_source_bytes` bounds the complete staged diff; exceeding it fails
closed before transport. This preserves the cross-file context needed to catch
reference drift, protocol mismatches, and lifecycle wiring defects.

## Gate seniority

`load_bearing` is the fail-closed default. `secondary` changes only the disposition
of retryable reviewer infrastructure failure: it may report
`blocks_handoff=false` when a stronger executable exact-SHA gate is authoritative.
Concrete findings, privacy/policy failures, secret findings, and stale candidates
always block. Pre-work design criticism stays outside this plugin and has no
receipt or release authority.

## Receipt signature

The HMAC-SHA256 signature covers the canonical `receipt`, `verdict`, and `metrics`
objects. The receipt includes requirements/evidence hashes so a PASS cannot be
reused under changed acceptance criteria or claimed verification. The signing key
remains local, must be a regular `0600` file, and is never sent to the reviewer.
Release automation must verify the signature against the current candidate rather
than trusting a copied JSON status string.

## Observability

JSONL metrics contain status, model, route fingerprint, duration, attempts, token counts, and normalized error class. Raw exception text, endpoints, credentials, prompts, source code, and findings are intentionally excluded.
