# Architecture

## Trust boundary

The local Hermes process owns Git inspection, secret scanning, budget reservation, candidate identity, result validation, persistence, signing, and metrics. The remote reviewer receives only:

- staged unified diff bytes;
- explicit acceptance criteria;
- deterministic test/evidence text;
- a non-secret receipt containing HEAD, index tree, diff SHA, and route fingerprint.

It receives no terminal, Docker, SSH, filesystem, GitHub, or secret-file access.

## Candidate state machine

1. Resolve and validate the fixed reviewer worker.
2. Reject dirty tracked worktree files and non-ignored untracked files.
3. Freeze `HEAD`, `git write-tree`, staged diff SHA, and staged paths.
4. Run local privacy and token-budget preflight.
5. Review once or by file-bound chunks.
6. Validate strict verdict shape and all P0/P1 `file:line` references.
7. Re-freeze HEAD and index. Any mismatch becomes `STALE`.
8. Build the aggregate receipt, sign it locally, and atomically persist it.
9. Allow release only when the signature verifies and `safe_to_commit=true`.

## Agent invocation contract

The release owner invokes this gate proactively after all deterministic checks and
before commit/push/release. The gate covers only the staged HEAD + index tree it
receives. Any code, test, documentation, packaging, or staging change invalidates
the prior verdict. Read-only investigation and incomplete work are intentionally
outside the gate so reviewer budget is spent only on final candidates.

## Route identity

The route fingerprint hashes only provider name, model, normalized API mode, and canonical endpoint. It never hashes or serializes API keys, authorization headers, or key-file contents.

There is no fallback under the same approval identity. A transport or reviewer failure is an infrastructure failure, not a PASS.

## Segmentation

Segmentation is deterministic and file-boundary only. The full candidate identity stays authoritative. Every chunk result must report the same model and route fingerprint; an oversized single-file diff is rejected. The aggregate Verdict is the conjunction of every chunk Verdict and concatenates all findings.

## Receipt signature

The HMAC-SHA256 signature covers the canonical `receipt`, `verdict`, and `metrics` objects. The signing key remains local, must be a regular `0600` file, and is never sent to the reviewer. Release automation must verify the signature against the current candidate rather than trusting a copied JSON status string.

## Observability

JSONL metrics contain status, model, route fingerprint, duration, attempts, token counts, and normalized error class. Raw exception text, endpoints, credentials, prompts, source code, and findings are intentionally excluded.
