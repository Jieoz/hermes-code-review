from __future__ import annotations

import json

REVIEW_SCHEMA = {
    "name": "review_git_candidate",
    "description": "Review the immutable staged Git candidate with the configured fixed independent reviewer. Fails closed on drift, infrastructure errors, secrets, or invalid verdicts.",
    "parameters": {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Absolute path to a Git repository with the intended candidate staged."},
            "requirements": {"type": "string", "description": "Acceptance criteria."},
            "evidence": {"type": "string", "description": "Deterministic test/static evidence to scrutinize."},
        },
        "required": ["repo"],
    },
}

STATUS_SCHEMA = {
    "name": "code_review_status",
    "description": "Read the fixed independent reviewer identity and health without exposing credentials.",
    "parameters": {"type": "object", "properties": {}},
}


def _not_implemented(args: dict, **kwargs) -> str:
    return json.dumps({"status": "INFRA_FAILED", "error": "not implemented"})


def register(ctx) -> None:
    ctx.register_tool(name="review_git_candidate", toolset="code_review", schema=REVIEW_SCHEMA, handler=_not_implemented)
    ctx.register_tool(name="code_review_status", toolset="code_review", schema=STATUS_SCHEMA, handler=_not_implemented)
