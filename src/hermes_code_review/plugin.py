from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import core

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


def _route() -> tuple[str, dict[str, Any], dict[str, Any]]:
    cfg = core.load_config()
    name = core.selected_name(cfg)
    workers = (cfg.get("main_token_reserve") or {}).get("workers") or {}
    worker = workers.get(name)
    if not name or not isinstance(worker, dict):
        raise RuntimeError("fixed code-review worker is not configured")
    return name, worker, cfg


def review_git_candidate(args: dict, **_: Any) -> str:
    try:
        name, worker, cfg = _route()
        settings = cfg.get("code_review") or {}
        result = core.run_git_review(
            Path(str(args["repo"])),
            name,
            worker,
            requirements=str(args.get("requirements") or ""),
            evidence=str(args.get("evidence") or ""),
            attempts=1,
            timeout=240,
            current_worker=lambda: _route()[1],
            budget_path=core.BUDGET,
            max_input_tokens=int(settings.get("max_input_tokens") or 120_000),
            daily_input_tokens=int(settings.get("daily_input_tokens") or 1_000_000),
        )
        verdict = result["verdict"]
        status = "PASS" if verdict.get("passed") is True and verdict.get("safe_to_commit") is True else "BLOCKED"
        public = {
            "status": status,
            "verdict": verdict,
            "receipt": result["receipt"],
            "route": result.get("route", {}),
            "metrics": result.get("metrics", {}),
        }
        return json.dumps(public, ensure_ascii=False, sort_keys=True)
    except Exception as exc:
        return json.dumps({"status": "INFRA_FAILED", "error": str(exc)}, ensure_ascii=False, sort_keys=True)


def code_review_status(args: dict, **_: Any) -> str:
    del args
    try:
        name, worker, _cfg = _route()
        snapshot = core.worker_snapshot(name, worker)
        return json.dumps({
            "status": "READY",
            "worker": name,
            "model": snapshot["model"],
            "api_mode": snapshot["api_mode"],
            "route_sha": snapshot["route_sha"],
            "fallback": "fail",
        }, ensure_ascii=False, sort_keys=True)
    except Exception as exc:
        return json.dumps({"status": "INFRA_FAILED", "error": str(exc)}, ensure_ascii=False, sort_keys=True)


def register(ctx) -> None:
    ctx.register_tool(name="review_git_candidate", toolset="code_review", schema=REVIEW_SCHEMA, handler=review_git_candidate)
    ctx.register_tool(name="code_review_status", toolset="code_review", schema=STATUS_SCHEMA, handler=code_review_status)
