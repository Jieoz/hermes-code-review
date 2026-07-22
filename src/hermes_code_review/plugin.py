from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import __version__, core, observability, policy, signing

SIGNING_KEY = core.HERMES_HOME / "secrets/code_review_receipt.key"
METRICS = core.HERMES_HOME / "state/code_review_metrics.jsonl"

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
    "description": "Read the fixed reviewer identity and local readiness (configuration and circuit state) without exposing credentials or spending a network probe.",
    "parameters": {"type": "object", "properties": {}},
}


def _route() -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    cfg = core.load_config()
    name = core.selected_name(cfg)
    workers = (cfg.get("main_token_reserve") or {}).get("workers") or {}
    worker = workers.get(name)
    if name != core.APPROVED_WORKER or not isinstance(worker, dict):
        raise RuntimeError("fixed code-review worker is not configured")
    snapshot = core.worker_snapshot(name, worker)
    return name, worker, cfg, snapshot


def _error_class(exc: Exception) -> str:
    classified = observability.classify_error(str(exc))
    if classified != "OTHER":
        return classified
    return type(exc).__name__.replace("Error", "_ERROR").upper()


def _public_result(result: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    receipt_keys = (
        "review_head", "review_index_tree", "review_diff_sha",
        "review_route_sha", "reviewer_model",
    )
    metric_keys = ("attempts", "elapsed_ms", "input_tokens", "output_tokens", "chunk_count")
    receipt = result.get("receipt") or {}
    metrics = result.get("metrics") or {}
    signature = result.get("signature") or {}
    public = {
        "verdict": result.get("verdict"),
        "receipt": {key: receipt[key] for key in receipt_keys if key in receipt},
        "route": core.public_route(snapshot),
        "metrics": {key: int(metrics[key]) for key in metric_keys if key in metrics},
        "signature": {
            "algorithm": signature.get("algorithm"),
            "digest": signature.get("digest"),
        },
    }
    policy.assert_public_payload_safe(public, forbidden=[str(snapshot.get("credential") or "")])
    return public


def review_git_candidate(args: dict, **_: Any) -> str:
    started = time.monotonic()
    worker_name = ""
    model = ""
    route_sha = ""
    try:
        name, worker, cfg, snapshot = _route()
        worker_name = name
        model = str(worker.get("model") or "")
        settings = cfg.get("code_review") or {}
        signing.create_signing_key(SIGNING_KEY)
        result = core.run_git_review(
            Path(str(args["repo"])),
            name,
            worker,
            requirements=str(args.get("requirements") or ""),
            evidence=str(args.get("evidence") or ""),
            attempts=1,
            timeout=max(1, min(int(args.get("timeout") or 240), 600)),
            current_worker=lambda: _route()[1],
            budget_path=core.BUDGET,
            max_input_tokens=int(settings.get("max_input_tokens") or 120_000),
            daily_input_tokens=int(settings.get("daily_input_tokens") or 1_000_000),
            max_output_tokens=int(settings.get("max_output_tokens") or 4_096),
            daily_output_tokens=int(settings.get("daily_output_tokens") or 100_000),
            signing_key_path=SIGNING_KEY,
            max_source_bytes=int(settings.get("max_source_bytes") or 350_000),
        )
        signing.verify_result(result, SIGNING_KEY)
        public = _public_result(result, snapshot)
        verdict = public["verdict"]
        status = "PASS" if verdict.get("passed") is True and verdict.get("safe_to_commit") is True else "BLOCKED"
        public["status"] = status
        route_sha = str((result.get("route") or {}).get("route_sha") or "")
        metrics = result.get("metrics") or {}
        observability.record_event(
            METRICS, status=status, worker=worker_name, model=model,
            route_sha=route_sha,
            elapsed_ms=int(metrics.get("elapsed_ms") or 0),
            input_tokens=int(metrics.get("input_tokens") or 0),
            output_tokens=int(metrics.get("output_tokens") or 0),
        )
        return json.dumps(public, ensure_ascii=False, sort_keys=True)
    except Exception as exc:
        try:
            observability.record_event(
                METRICS, status="INFRA_FAILED", worker=worker_name,
                model=model, route_sha=route_sha,
                elapsed_ms=round((time.monotonic() - started) * 1000),
                input_tokens=0, output_tokens=0, error=str(exc),
            )
        except Exception:
            pass
        return json.dumps({"status": "INFRA_FAILED", "error_class": _error_class(exc)}, ensure_ascii=False, sort_keys=True)


def _local_status_payload() -> dict:
    """Validate the fixed local route without making a reviewer request."""
    name, _worker, _cfg, snapshot = _route()
    core.assert_circuit_closed(core.STATE, snapshot["route_sha"])
    return {
        "status": "READY",
        "version": __version__,
        "worker": name,
        "model": snapshot["model"],
        "api_mode": snapshot["api_mode"],
        "route_sha": snapshot["route_sha"],
        "fallback": "fail",
    }


def code_review_status(args: dict, **_: Any) -> str:
    del args
    try:
        payload = _local_status_payload()
    except Exception as exc:
        payload = {"status": "INFRA_FAILED", "error_class": _error_class(exc)}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def register(ctx) -> None:
    ctx.register_tool(name="review_git_candidate", toolset="code_review", schema=REVIEW_SCHEMA, handler=review_git_candidate)
    ctx.register_tool(name="code_review_status", toolset="code_review", schema=STATUS_SCHEMA, handler=code_review_status)
