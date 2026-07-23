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
            "release_gate": {"type": "boolean", "description": "Allow this final tag, release, or deployment review to consume the protected release budget reserve."},
        },
        "required": ["repo"],
    },
}

STATUS_SCHEMA = {
    "name": "code_review_status",
    "description": "Read the fixed reviewer identity and local readiness (configuration and circuit state) without exposing credentials or spending a network probe.",
    "parameters": {"type": "object", "properties": {}},
}


def _routes() -> tuple[list[tuple[str, dict[str, Any], dict[str, Any]]], dict[str, Any]]:
    cfg = core.load_config()
    workers = (cfg.get("main_token_reserve") or {}).get("workers") or {}
    settings = cfg.get("code_review") or {}
    names = settings.get("workers")
    if names is None:
        names = [core.selected_name(cfg), *(settings.get("fallback_workers") or [])]
    if (
        not isinstance(names, list)
        or not names
        or not all(isinstance(name, str) and name for name in names)
        or len(names) != len(set(names))
    ):
        raise RuntimeError("code-review workers must be a non-empty list of unique worker names")
    routes = []
    for name in names:
        worker = workers.get(name)
        if not isinstance(worker, dict):
            raise RuntimeError("configured code-review route is not preapproved")
        routes.append((name, worker, core.worker_snapshot(name, worker)))
    return routes, cfg


def _route() -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    routes, cfg = _routes()
    name, worker, snapshot = routes[0]
    return name, worker, cfg, snapshot


def _current_worker(name: str) -> dict[str, Any]:
    cfg = core.load_config()
    worker = (((cfg.get("main_token_reserve") or {}).get("workers") or {}).get(name))
    if not isinstance(worker, dict):
        raise RuntimeError("configured code-review route disappeared")
    return worker


def _pool_identity(routes: list[tuple[str, dict[str, Any], dict[str, Any]]]) -> tuple[tuple[str, str], ...]:
    return tuple((name, str(snapshot["route_sha"])) for name, _worker, snapshot in routes)


def _current_pool_worker(expected_pool: tuple[tuple[str, str], ...], name: str) -> dict[str, Any]:
    current_routes, _cfg = _routes()
    if _pool_identity(current_routes) != expected_pool:
        raise RuntimeError("reviewer pool changed during request")
    for route_name, worker, _snapshot in current_routes:
        if route_name == name:
            return worker
    raise RuntimeError("reviewer removed from pool during request")


def _error_class(exc: Exception) -> str:
    classified = observability.classify_error(str(exc))
    if classified != "OTHER":
        return classified
    if isinstance(exc, core.ReviewTransportError):
        return "TRANSPORT"
    return type(exc).__name__.replace("Error", "_ERROR").upper()


def _fallback_eligible(exc: Exception) -> bool:
    if isinstance(exc, core.ReviewHTTPError):
        return exc.status == 429 or 500 <= exc.status <= 599
    if isinstance(exc, (core.ReviewTransportError, core.InvalidVerdictError)):
        return True
    return isinstance(exc, core.CircuitOpenError)


def _positive_setting(settings: dict[str, Any], key: str, default: int) -> int:
    value = default if key not in settings else settings[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"code_review.{key} must be a positive integer")
    if value <= 0:
        raise RuntimeError(f"code_review.{key} must be a positive integer")
    return value


def _nonnegative_setting(settings: dict[str, Any], key: str, default: int = 0) -> int:
    value = default if key not in settings else settings[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError(f"code_review.{key} must be a nonnegative integer")
    return value


def _public_result(result: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    receipt_keys = (
        "review_head", "review_index_tree", "review_diff_sha",
        "review_route_sha", "reviewer_model", "review_requirements_sha",
        "review_evidence_sha",
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
        routes, cfg = _routes()
        expected_pool = _pool_identity(routes)
        settings = cfg.get("code_review") or {}
        invocation_frozen = core.freeze_git_candidate(Path(str(args["repo"])))
        signing.create_signing_key(SIGNING_KEY)
        result = None
        snapshot = None
        route_index = 0
        for route_index, (name, worker, candidate_snapshot) in enumerate(routes):
            worker_name = name
            model = str(worker.get("model") or "")
            route_sha = str(candidate_snapshot["route_sha"])
            try:
                result = core.run_git_review(
                    Path(str(args["repo"])),
                    name,
                    worker,
                    requirements=str(args.get("requirements") or ""),
                    evidence=str(args.get("evidence") or ""),
                    attempts=2,
                    timeout=max(1, min(int(args.get("timeout") or 240), 600)),
                    current_worker=lambda route_name=name: _current_pool_worker(expected_pool, route_name),
                    budget_path=core.BUDGET,
                    max_input_tokens=_positive_setting(settings, "max_input_tokens", 120_000),
                    daily_input_tokens=_nonnegative_setting(settings, "daily_input_tokens"),
                    max_output_tokens=_positive_setting(settings, "max_output_tokens", 8_192),
                    daily_output_tokens=_nonnegative_setting(settings, "daily_output_tokens"),
                    release_input_reserve=_nonnegative_setting(settings, "release_input_reserve"),
                    allow_release_reserve=args.get("release_gate") is True,
                    signing_key_path=SIGNING_KEY,
                    max_source_bytes=_positive_setting(settings, "max_source_bytes", 350_000),
                    expected_candidate=invocation_frozen,
                )
                snapshot = candidate_snapshot
                break
            except Exception as route_exc:
                if route_index + 1 >= len(routes) or not _fallback_eligible(route_exc):
                    raise
                current = core.freeze_git_candidate(invocation_frozen["repo"])
                if (
                    current["head"] != invocation_frozen["head"]
                    or current["index_tree"] != invocation_frozen["index_tree"]
                ):
                    raise RuntimeError(
                        "stale review candidate: Git HEAD or INDEX_TREE changed before fallback"
                    ) from route_exc
                observability.record_event(
                    METRICS, status="INFRA_FAILED", worker=worker_name,
                    model=model, route_sha=route_sha,
                    elapsed_ms=round((time.monotonic() - started) * 1000),
                    input_tokens=0, output_tokens=0, error=str(route_exc),
                )
        if result is None or snapshot is None:
            raise RuntimeError("review routes completed without a result")
        receipt = result.get("receipt") or {}
        if (
            receipt.get("review_head") != invocation_frozen["head"]
            or receipt.get("review_index_tree") != invocation_frozen["index_tree"]
        ):
            raise RuntimeError("stale review verdict: route result does not match invocation candidate")
        signing.verify_result(result, SIGNING_KEY)
        public = _public_result(result, snapshot)
        verdict = public["verdict"]
        status = "PASS" if verdict.get("passed") is True and verdict.get("safe_to_commit") is True else "BLOCKED"
        public["status"] = status
        public["fallback_used"] = route_index > 0
        public["reused"] = result.get("reused") is True
        route_sha = str((result.get("route") or {}).get("route_sha") or "")
        metrics = result.get("metrics") or {}
        reused = result.get("reused") is True
        observability.record_event(
            METRICS, status=status, worker=worker_name, model=model,
            route_sha=route_sha,
            elapsed_ms=int(metrics.get("elapsed_ms") or 0),
            input_tokens=0 if reused else int(metrics.get("input_tokens") or 0),
            output_tokens=0 if reused else int(metrics.get("output_tokens") or 0),
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
    """Validate preapproved local routes without making a reviewer request."""
    routes, cfg = _routes()
    settings = cfg.get("code_review") or {}
    daily_input = _nonnegative_setting(settings, "daily_input_tokens")
    daily_output = _nonnegative_setting(settings, "daily_output_tokens")
    release_reserve = _nonnegative_setting(settings, "release_input_reserve")
    route_rows = []
    for name, _worker, snapshot in routes:
        try:
            core.assert_circuit_closed(core.STATE, snapshot["route_sha"])
            route_status = "READY"
        except RuntimeError as exc:
            if "circuit open" not in str(exc).lower():
                raise
            route_status = "CIRCUIT_OPEN"
        route_rows.append({
            "worker": name,
            "model": snapshot["model"],
            "api_mode": snapshot["api_mode"],
            "route_sha": snapshot["route_sha"],
            "status": route_status,
            "budget": policy.budget_status(
                core.BUDGET,
                route_sha=snapshot["route_sha"],
                daily_input_limit=daily_input,
                daily_output_limit=daily_output,
                release_input_reserve=release_reserve,
            ),
        })
    if not any(row["status"] == "READY" for row in route_rows):
        raise RuntimeError("review worker circuit open")
    primary = route_rows[0]
    fallbacks = route_rows[1:]
    return {
        "status": "READY",
        "version": __version__,
        "worker": primary["worker"],
        "model": primary["model"],
        "api_mode": primary["api_mode"],
        "route_sha": primary["route_sha"],
        "primary_status": primary["status"],
        "fallback": "preapproved_infra_only" if fallbacks else "fail",
        "fallback_workers": fallbacks,
        "budget": primary["budget"],
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
