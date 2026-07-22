from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_corpus(path: Path) -> list[dict[str, Any]]:
    cases = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError("corpus must be a non-empty list")
    ids: set[str] = set()
    for case in cases:
        required = {"id", "file", "severity", "keywords", "diff"}
        if not isinstance(case, dict) or not required.issubset(case):
            raise ValueError("invalid corpus case")
        if case["id"] in ids:
            raise ValueError(f"duplicate corpus id: {case['id']}")
        ids.add(case["id"])
        if case["severity"] not in {"p0", "p1"}:
            raise ValueError("corpus severity must be p0 or p1")
        if not isinstance(case["keywords"], list) or not case["keywords"]:
            raise ValueError("corpus keywords must be a non-empty list")
    return cases


def evaluate_verdict(cases: list[dict[str, Any]], verdict: dict[str, Any]) -> dict[str, Any]:
    findings = list(verdict.get("p0") or []) + list(verdict.get("p1") or [])
    hits: list[str] = []
    missed: list[str] = []
    for case in cases:
        matched = False
        for finding in findings:
            if str(finding.get("file") or "") != case["file"]:
                continue
            issue = str(finding.get("issue") or "").lower()
            if all(str(word).lower() in issue for word in case["keywords"]):
                matched = True
                break
        (hits if matched else missed).append(case["id"])
    total = len(cases)
    return {
        "total": total,
        "hits": hits,
        "missed": missed,
        "recall": len(hits) / total if total else 0.0,
    }


def build_bundle(cases: list[dict[str, Any]]) -> bytes:
    return "\n".join(str(case["diff"]) for case in cases).encode("utf-8")


def run_benchmark(cases: list[dict[str, Any]], reviewer: str, worker: dict[str, Any], *, runner=None,
                  timeout: int = 240, **runner_kwargs: Any) -> dict[str, Any]:
    import hashlib
    from . import core

    source = build_bundle(cases)
    digest = hashlib.sha256(source).hexdigest()
    snapshot = {"head": digest, "index_tree": digest, "diff_sha": digest}
    acceptance = (
        "Independent blind benchmark. Review every supplied unified diff. "
        "Report every release-blocking P0/P1 with exact file and changed line; "
        "do not assume tests make unsafe code acceptable."
    )
    evidence = "Synthetic known-defect corpus; no external evidence and no credentials."
    core.worker_snapshot(reviewer, worker)
    core.policy.check_privacy([str(case['file']) for case in cases], source, acceptance, evidence)
    runner_kwargs.setdefault('budget_path', core.BUDGET)
    runner_kwargs.setdefault('max_input_tokens', 120_000)
    runner_kwargs.setdefault('daily_input_tokens', 1_000_000)
    runner_kwargs.setdefault('max_output_tokens', 4_096)
    runner_kwargs.setdefault('daily_output_tokens', 100_000)
    call = runner or core.run_review
    result = call(
        source, acceptance, evidence, reviewer, worker,
        timeout=timeout, snapshot=snapshot, persist=False, **runner_kwargs,
    )
    return {"evaluation": evaluate_verdict(cases, result["verdict"]), "review": result}
