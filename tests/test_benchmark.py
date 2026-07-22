from pathlib import Path


def configured_worker():
    return {
        'provider': 'custom', 'base_url': 'https://review.example/v1',
        'api_key': 'secret', 'model': 'grok-4.5',
        'api_mode': 'chat_completions', 'enabled': True,
    }


def test_known_defect_corpus_is_valid_and_unique():
    from hermes_code_review.benchmark import load_corpus
    cases = load_corpus(Path("corpus/known_defects.json"))
    assert len(cases) >= 4
    assert len({case["id"] for case in cases}) == len(cases)


def test_evaluator_measures_exact_case_recall():
    from hermes_code_review.benchmark import evaluate_verdict
    cases = [{"id": "a", "file": "a.py", "severity": "p1", "keywords": ["shell", "injection"], "diff": "x"}]
    verdict = {"p0": [], "p1": [{"file": "a.py", "line": 2, "issue": "Shell command injection"}]}
    assert evaluate_verdict(cases, verdict) == {"total": 1, "hits": ["a"], "missed": [], "recall": 1.0}


def test_evaluator_recognizes_toctou_index_finding():
    from hermes_code_review.benchmark import evaluate_verdict, load_corpus
    cases = [case for case in load_corpus(Path("corpus/known_defects.json"))
             if case["id"] == "toctou-index"]
    verdict = {"p0": [{"file": "release/gate.py", "line": 33,
                        "issue": "TOCTOU bypass publishes a fresh git_index_tree"}], "p1": []}
    assert evaluate_verdict(cases, verdict)["recall"] == 1.0


def test_live_benchmark_uses_one_fixed_route_and_reports_recall(monkeypatch):
    from hermes_code_review import benchmark, core
    cases = [{"id": "a", "file": "a.py", "severity": "p1", "keywords": ["shell"], "diff": "diff"}]
    seen = {}
    def runner(reviewer, worker, source, head, index_tree, **kwargs):
        seen['reviewer'] = reviewer
        seen['worker'] = worker
        seen['source'] = source
        seen['head'] = head
        seen['index_tree'] = index_tree
        seen.update(kwargs)
        return {"verdict": {"p0": [], "p1": [{"file": "a.py", "line": 1, "issue": "shell injection"}]}, "receipt": {}, "metrics": {}}
    result = benchmark.run_benchmark(cases, "hybgzs_grok45", configured_worker(), runner=runner)
    assert seen["reviewer"] == "hybgzs_grok45"
    assert seen["budget_path"] == core.BUDGET
    assert {"max_input_tokens", "daily_input_tokens", "max_output_tokens",
            "daily_output_tokens"}.issubset(seen)
    assert result["evaluation"]["recall"] == 1.0


def test_benchmark_rejects_wrong_route_before_runner():
    import pytest
    from hermes_code_review import benchmark
    called = False
    def runner(*args, **kwargs):
        nonlocal called
        called = True
    with pytest.raises(ValueError, match="fixed approved reviewer"):
        benchmark.run_benchmark(
            [{"id": "a", "file": "a.py", "severity": "p1",
              "keywords": ["shell"], "diff": "diff"}],
            "wrong-worker", configured_worker(), runner=runner,
        )
    assert called is False


def test_benchmark_rejects_nonpositive_budget_before_runner():
    import pytest
    from hermes_code_review import benchmark
    called = False
    def runner(*args, **kwargs):
        nonlocal called
        called = True
    with pytest.raises(ValueError, match="max_output_tokens must be positive"):
        benchmark.run_benchmark(
            [{"id": "a", "file": "a.py", "severity": "p1",
              "keywords": ["shell"], "diff": "diff"}],
            "hybgzs_grok45", configured_worker(), runner=runner,
            max_output_tokens=0,
        )
    assert called is False


def test_actual_corpus_is_evaluated_end_to_end_without_transport():
    from hermes_code_review import benchmark
    cases = benchmark.load_corpus(Path("corpus/known_defects.json"))
    findings = [
        {"file": "app/export.py", "line": 9, "issue": "shell command injection"},
        {"file": "app/auth.py", "line": 17, "issue": "fail-open auth"},
        {"file": "app/archive.py", "line": 22, "issue": "path traversal"},
        {"file": "release/gate.py", "line": 33, "issue": "TOCTOU bypass uses a fresh index"},
    ]
    def runner(*args, **kwargs):
        return {"verdict": {"p0": [], "p1": findings}, "receipt": {}, "metrics": {}}
    result = benchmark.run_benchmark(
        cases, "hybgzs_grok45", configured_worker(), runner=runner,
    )
    assert result["evaluation"] == {
        "total": 4,
        "hits": ["shell-injection", "fail-open-auth", "zip-slip", "toctou-index"],
        "missed": [],
        "recall": 1.0,
    }


def test_benchmark_privacy_preflight_runs_before_transport():
    import pytest
    from hermes_code_review import benchmark, policy
    cases = [{"id": "a", "file": "a.py", "severity": "p1", "keywords": ["shell"], "diff": "+Authorization: Bearer " + "a" * 16}]
    called = False
    def runner(*args, **kwargs):
        nonlocal called
        called = True
    with pytest.raises(policy.PolicyViolation, match="secret-like"):
        benchmark.run_benchmark(cases, "hybgzs_grok45", configured_worker(), runner=runner)
    assert called is False
