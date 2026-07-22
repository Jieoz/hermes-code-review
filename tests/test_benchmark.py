from pathlib import Path


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


def test_live_benchmark_uses_one_fixed_route_and_reports_recall(monkeypatch):
    from hermes_code_review import benchmark
    cases = [{"id": "a", "file": "a.py", "severity": "p1", "keywords": ["shell"], "diff": "diff"}]
    seen = {}
    def runner(source, acceptance, evidence, reviewer, worker, **kwargs):
        seen["reviewer"] = reviewer
        return {"verdict": {"p0": [], "p1": [{"file": "a.py", "line": 1, "issue": "shell injection"}]}, "receipt": {}, "metrics": {}}
    result = benchmark.run_benchmark(cases, "fixed", {"model": "grok-4.5"}, runner=runner)
    assert seen["reviewer"] == "fixed"
    assert result["evaluation"]["recall"] == 1.0
