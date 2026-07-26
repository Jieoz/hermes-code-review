from __future__ import annotations

import subprocess


def init_repo(path):
    subprocess.run(['git', 'init', '-q', str(path)], check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.email', 'test@local'], check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.name', 'Test'], check=True)
    (path / 'base.txt').write_text('base\n')
    subprocess.run(['git', '-C', str(path), 'add', 'base.txt'], check=True)
    subprocess.run(['git', '-C', str(path), 'commit', '-qm', 'base'], check=True)


def worker():
    return {
        'provider': 'custom', 'base_url': 'https://review.example/v1',
        'api_key': 'secret', 'model': 'grok-4.5',
        'api_mode': 'chat_completions', 'enabled': True,
    }


def result_for(core, source, passed):
    snap = core.worker_snapshot(core.APPROVED_WORKER, worker())
    receipt = core.snapshot_receipt_bytes(
        source, 'h', 't', route_sha=snap['route_sha'], reviewer_model=snap['model'],
    )
    finding = [] if passed else [{'file': 'b.py', 'line': 1, 'issue': 'wrong branch'}]
    verdict = {
        'passed': passed, **receipt, 'p0': [], 'p1': finding, 'p2': [],
        'needs_evidence': [], 'security_concerns': [], 'safe_to_commit': passed,
        'summary': 'clean' if passed else 'blocked',
    }
    return {
        'receipt': receipt,
        'verdict': verdict,
        'route': {k: snap[k] for k in ('name', 'endpoint', 'model', 'api_mode', 'route_sha')},
        'metrics': {'attempts': 1, 'elapsed_ms': 3, 'input_tokens': 10, 'output_tokens': 2},
    }


def test_review_rejects_index_change_after_remote_verdict(tmp_path):
    import pytest
    from hermes_code_review import core
    init_repo(tmp_path)
    (tmp_path / 'a.py').write_text('value = 1\n')
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'a.py'], check=True)

    def runner(name, worker_value, source, head, index_tree, **kwargs):
        (tmp_path / 'a.py').write_text('value = 2\n')
        subprocess.run(['git', '-C', str(tmp_path), 'add', 'a.py'], check=True)
        return result_for(core, source, passed=True)

    with pytest.raises(RuntimeError, match='stale'):
        core.run_git_review(
            tmp_path, core.APPROVED_WORKER, worker(), runner=runner,
            runs_dir=tmp_path / 'runs',
        )


def test_complete_candidate_is_passed_to_one_reviewer_call(tmp_path, monkeypatch):
    from hermes_code_review import core
    full = b'x' * 249_606
    frozen = {
        'repo': tmp_path, 'head': 'h', 'index_tree': 't',
        'diff': full, 'paths': ['a.py', 'b.py'],
    }
    monkeypatch.setattr(core, 'freeze_git_candidate', lambda repo: frozen)
    calls = []

    def runner(name, worker_value, source, head, index_tree, **kwargs):
        calls.append(source)
        return result_for(core, source, passed=True)

    core.run_git_review(
        tmp_path, core.APPROVED_WORKER, worker(), runner=runner,
        runs_dir=tmp_path / 'runs',
    )
    assert calls == [full]
