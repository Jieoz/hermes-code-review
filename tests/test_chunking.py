from __future__ import annotations

import hashlib
import subprocess


def init_repo(path):
    subprocess.run(['git', 'init', '-q', str(path)], check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.email', 'test@local'], check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.name', 'Test'], check=True)
    (path / 'base.txt').write_text('base\n')
    subprocess.run(['git', '-C', str(path), 'add', 'base.txt'], check=True)
    subprocess.run(['git', '-C', str(path), 'commit', '-qm', 'base'], check=True)


def worker():
    return {'provider': 'custom', 'base_url': 'https://review.example/v1', 'api_key': 'secret', 'model': 'grok-4.5', 'api_mode': 'chat_completions', 'enabled': True}


def result_for(core, source, passed):
    snap = core.worker_snapshot('r', worker())
    receipt = core.snapshot_receipt_bytes(source, 'h', 't', route_sha=snap['route_sha'], reviewer_model=snap['model'])
    finding = [] if passed else [{'file': 'b.py', 'line': 1, 'issue': 'wrong branch'}]
    verdict = {
        'passed': passed, **receipt, 'p0': [], 'p1': finding, 'p2': [],
        'needs_evidence': [], 'security_concerns': [], 'safe_to_commit': passed,
        'summary': 'clean' if passed else 'blocked',
    }
    return {'receipt': receipt, 'verdict': verdict,
            'route': {k: snap[k] for k in ('name', 'endpoint', 'model', 'api_mode', 'route_sha')},
            'metrics': {'attempts': 1, 'elapsed_ms': 3, 'input_tokens': 10, 'output_tokens': 2}}


def test_staged_diff_is_split_only_at_file_boundaries(tmp_path):
    from hermes_code_review import core
    init_repo(tmp_path)
    for name in ('a.py', 'b.py', 'c.py'):
        (tmp_path / name).write_text('x = ' + repr(name * 30) + '\n')
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'a.py', 'b.py', 'c.py'], check=True)
    frozen = core.freeze_git_candidate(tmp_path)
    chunks = core.chunk_staged_diff(tmp_path, frozen['paths'], max_source_bytes=350)
    assert len(chunks) >= 2
    assert all(len(chunk['diff']) <= 350 for chunk in chunks)
    assert sorted(path for chunk in chunks for path in chunk['paths']) == ['a.py', 'b.py', 'c.py']


def test_segmented_review_aggregates_blockers_and_full_identity(tmp_path, monkeypatch):
    from hermes_code_review import core
    full = b'full staged diff larger than cap'
    frozen = {'repo': tmp_path, 'head': 'h', 'index_tree': 't', 'diff': full, 'paths': ['a.py', 'b.py']}
    monkeypatch.setattr(core, 'freeze_git_candidate', lambda repo: frozen)
    monkeypatch.setattr(core, 'chunk_staged_diff', lambda repo, paths, max_source_bytes: [
        {'paths': ['a.py'], 'diff': b'chunk-a'}, {'paths': ['b.py'], 'diff': b'chunk-b'},
    ])
    calls = []
    def runner(name, worker_value, source, head, index_tree, **kwargs):
        calls.append(source)
        return result_for(core, source, passed=source == b'chunk-a')
    result = core.run_git_review(tmp_path, 'r', worker(), runner=runner,
                                 runs_dir=tmp_path / 'runs', max_source_bytes=5)
    assert calls == [b'chunk-a', b'chunk-b']
    assert result['verdict']['passed'] is False
    assert result['verdict']['p1'][0]['file'] == 'b.py'
    assert result['receipt']['review_diff_sha'] == hashlib.sha256(full).hexdigest()
    assert result['metrics']['chunk_count'] == 2
