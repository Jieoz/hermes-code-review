from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest


def init_repo(path: Path):
    subprocess.run(['git', 'init', '-q', str(path)], check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.email', 'test@local'], check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.name', 'Test'], check=True)
    (path / 'code.py').write_text('value = 1\n')
    subprocess.run(['git', '-C', str(path), 'add', 'code.py'], check=True)
    subprocess.run(['git', '-C', str(path), 'commit', '-qm', 'baseline'], check=True)


def test_freeze_binds_head_and_index_tree(tmp_path):
    from hermes_code_review import core
    init_repo(tmp_path)
    (tmp_path / 'code.py').write_text('value = 2\n')
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'code.py'], check=True)
    frozen = core.freeze_git_candidate(tmp_path)
    assert frozen['head'] == subprocess.check_output(['git', '-C', str(tmp_path), 'rev-parse', 'HEAD'], text=True).strip()
    assert frozen['index_tree'] == subprocess.check_output(['git', '-C', str(tmp_path), 'write-tree'], text=True).strip()
    assert frozen['paths'] == ['code.py']
    assert b'value = 2' in frozen['diff']


def test_freeze_rejects_tracked_unstaged_and_untracked(tmp_path):
    from hermes_code_review import core
    init_repo(tmp_path)
    (tmp_path / 'code.py').write_text('value = 2\n')
    with pytest.raises(RuntimeError, match='tracked unstaged'):
        core.freeze_git_candidate(tmp_path)
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'code.py'], check=True)
    (tmp_path / 'helper.py').write_text('value = 99\n')
    with pytest.raises(RuntimeError, match='untracked'):
        core.freeze_git_candidate(tmp_path)


def test_route_fingerprint_excludes_credentials():
    from hermes_code_review import core
    base = {'provider': 'custom', 'base_url': 'https://review.example/v1', 'model': 'grok-4.5', 'api_mode': 'chat_completions', 'enabled': True}
    a = core.worker_snapshot(core.APPROVED_WORKER, {**base, 'api_key': 'secret-one'})
    b = core.worker_snapshot(core.APPROVED_WORKER, {**base, 'api_key': 'secret-two'})
    assert a['route_sha'] == b['route_sha']
    assert 'secret' not in a['route_sha']


def test_every_approved_reviewer_has_a_recognized_model_family():
    from hermes_code_review import core
    unknown = {
        model for model, _api_mode in core.APPROVED_REVIEWER_IDENTITIES
        if core.model_family(model) is None
    }
    assert unknown == set()


def test_keyfile_must_be_0600_and_under_allowed_dir(tmp_path, monkeypatch):
    from hermes_code_review import core
    monkeypatch.setattr(core, 'RESERVE_KEY_DIR', tmp_path)
    path = tmp_path / 'key'
    path.write_text('secret\n')
    path.chmod(0o600)
    worker = {'provider': 'custom', 'base_url': 'https://review.example/v1', 'model': 'grok-4.5', 'api_mode': 'chat_completions', 'enabled': True, 'api_key_file': str(path)}
    assert core.worker_snapshot(core.APPROVED_WORKER, worker)['credential'] == 'secret'
    path.chmod(0o644)
    with pytest.raises(ValueError, match='permissions'):
        core.worker_snapshot(core.APPROVED_WORKER, worker)
    path.chmod(0o600)
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(ValueError, match='regular file'):
        core.worker_snapshot(core.APPROVED_WORKER, {**worker, 'api_key_file': str(link)})
    nested = tmp_path / 'nested'
    nested.mkdir()
    nested_key = nested / 'key'
    nested_key.write_text('secret')
    nested_key.chmod(0o600)
    with pytest.raises(ValueError, match='direct child'):
        core.worker_snapshot(core.APPROVED_WORKER, {**worker, 'api_key_file': str(nested_key)})


def test_strict_verdict_requires_evidence_and_identity():
    from hermes_code_review import core
    receipt = {
        'review_head': 'h', 'review_index_tree': 't', 'review_diff_sha': 'd',
        'review_route_sha': 'r', 'reviewer_model': 'grok-4.5',
        'review_requirements_sha': 'q', 'review_evidence_sha': 'e',
    }
    value = {'passed': False, **receipt, 'p0': [], 'p1': [{'file': 'x.py', 'line': 1, 'issue': 'bug'}], 'p2': [], 'needs_evidence': [], 'security_concerns': [], 'safe_to_commit': False, 'summary': 'blocked'}
    assert core.validate_verdict(value, receipt) == value
    value['p1'] = ['vague']
    with pytest.raises(ValueError, match='file/line/issue'):
        core.validate_verdict(value, receipt)
    valid = {'passed': True, **receipt, 'p0': [], 'p1': [], 'p2': [], 'needs_evidence': [], 'security_concerns': [], 'safe_to_commit': True, 'summary': 'clean'}
    wrong_identity = {**valid, 'review_head': 'other'}
    with pytest.raises(ValueError, match='stale'):
        core.validate_verdict(wrong_identity, receipt)
    inconsistent = {**valid, 'safe_to_commit': False}
    with pytest.raises(ValueError, match='inconsistent'):
        core.validate_verdict(inconsistent, receipt)
    missing = dict(valid)
    missing.pop('review_route_sha')
    with pytest.raises(ValueError, match='schema'):
        core.validate_verdict(missing, receipt)


def test_circuit_failure_updates_are_atomic(tmp_path):
    from hermes_code_review import core
    state = tmp_path / 'health.json'
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: core.record_failure(state, 'route', threshold=1000), range(30)))
    assert json.loads(state.read_text())['route']['failures'] == 30


def test_circuit_state_reports_retry_after_without_raising(tmp_path):
    """circuit_state must expose open_until + retry_after_seconds instead of raising,
    so the status tool can tell a caller WHEN a route reopens (no blind polling)."""
    from hermes_code_review import core
    state = tmp_path / 'health.json'
    # Closed route: READY, zero wait.
    closed = core.circuit_state(state, 'route', now=100)
    assert closed == {'status': 'READY', 'open_until': 0, 'retry_after_seconds': 0}
    # Trip it: 300s cooldown opened at t=100.
    core.record_failure(state, 'route', threshold=1, cooldown=300, now=100)
    opened = core.circuit_state(state, 'route', now=101)
    assert opened['status'] == 'CIRCUIT_OPEN'
    assert opened['open_until'] == 400
    assert opened['retry_after_seconds'] == 299  # rounds up remaining wait
    # After cooldown lapses it reads READY again without any success write.
    lapsed = core.circuit_state(state, 'route', now=401)
    assert lapsed['status'] == 'READY'
    assert lapsed['retry_after_seconds'] == 0
