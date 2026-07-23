from __future__ import annotations

import base64
import json

import pytest


def worker():
    return {
        'provider': 'custom', 'base_url': 'https://review.example/v1',
        'api_key': 'secret', 'model': 'grok-4.5',
        'api_mode': 'chat_completions', 'enabled': True,
    }


def test_exact_signed_pass_is_reused_only_for_matching_review_context(tmp_path, monkeypatch):
    from hermes_code_review import core, signing

    runs = tmp_path / 'runs'
    runs.mkdir()
    key = tmp_path / 'receipt.key'
    signing.create_signing_key(key)
    snapshot = core.worker_snapshot(core.APPROVED_WORKER, worker())
    frozen = {
        'head': 'head', 'index_tree': 'tree', 'diff': b'+safe = True\n',
        'paths': ['app.py'], 'repo': tmp_path,
    }
    receipt = core.snapshot_receipt_bytes(
        frozen['diff'], frozen['head'], frozen['index_tree'],
        route_sha=snapshot['route_sha'], reviewer_model=snapshot['model'],
        requirements='must be safe', evidence='tests passed',
    )
    verdict = {
        'passed': True, **receipt, 'p0': [], 'p1': [], 'p2': [],
        'needs_evidence': [], 'security_concerns': [], 'safe_to_commit': True,
        'summary': 'clean',
    }
    signed = signing.sign_result({
        'receipt': receipt, 'verdict': verdict,
        'route': core.public_route(snapshot),
        'metrics': {'attempts': 1, 'elapsed_ms': 1, 'input_tokens': 10, 'output_tokens': 2},
    }, key)
    (runs / '1000-pass.json').write_text(json.dumps(signed))

    reused = core.find_cached_pass(
        runs, frozen=frozen, route_snapshots=[snapshot],
        requirements='must be safe', evidence='tests passed', signing_key_path=key,
    )
    assert reused == signed
    assert core.find_cached_pass(
        runs, frozen=frozen, route_snapshots=[snapshot],
        requirements='different requirement', evidence='tests passed', signing_key_path=key,
    ) is None

    freezes = iter([frozen, frozen])
    monkeypatch.setattr(core, 'freeze_git_candidate', lambda repo: next(freezes))
    reused_by_review = core.run_git_review(
        tmp_path, core.APPROVED_WORKER, worker(),
        requirements='must be safe', evidence='tests passed',
        runner=lambda *a, **k: (_ for _ in ()).throw(AssertionError('remote runner')),
        runs_dir=runs, signing_key_path=key,
    )
    assert reused_by_review['reused'] is True
    assert reused_by_review['receipt'] == receipt

    changed = frozen | {'index_tree': 'changed-tree'}
    freezes = iter([frozen, changed])
    monkeypatch.setattr(core, 'freeze_git_candidate', lambda repo: next(freezes))
    with pytest.raises(RuntimeError, match='stale cached review'):
        core.run_git_review(
            tmp_path, core.APPROVED_WORKER, worker(),
            requirements='must be safe', evidence='tests passed',
            runner=lambda *a, **k: (_ for _ in ()).throw(AssertionError('remote runner')),
            runs_dir=runs, signing_key_path=key,
        )


def test_expected_invocation_candidate_is_checked_before_remote_runner(tmp_path, monkeypatch):
    from hermes_code_review import core

    expected = {
        'head': 'head', 'index_tree': 'tree', 'diff': b'+safe = True\n',
        'paths': ['app.py'], 'repo': tmp_path,
    }
    changed = expected | {'index_tree': 'changed-tree', 'diff': b'+unsafe = True\n'}
    monkeypatch.setattr(core, 'freeze_git_candidate', lambda repo: changed)
    called = False

    def runner(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError('remote runner must not receive a changed candidate')

    with pytest.raises(RuntimeError, match='changed before route review'):
        core.run_git_review(
            tmp_path, core.APPROVED_WORKER, worker(),
            runner=runner, runs_dir=tmp_path / 'runs',
            expected_candidate=expected,
        )
    assert called is False


def test_candidate_guard_runs_immediately_before_transport(tmp_path):
    from hermes_code_review import core

    guard_calls = 0
    transport_called = False

    def guard():
        nonlocal guard_calls
        guard_calls += 1
        if guard_calls == 2:
            raise RuntimeError('stale review candidate: changed before transport')

    def transport(*args, **kwargs):
        nonlocal transport_called
        transport_called = True
        raise AssertionError('transport must not receive a stale candidate')

    with pytest.raises(RuntimeError, match='changed before transport'):
        core.run_review(
            core.APPROVED_WORKER, worker(), b'+safe = True\n', 'head', 'tree',
            transport=transport, candidate_guard=guard,
            state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
        )
    assert guard_calls == 2
    assert transport_called is False


def test_concurrent_change_cannot_change_outbound_frozen_source_and_makes_result_stale(tmp_path, monkeypatch):
    from hermes_code_review import core

    expected = {
        'head': 'head', 'index_tree': 'tree', 'diff': b'+safe = True\n',
        'paths': ['app.py'], 'repo': tmp_path,
    }
    changed = expected | {'index_tree': 'changed-tree', 'diff': b'+unsafe = True\n'}
    freezes = iter([expected, expected, expected, changed])
    monkeypatch.setattr(core, 'freeze_git_candidate', lambda repo: next(freezes))
    snapshot = core.worker_snapshot(core.APPROVED_WORKER, worker())
    receipt = core.snapshot_receipt_bytes(
        expected['diff'], expected['head'], expected['index_tree'],
        route_sha=snapshot['route_sha'], reviewer_model=snapshot['model'],
    )

    def transport(route, body, timeout):
        prompt = body['messages'][-1]['content']
        assert base64.b64encode(expected['diff']).decode() in prompt
        assert base64.b64encode(changed['diff']).decode() not in prompt
        verdict = {
            'passed': True, 'safe_to_commit': True, 'summary': 'clean',
            'p0': [], 'p1': [], 'p2': [], 'security_concerns': [],
            'needs_evidence': [], **receipt,
        }
        return {
            'choices': [{'message': {'content': json.dumps(verdict)}}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 5},
        }

    def review_runner(*args, **kwargs):
        return core.run_review(*args, transport=transport, **kwargs)

    with pytest.raises(RuntimeError, match='stale review verdict'):
        core.run_git_review(
            tmp_path, core.APPROVED_WORKER, worker(),
            runner=review_runner,
            state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
            expected_candidate=expected,
        )
