from __future__ import annotations

import json
from pathlib import Path

import pytest


def worker():
    return {'provider': 'custom', 'base_url': 'https://review.example/v1', 'api_key': 'secret', 'model': 'grok-4.5', 'api_mode': 'chat_completions', 'enabled': True}


def valid_payload(receipt, input_tokens=20, output_tokens=5):
    verdict = {
        'passed': True, **receipt, 'p0': [], 'p1': [], 'p2': [],
        'needs_evidence': [], 'security_concerns': [], 'safe_to_commit': True,
        'summary': 'clean',
    }
    return {'choices': [{'message': {'content': json.dumps(verdict)}}], 'usage': {'prompt_tokens': input_tokens, 'completion_tokens': output_tokens}}


def test_run_review_reserves_and_reconciles_budget(tmp_path):
    from hermes_code_review import core
    ledger = tmp_path / 'budget.json'

    def transport(snapshot, body, timeout):
        prompt = body['messages'][0]['content']
        receipt = {
            key: next(line.split(': ', 1)[1] for line in prompt.splitlines() if line.startswith(key + ': '))
            for key in (
                'review_head', 'review_index_tree', 'review_diff_sha',
                'review_route_sha', 'reviewer_model', 'review_requirements_sha',
                'review_evidence_sha',
            )
        }
        return valid_payload(receipt)

    result = core.run_review(core.APPROVED_WORKER, worker(), b'diff', 'h', 't', transport=transport,
                             state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
                             budget_path=ledger, max_input_tokens=5000, daily_input_tokens=5000)
    assert result['verdict']['passed'] is True
    row = next(iter(json.loads(ledger.read_text())['routes'].values()))
    assert row['reserved_input_tokens'] == 0
    assert row['input_tokens'] == 20 and row['output_tokens'] == 5


def test_run_review_retries_transient_http_and_conservatively_charges_unknown_usage(tmp_path):
    from hermes_code_review import core
    ledger = tmp_path / 'budget.json'
    calls = 0

    def transport(snapshot, body, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise core.ReviewHTTPError(503, 'private upstream body')
        prompt = body['messages'][0]['content']
        receipt = {
            key: next(line.split(': ', 1)[1] for line in prompt.splitlines() if line.startswith(key + ': '))
            for key in (
                'review_head', 'review_index_tree', 'review_diff_sha',
                'review_route_sha', 'reviewer_model', 'review_requirements_sha',
                'review_evidence_sha',
            )
        }
        verdict = {
            'passed': True, **receipt, 'p0': [], 'p1': [], 'p2': [],
            'needs_evidence': [], 'security_concerns': [],
            'safe_to_commit': True, 'summary': 'clean',
        }
        return {
            'choices': [{'message': {'content': json.dumps(verdict)}}],
            'usage': {'prompt_tokens': 20, 'completion_tokens': 4},
        }

    result = core.run_review(
        core.APPROVED_WORKER, worker(), b'diff', 'h', 't',
        transport=transport, attempts=2, sleep=lambda _: None,
        state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
        budget_path=ledger, max_input_tokens=5000, max_output_tokens=100,
        daily_input_tokens=5000,
    )

    assert calls == 2
    assert result['metrics']['attempts'] == 2
    assert result['metrics']['input_tokens'] > 20
    assert result['metrics']['output_tokens'] == 104
    row = next(iter(json.loads(ledger.read_text())['routes'].values()))
    assert row['input_tokens'] == result['metrics']['input_tokens']
    assert row['output_tokens'] == 104


def test_run_review_retries_one_invalid_verdict_and_accounts_for_both_responses(tmp_path):
    from hermes_code_review import core
    ledger = tmp_path / 'budget.json'
    calls = 0

    def transport(snapshot, body, timeout):
        nonlocal calls
        calls += 1
        prompt = body['messages'][0]['content']
        receipt = {
            key: next(line.split(': ', 1)[1] for line in prompt.splitlines() if line.startswith(key + ': '))
            for key in (
                'review_head', 'review_index_tree', 'review_diff_sha',
                'review_route_sha', 'reviewer_model', 'review_requirements_sha',
                'review_evidence_sha',
            )
        }
        if calls == 1:
            return {
                'choices': [{'message': {'content': '{"not":"a verdict"}'}}],
                'usage': {'prompt_tokens': 20, 'completion_tokens': 3},
            }
        return valid_payload(receipt, input_tokens=21, output_tokens=5)

    result = core.run_review(
        core.APPROVED_WORKER, worker(), b'diff', 'h', 't',
        transport=transport, attempts=2, sleep=lambda _: None,
        state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
        budget_path=ledger, max_input_tokens=5000, daily_input_tokens=5000,
    )

    assert calls == 2
    assert result['verdict']['passed'] is True
    assert result['metrics']['input_tokens'] == 41
    assert result['metrics']['output_tokens'] == 8
    row = next(iter(json.loads(ledger.read_text())['routes'].values()))
    assert row['input_tokens'] == 41 and row['output_tokens'] == 8


def test_run_review_rejects_over_cap_before_transport(tmp_path):
    from hermes_code_review import core
    called = False
    def transport(*args):
        nonlocal called
        called = True
    with pytest.raises(RuntimeError, match='request token estimate'):
        core.run_review(core.APPROVED_WORKER, worker(), b'x' * 1000, 'h', 't', transport=transport,
                        state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
                        budget_path=tmp_path / 'budget.json', max_input_tokens=10, daily_input_tokens=5000)
    assert called is False


def test_git_review_privacy_gate_runs_before_remote_runner(tmp_path, monkeypatch):
    from hermes_code_review import core
    monkeypatch.setattr(core, 'freeze_git_candidate', lambda repo: {
        'repo': Path(repo), 'head': 'h', 'index_tree': 't',
        'diff': b'+api_key="sk-' + b'a' * 40 + b'"', 'paths': ['app.py'],
    })
    called = False
    def runner(*args, **kwargs):
        nonlocal called
        called = True
    with pytest.raises(RuntimeError, match='secret-like material'):
        core.run_git_review(tmp_path, core.APPROVED_WORKER, worker(), runner=runner, runs_dir=tmp_path / 'runs')
    assert called is False


def test_git_review_signs_before_persisting(tmp_path, monkeypatch):
    from hermes_code_review import core, signing
    frozen = {
        'repo': tmp_path, 'head': 'h', 'index_tree': 't',
        'diff': b'+safe = True', 'paths': ['app.py'],
    }
    monkeypatch.setattr(core, 'freeze_git_candidate', lambda repo: frozen)
    key = tmp_path / 'receipt.key'
    signing.create_signing_key(key)
    snapshot = core.worker_snapshot(core.APPROVED_WORKER, worker())
    receipt = core.snapshot_receipt_bytes(
        b'+safe = True', 'h', 't',
        route_sha=snapshot['route_sha'], reviewer_model=snapshot['model'],
    )
    unsigned = {
        'receipt': receipt,
        'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'clean'},
        'route': core.public_route(snapshot),
        'metrics': {'input_tokens': 1, 'output_tokens': 1, 'elapsed_ms': 1},
    }
    result = core.run_git_review(
        tmp_path, core.APPROVED_WORKER, worker(), runner=lambda *a, **k: unsigned,
        runs_dir=tmp_path / 'runs', signing_key_path=key,
    )
    signing.verify_result(result, key)
    stored = json.loads(next((tmp_path / 'runs').glob('*.json')).read_text())
    assert stored['signature'] == result['signature']


def test_malformed_response_without_usage_charges_full_reservation(tmp_path):
    from hermes_code_review import core

    ledger = tmp_path / 'budget.json'
    with pytest.raises(core.InvalidVerdictError):
        core.run_review(
            core.APPROVED_WORKER, worker(), b'+safe = True\n', 'head', 'tree',
            attempts=1,
            transport=lambda snapshot, body, timeout: {'malformed': True},
            state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
            budget_path=ledger, max_input_tokens=1000, max_output_tokens=77,
            daily_input_tokens=1000, daily_output_tokens=1000,
        )
    value = json.loads(ledger.read_text())
    row = next(iter(value['routes'].values()))
    assert row['reserved_input_tokens'] == 0
    assert row['reserved_output_tokens'] == 0
    assert row['input_tokens'] > 0
    assert row['output_tokens'] == 77


def test_retry_revalidates_worker_pool_before_second_transport(tmp_path):
    from hermes_code_review import core

    current_calls = 0
    transport_calls = 0

    def current_worker():
        nonlocal current_calls
        current_calls += 1
        if current_calls >= 4:
            return worker() | {'base_url': 'https://changed.example/v1'}
        return worker()

    def transport(snapshot, body, timeout):
        nonlocal transport_calls
        transport_calls += 1
        raise core.ReviewHTTPError(503, '')

    with pytest.raises(RuntimeError, match='worker config changed'):
        core.run_review(
            core.APPROVED_WORKER, worker(), b'+safe = True\n', 'head', 'tree',
            attempts=2, transport=transport, current_worker=current_worker,
            sleep=lambda _: None,
            state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
        )
    assert transport_calls == 1


def test_nonretryable_http_does_not_open_circuit_or_enable_later_fallback(tmp_path):
    from hermes_code_review import core

    state = tmp_path / 'health.json'
    for _ in range(4):
        with pytest.raises(core.ReviewHTTPError):
            core.run_review(
                core.APPROVED_WORKER, worker(), b'+safe = True\n', 'head', 'tree',
                attempts=1,
                transport=lambda snapshot, body, timeout: (_ for _ in ()).throw(core.ReviewHTTPError(401, '')),
                state_path=state, runs_dir=tmp_path / 'runs',
            )
    core.assert_circuit_closed(state, core.worker_snapshot(core.APPROVED_WORKER, worker())['route_sha'])


def test_missing_usage_is_invalid_and_conservatively_reconciled(tmp_path):
    from hermes_code_review import core

    ledger = tmp_path / 'budget.json'
    payload = {'choices': [{'message': {'content': '{}'}}], 'usage': {}}
    with pytest.raises(core.InvalidVerdictError):
        core.run_review(
            core.APPROVED_WORKER, worker(), b'+safe = True\n', 'head', 'tree',
            attempts=1, transport=lambda snapshot, body, timeout: payload,
            state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
            budget_path=ledger, max_input_tokens=1000, max_output_tokens=55,
            daily_input_tokens=1000, daily_output_tokens=1000,
        )
    row = next(iter(json.loads(ledger.read_text())['routes'].values()))
    assert row['reserved_input_tokens'] == 0
    assert row['input_tokens'] > 0
    assert row['output_tokens'] == 55


def test_local_pretransport_validation_error_is_refunded_and_not_retyped(tmp_path):
    from hermes_code_review import core

    ledger = tmp_path / 'budget.json'
    calls = 0

    def guard():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError('local validation failed')

    with pytest.raises(ValueError, match='local validation failed'):
        core.run_review(
            core.APPROVED_WORKER, worker(), b'+safe = True\n', 'head', 'tree',
            candidate_guard=guard, state_path=tmp_path / 'health.json',
            runs_dir=tmp_path / 'runs', budget_path=ledger,
            max_output_tokens=100,
            daily_input_tokens=1000, daily_output_tokens=1000,
        )
    row = next(iter(json.loads(ledger.read_text())['routes'].values()))
    assert row['reserved_input_tokens'] == 0
    assert row['input_tokens'] == 0
    assert row['output_tokens'] == 0


@pytest.mark.parametrize('bad_usage', [True, 0.5, '12', -1])
def test_wrong_typed_usage_is_rejected_and_conservatively_charged(tmp_path, bad_usage):
    from hermes_code_review import core

    ledger = tmp_path / 'budget.json'

    def transport(snapshot, body, timeout):
        prompt = body['messages'][0]['content']
        receipt = {
            key: next(line.split(': ', 1)[1] for line in prompt.splitlines() if line.startswith(key + ': '))
            for key in (
                'review_head', 'review_index_tree', 'review_diff_sha',
                'review_route_sha', 'reviewer_model', 'review_requirements_sha',
                'review_evidence_sha',
            )
        }
        payload = valid_payload(receipt)
        payload['usage']['prompt_tokens'] = bad_usage
        return payload

    with pytest.raises(core.InvalidVerdictError):
        core.run_review(
            core.APPROVED_WORKER, worker(), b'+safe = True\n', 'head', 'tree',
            attempts=1, transport=transport,
            state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
            budget_path=ledger, max_input_tokens=1000, max_output_tokens=66,
            daily_input_tokens=1000, daily_output_tokens=1000,
        )
    row = next(iter(json.loads(ledger.read_text())['routes'].values()))
    assert row['input_tokens'] > 0
    assert row['output_tokens'] == 66
