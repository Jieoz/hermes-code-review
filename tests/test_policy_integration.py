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
            for key in ('review_head', 'review_index_tree', 'review_diff_sha', 'review_route_sha', 'reviewer_model')
        }
        return valid_payload(receipt)

    result = core.run_review('r', worker(), b'diff', 'h', 't', transport=transport,
                             state_path=tmp_path / 'health.json', runs_dir=tmp_path / 'runs',
                             budget_path=ledger, max_input_tokens=5000, daily_input_tokens=5000)
    assert result['verdict']['passed'] is True
    row = next(iter(json.loads(ledger.read_text())['routes'].values()))
    assert row['reserved_input_tokens'] == 0
    assert row['input_tokens'] == 20 and row['output_tokens'] == 5


def test_run_review_rejects_over_cap_before_transport(tmp_path):
    from hermes_code_review import core
    called = False
    def transport(*args):
        nonlocal called; called = True
    with pytest.raises(RuntimeError, match='request token estimate'):
        core.run_review('r', worker(), b'x' * 1000, 'h', 't', transport=transport,
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
        nonlocal called; called = True
    with pytest.raises(RuntimeError, match='secret-like material'):
        core.run_git_review(tmp_path, 'r', worker(), runner=runner, runs_dir=tmp_path / 'runs')
    assert called is False
