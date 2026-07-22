from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_privacy_preflight_rejects_sensitive_paths_and_secret_material():
    from hermes_code_review import policy
    with pytest.raises(policy.PolicyViolation, match='sensitive path'):
        policy.check_privacy(['.env.production'], b'+DEBUG=false\n', '', '')
    with pytest.raises(policy.PolicyViolation, match='secret-like material'):
        policy.check_privacy(['app.py'], b'+api_key = "sk-' + b'a' * 40 + b'"\n', '', '')
    with pytest.raises(policy.PolicyViolation, match='secret-like material'):
        policy.check_privacy(['app.py'], b'+safe = True\n', 'Authorization: Bearer ' + 'x' * 30, '')


def test_privacy_preflight_allows_examples_and_normal_code():
    from hermes_code_review import policy
    policy.check_privacy(['.env.example', 'src/client.py'], b'+timeout = 30\n+api_key = os.environ["API_KEY"]\n', 'No raw credentials', '12 tests passed')


def test_budget_reservation_is_atomic_and_fail_closed(tmp_path):
    from hermes_code_review import policy
    ledger = tmp_path / 'budget.json'
    policy.reserve_budget(ledger, route_sha='route', estimated_input_tokens=80, daily_limit=100, now=1000)
    with pytest.raises(policy.PolicyViolation, match='budget exhausted'):
        policy.reserve_budget(ledger, route_sha='route', estimated_input_tokens=21, daily_limit=100, now=1000)
    value = json.loads(ledger.read_text())
    assert value['routes']['route']['reserved_input_tokens'] == 80


def test_budget_reconciles_estimate_to_actual(tmp_path):
    from hermes_code_review import policy
    ledger = tmp_path / 'budget.json'
    reservation = policy.reserve_budget(ledger, route_sha='route', estimated_input_tokens=80, daily_limit=100, now=1000)
    policy.reconcile_budget(ledger, reservation, actual_input_tokens=50, actual_output_tokens=10, now=1001)
    row = json.loads(ledger.read_text())['routes']['route']
    assert row['reserved_input_tokens'] == 0
    assert row['input_tokens'] == 50 and row['output_tokens'] == 10


def test_request_token_cap_is_checked_before_transport():
    from hermes_code_review import policy
    assert policy.estimate_tokens('abcd' * 10) == 10
    with pytest.raises(policy.PolicyViolation, match='request token estimate'):
        policy.assert_request_budget('x' * 401, max_input_tokens=100)
