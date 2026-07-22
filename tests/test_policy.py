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
    policy.reserve_budget(
        ledger, route_sha='route', estimated_input_tokens=80, estimated_output_tokens=10,
        daily_input_limit=100, daily_output_limit=100, now=1000,
    )
    with pytest.raises(policy.PolicyViolation, match='input budget exhausted'):
        policy.reserve_budget(
            ledger, route_sha='route', estimated_input_tokens=21, estimated_output_tokens=10,
            daily_input_limit=100, daily_output_limit=100, now=1000,
        )
    value = json.loads(ledger.read_text())
    assert value['routes']['route']['reserved_input_tokens'] == 80


def test_budget_releases_reservation_and_records_actual_usage(tmp_path):
    from hermes_code_review.policy import reconcile_budget, reserve_budget
    ledger = tmp_path / 'budget.json'
    rid = reserve_budget(
        ledger, route_sha='route', estimated_input_tokens=40,
        estimated_output_tokens=20, daily_input_limit=100, daily_output_limit=50,
    )
    reconcile_budget(ledger, rid, actual_input_tokens=30, actual_output_tokens=5)
    row = json.loads(ledger.read_text())['routes']['route']
    assert row == {
        'input_tokens': 30, 'output_tokens': 5,
        'reserved_input_tokens': 0, 'reserved_output_tokens': 0,
    }


def test_output_budget_is_reserved_atomically(tmp_path):
    from hermes_code_review.policy import PolicyViolation, reserve_budget
    ledger = tmp_path / 'budget.json'
    reserve_budget(
        ledger, route_sha='route', estimated_input_tokens=1,
        estimated_output_tokens=40, daily_input_limit=100, daily_output_limit=50,
    )
    with pytest.raises(PolicyViolation, match='output budget'):
        reserve_budget(
            ledger, route_sha='route', estimated_input_tokens=1,
            estimated_output_tokens=20, daily_input_limit=100, daily_output_limit=50,
        )


def test_budget_lock_and_ledger_symlinks_fail_closed(tmp_path):
    from hermes_code_review import policy
    target = tmp_path / 'target'; target.write_text('{}')
    ledger = tmp_path / 'budget.json'
    lock = tmp_path / '.budget.json.lock'; lock.symlink_to(target)
    with pytest.raises(policy.PolicyViolation, match='unsafe policy lock'):
        policy.reserve_budget(ledger, route_sha='r', estimated_input_tokens=1,
                              estimated_output_tokens=1, daily_input_limit=10,
                              daily_output_limit=10)
    lock.unlink(); ledger.symlink_to(target)
    with pytest.raises(policy.PolicyViolation, match='unsafe budget ledger'):
        policy.reserve_budget(ledger, route_sha='r', estimated_input_tokens=1,
                              estimated_output_tokens=1, daily_input_limit=10,
                              daily_output_limit=10)



def test_request_token_cap_is_checked_before_transport():
    from hermes_code_review import policy
    assert policy.estimate_tokens('abcd' * 10) == 10
    with pytest.raises(policy.PolicyViolation, match='request token estimate'):
        policy.assert_request_budget('x' * 401, max_input_tokens=100)
