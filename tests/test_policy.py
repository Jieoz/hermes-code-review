from __future__ import annotations

import json
import pytest


def test_privacy_preflight_rejects_sensitive_paths_and_secret_material():
    from hermes_code_review import policy
    with pytest.raises(policy.PolicyViolation, match='sensitive path'):
        policy.check_privacy(['.env.production'], b'+DEBUG=false\n', '', '')
    with pytest.raises(policy.PolicyViolation, match='secret-like material'):
        policy.check_privacy(['app.py'], b'+api_key = "sk-' + b'a' * 40 + b'"\n', '', '')
    with pytest.raises(policy.PolicyViolation, match='secret-like material'):
        policy.check_privacy(['app.py'], b'+safe = True\n', 'Authorization: ' + 'Bearer' + ' ' + 'x' * 30, '')


def test_privacy_preflight_allows_examples_and_normal_code():
    from hermes_code_review import policy
    policy.check_privacy(
        ['.env.example', 'src/client.py'],
        b'+timeout = 30\n+api_key = os.environ["API_KEY"]\n',
        'No raw credentials', '12 tests passed',
    )


def test_usage_reservation_is_atomic_and_records_actual_usage(tmp_path):
    from hermes_code_review import policy
    ledger = tmp_path / 'usage.json'
    rid = policy.reserve_usage(
        ledger, route_sha='route', estimated_input_tokens=40,
        estimated_output_tokens=20,
    )
    policy.reconcile_usage(
        ledger, rid, actual_input_tokens=30, actual_output_tokens=5,
    )
    row = json.loads(ledger.read_text())['routes']['route']
    assert row == {
        'input_tokens': 30, 'output_tokens': 5,
        'reserved_input_tokens': 0, 'reserved_output_tokens': 0,
    }


def test_usage_ledger_never_blocks_normal_reviews(tmp_path):
    from hermes_code_review import policy
    ledger = tmp_path / 'usage.json'

    first = policy.reserve_usage(
        ledger, route_sha='primary', estimated_input_tokens=9_000_000,
        estimated_output_tokens=900_000, now=1_769_212_800,
    )
    policy.reconcile_usage(
        ledger, first, actual_input_tokens=9_000_000,
        actual_output_tokens=900_000, now=1_769_212_800,
    )
    second = policy.reserve_usage(
        ledger, route_sha='fallback', estimated_input_tokens=9_000_000,
        estimated_output_tokens=900_000, now=1_769_212_800,
    )

    assert second
    assert policy.usage_status(ledger, now=1_769_212_800) == {
        'day_utc': '2026-01-24',
        'input_used': 18_000_000,
        'output_used': 1_800_000,
    }


def test_usage_lock_and_ledger_symlinks_fail_closed(tmp_path):
    from hermes_code_review import policy
    target = tmp_path / 'target'
    target.write_text('{}')
    ledger = tmp_path / 'usage.json'
    lock = tmp_path / '.usage.json.lock'
    lock.symlink_to(target)
    with pytest.raises(policy.PolicyViolation, match='unsafe policy lock'):
        policy.reserve_usage(
            ledger, route_sha='r', estimated_input_tokens=1,
            estimated_output_tokens=1,
        )
    lock.unlink()
    ledger.symlink_to(target)
    with pytest.raises(policy.PolicyViolation, match='unsafe usage ledger'):
        policy.reserve_usage(
            ledger, route_sha='r', estimated_input_tokens=1,
            estimated_output_tokens=1,
        )


def test_request_token_cap_is_checked_before_transport():
    from hermes_code_review import policy
    assert policy.estimate_tokens('abcd' * 10) == 10
    with pytest.raises(policy.PolicyViolation, match='request token estimate'):
        policy.assert_request_bound('x' * 401, max_input_tokens=100)
