from __future__ import annotations

import json

import pytest


def sample_result():
    return {
        'receipt': {'review_head': 'h', 'review_index_tree': 't', 'review_diff_sha': 'd', 'review_route_sha': 'r', 'reviewer_model': 'grok-4.5'},
        'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'clean'},
        'metrics': {'input_tokens': 10, 'output_tokens': 2, 'elapsed_ms': 5},
    }


def test_sign_and_verify_review_result(tmp_path):
    from hermes_code_review import signing
    key = tmp_path / 'receipt.key'
    signing.create_signing_key(key)
    assert key.stat().st_mode & 0o077 == 0
    signed = signing.sign_result(sample_result(), key)
    assert signed['signature']['algorithm'] == 'hmac-sha256'
    signing.verify_result(signed, key)
    signed['verdict']['summary'] = 'tampered'
    with pytest.raises(ValueError, match='signature'):
        signing.verify_result(signed, key)


def test_signing_rejects_weak_permissions(tmp_path):
    from hermes_code_review import signing
    key = tmp_path / 'receipt.key'
    key.write_bytes(b'x' * 32)
    key.chmod(0o644)
    with pytest.raises(ValueError, match='permissions'):
        signing.sign_result(sample_result(), key)


def test_signing_and_metrics_reject_symlinks(tmp_path):
    from hermes_code_review import observability, signing
    key_target = tmp_path / 'key-target'
    key_target.write_bytes(b'x' * 32)
    key_target.chmod(0o600)
    key_link = tmp_path / 'key-link'
    key_link.symlink_to(key_target)
    with pytest.raises(ValueError, match='regular file'):
        signing.sign_result(sample_result(), key_link)
    metrics_target = tmp_path / 'metrics-target'
    metrics_target.write_text('unchanged')
    metrics_link = tmp_path / 'metrics.jsonl'
    metrics_link.symlink_to(metrics_target)
    with pytest.raises(OSError):
        observability.record_event(metrics_link, status='PASS', worker='hybgzs_grok45',
                                   model='grok-4.5', route_sha='abc', elapsed_ms=1,
                                   input_tokens=1, output_tokens=1)
    assert metrics_target.read_text() == 'unchanged'


def test_metrics_event_is_minimal_and_redacted(tmp_path):
    from hermes_code_review import observability
    path = tmp_path / 'metrics.jsonl'
    observability.record_event(path, status='INFRA_FAILED', worker='review', model='grok-4.5', route_sha='abc',
                               elapsed_ms=50, input_tokens=0, output_tokens=0,
                               error='HTTP 504 at https://secret.example/v1?api_key=topsecret')
    event = json.loads(path.read_text())
    assert event['status'] == 'INFRA_FAILED'
    assert event['error_class'] == 'HTTP_5XX'
    assert 'secret.example' not in json.dumps(event)
    assert 'topsecret' not in json.dumps(event)


def test_usage_accounting_failures_have_a_stable_error_class():
    from hermes_code_review.observability import classify_error
    assert classify_error('unsafe usage ledger') == 'USAGE_LEDGER'
    assert classify_error('unknown or expired usage reservation') == 'USAGE_LEDGER'
