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
    key = tmp_path / 'receipt.key'; key.write_bytes(b'x' * 32); key.chmod(0o644)
    with pytest.raises(ValueError, match='permissions'):
        signing.sign_result(sample_result(), key)


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
