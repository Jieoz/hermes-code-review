from __future__ import annotations

import json

import pytest

BASE = {
    'provider': 'custom',
    'base_url': 'https://review.example/v1',
    'model': 'grok-4.5',
    'api_mode': 'chat_completions',
    'enabled': True,
    'api_key': 'secret-key',
}


def _receipt():
    return {
        'review_head': 'a' * 40,
        'review_index_tree': 'b' * 40,
        'review_diff_sha': 'c' * 64,
        'review_route_sha': 'd' * 64,
        'reviewer_model': 'grok-4.5',
        'review_requirements_sha': 'e' * 64,
        'review_evidence_sha': 'f' * 64,
    }


def _verdict_json(receipt):
    return json.dumps({
        'passed': True,
        'review_head': receipt['review_head'],
        'review_index_tree': receipt['review_index_tree'],
        'review_diff_sha': receipt['review_diff_sha'],
        'review_route_sha': receipt['review_route_sha'],
        'reviewer_model': receipt['reviewer_model'],
        'review_requirements_sha': receipt['review_requirements_sha'],
        'review_evidence_sha': receipt['review_evidence_sha'],
        'p0': [], 'p1': [], 'p2': [],
        'needs_evidence': [], 'security_concerns': [],
        'safe_to_commit': True,
        'summary': 'ok',
    })


def test_json_mode_defaults_true_and_sets_response_format():
    from hermes_code_review import core
    snap = core.worker_snapshot(core.APPROVED_WORKER, BASE)
    assert snap['json_mode'] is True
    body = core._review_body(snap, 'prompt', 512)
    assert body['response_format'] == {'type': 'json_object'}


def test_json_mode_false_omits_response_format():
    from hermes_code_review import core
    snap = core.worker_snapshot(core.APPROVED_WORKER, {**BASE, 'review_json_mode': False})
    assert snap['json_mode'] is False
    body = core._review_body(snap, 'prompt', 512)
    assert 'response_format' not in body


def test_json_mode_is_transport_detail_not_route_identity():
    """Toggling review_json_mode must NOT change route_sha: it is a transport
    detail, not a reviewer-identity change."""
    from hermes_code_review import core
    a = core.worker_snapshot(core.APPROVED_WORKER, BASE)
    b = core.worker_snapshot(core.APPROVED_WORKER, {**BASE, 'review_json_mode': False})
    assert a['route_sha'] == b['route_sha']


def test_recovery_strips_markdown_fence_but_still_validates():
    from hermes_code_review import core
    receipt = _receipt()
    fenced = '```json\n' + _verdict_json(receipt) + '\n```'
    # strict mode (no recovery) rejects fenced output -> fail closed
    with pytest.raises(ValueError):
        core.parse_strict_verdict(fenced, receipt, allow_recovery=False)
    # recovery mode extracts the object and passes full schema validation
    verdict = core.parse_strict_verdict(fenced, receipt, allow_recovery=True)
    assert verdict['passed'] is True
    assert verdict['safe_to_commit'] is True


def test_recovery_extracts_leading_whitespace_object():
    from hermes_code_review import core
    receipt = _receipt()
    padded = '\n\n   ' + _verdict_json(receipt) + '  \n'
    verdict = core.parse_strict_verdict(padded, receipt, allow_recovery=True)
    assert verdict['passed'] is True


def test_recovery_still_fails_closed_on_schema_violation():
    """Recovery only reshapes candidate text; a structurally-wrong object (extra
    key / missing key) must still be rejected. No fail-open path."""
    from hermes_code_review import core
    receipt = _receipt()
    bad = json.loads(_verdict_json(receipt))
    bad['unexpected_key'] = 1  # schema requires an EXACT key set
    fenced = '```json\n' + json.dumps(bad) + '\n```'
    with pytest.raises(ValueError):
        core.parse_strict_verdict(fenced, receipt, allow_recovery=True)


def test_recovery_fails_closed_on_prose_with_no_object():
    from hermes_code_review import core
    receipt = _receipt()
    with pytest.raises(ValueError):
        core.parse_strict_verdict('I cannot produce JSON right now.', receipt, allow_recovery=True)


def test_recovery_ignores_braces_inside_strings():
    """The balanced-brace scanner must not be fooled by '{' or '}' inside string
    values; it should return the whole object, which then validates."""
    from hermes_code_review import core
    receipt = _receipt()
    obj = json.loads(_verdict_json(receipt))
    obj['summary'] = 'contains } and { braces in text'
    fenced = '```\n' + json.dumps(obj) + '\n```'
    verdict = core.parse_strict_verdict(fenced, receipt, allow_recovery=True)
    assert verdict['summary'] == 'contains } and { braces in text'


def test_retry_shaping_defaults_preserve_prior_behavior():
    from hermes_code_review import core
    snap = core.worker_snapshot(core.APPROVED_WORKER, BASE)
    assert snap['max_attempts'] == 1   # no floor -> caller's attempts govern
    assert snap['backoff_cap'] == 8.0


def test_retry_shaping_reads_per_route_config():
    from hermes_code_review import core
    snap = core.worker_snapshot(core.APPROVED_WORKER,
                                {**BASE, 'review_max_attempts': 6, 'review_backoff_cap_seconds': 20})
    assert snap['max_attempts'] == 6
    assert snap['backoff_cap'] == 20.0


def test_retry_shaping_is_transport_detail_not_route_identity():
    from hermes_code_review import core
    a = core.worker_snapshot(core.APPROVED_WORKER, BASE)
    b = core.worker_snapshot(core.APPROVED_WORKER,
                             {**BASE, 'review_max_attempts': 6, 'review_backoff_cap_seconds': 20})
    assert a['route_sha'] == b['route_sha']


def test_route_max_attempts_rides_through_intermittent_503(monkeypatch):
    """A route configured with review_max_attempts must keep retrying past the
    caller's default and succeed when a later attempt gets a good window."""
    from hermes_code_review import core

    calls = {'n': 0}

    def flaky_transport(snapshot, body, timeout):
        calls['n'] += 1
        if calls['n'] < 4:               # first 3 attempts: upstream exhausted
            raise core.ReviewHTTPError(503, 'no available channels after filtering')
        prompt = body['messages'][0]['content']
        receipt = {
            key: next(line.split(': ', 1)[1] for line in prompt.splitlines() if line.startswith(key + ': '))
            for key in ('review_head', 'review_index_tree', 'review_diff_sha',
                        'review_route_sha', 'reviewer_model', 'review_requirements_sha',
                        'review_evidence_sha')
        }
        import json as _j
        content = _j.dumps({
            'passed': True,
            'review_head': receipt['review_head'],
            'review_index_tree': receipt['review_index_tree'],
            'review_diff_sha': receipt['review_diff_sha'],
            'review_route_sha': receipt['review_route_sha'],
            'reviewer_model': receipt['reviewer_model'],
            'review_requirements_sha': receipt['review_requirements_sha'],
            'review_evidence_sha': receipt['review_evidence_sha'],
            'p0': [], 'p1': [], 'p2': [], 'needs_evidence': [], 'security_concerns': [],
            'safe_to_commit': True, 'summary': 'ok',
        })
        return {'choices': [{'message': {'content': content}}],
                'usage': {'prompt_tokens': 10, 'completion_tokens': 5}}

    import pathlib
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp())
    worker = {**BASE, 'review_max_attempts': 6, 'review_backoff_cap_seconds': 20, 'review_json_mode': False}
    res = core.run_review(
        'grok', worker, b'+x = 1\n', 'head', 'tree',
        attempts=2, transport=flaky_transport, sleep=lambda s: None,
        state_path=d / 'health.json', runs_dir=d / 'runs', persist=False,
    )
    assert res['verdict']['passed'] is True
    assert calls['n'] == 4          # rode through 3 x 503 then succeeded (default attempts=2 would have failed)


def test_circuit_threshold_scales_with_attempts_so_route_does_not_self_trip(monkeypatch):
    """With a high attempt count, 3 sub-attempt failures must NOT open the circuit
    before the route gets its later successful window."""
    import pathlib
    import tempfile

    from hermes_code_review import core
    d = pathlib.Path(tempfile.mkdtemp())
    state = d / 'health.json'
    calls = {'n': 0}

    def transport(snapshot, body, timeout):
        calls['n'] += 1
        if calls['n'] < 4:
            raise core.ReviewHTTPError(503, 'no available channels')
        prompt = body['messages'][0]['content']
        receipt = {
            key: next(line.split(': ', 1)[1] for line in prompt.splitlines() if line.startswith(key + ': '))
            for key in ('review_head', 'review_index_tree', 'review_diff_sha',
                        'review_route_sha', 'reviewer_model', 'review_requirements_sha',
                        'review_evidence_sha')
        }
        import json as _j
        content = _j.dumps({
            'passed': True, 'review_head': receipt['review_head'],
            'review_index_tree': receipt['review_index_tree'], 'review_diff_sha': receipt['review_diff_sha'],
            'review_route_sha': receipt['review_route_sha'], 'reviewer_model': receipt['reviewer_model'],
            'review_requirements_sha': receipt['review_requirements_sha'], 'review_evidence_sha': receipt['review_evidence_sha'],
            'p0': [], 'p1': [], 'p2': [], 'needs_evidence': [], 'security_concerns': [],
            'safe_to_commit': True, 'summary': 'ok',
        })
        return {'choices': [{'message': {'content': content}}], 'usage': {'prompt_tokens': 1, 'completion_tokens': 1}}

    worker = {**BASE, 'review_max_attempts': 6, 'review_backoff_cap_seconds': 20, 'review_json_mode': False}
    res = core.run_review('grok', worker, b'+x=1\n', 'head', 'tree',
                          attempts=2, transport=transport, sleep=lambda s: None,
                          state_path=state, runs_dir=d / 'runs', persist=False)
    assert res['verdict']['passed'] is True
    # circuit must be closed (success reset it), route did not self-trip at 3 failures
    core.assert_circuit_closed(state, core.worker_snapshot('grok', worker)['route_sha'])
