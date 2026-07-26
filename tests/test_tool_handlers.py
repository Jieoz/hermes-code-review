from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def stable_invocation_candidate(monkeypatch):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin.core, 'freeze_git_candidate', lambda repo: {
        'head': 'h', 'index_tree': 't', 'repo': Path(repo),
        'diff': b'', 'paths': [],
    })


def configured_worker():
    return {
        'provider': 'custom', 'base_url': 'https://review.example/v1',
        'api_key': 'secret', 'model': 'grok-4.5', 'api_mode': 'chat_completions',
        'enabled': True,
    }


def configured_fallback_worker():
    return {
        'provider': 'custom', 'base_url': 'https://fallback.example/v1',
        'api_key': 'fallback-secret', 'model': 'claude-opus-4-8',
        'api_mode': 'anthropic_messages', 'enabled': True,
    }


def configured_kimi_worker():
    return {
        'provider': 'custom', 'base_url': 'https://kimi.example/v1',
        'api_key': 'kimi-secret', 'model': 'kimi-k3',
        'api_mode': 'chat_completions', 'enabled': True,
    }


def test_fallback_policy_accepts_only_infrastructure_classes():
    from hermes_code_review import core, plugin, policy
    assert plugin._fallback_eligible(core.ReviewHTTPError(429, 'limited')) is True
    assert plugin._fallback_eligible(core.ReviewHTTPError(503, 'down')) is True
    assert plugin._fallback_eligible(core.ReviewTransportError('network transport failed')) is True
    assert plugin._fallback_eligible(core.InvalidVerdictError('invalid review verdict')) is True
    assert plugin._fallback_eligible(policy.PolicyViolation('secret-like material')) is False
    assert plugin._fallback_eligible(RuntimeError('stale review verdict')) is False
    assert plugin._fallback_eligible(core.ReviewHTTPError(403, 'forbidden')) is False


def test_review_tool_returns_machine_pass(monkeypatch, tmp_path):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
        'code_review': {'author_model_families': ['gpt']},
    })
    seen = {}
    def fake_run(*args, **kwargs):
        seen.update(kwargs)
        return plugin.signing.sign_result({
            'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'clean'},
            'receipt': {'reviewer_model': 'grok-4.5', 'review_head': 'h', 'review_index_tree': 't'},
            'route': {'route_sha': 'route'},
            'metrics': {'input_tokens': 10, 'output_tokens': 5, 'elapsed_ms': 7},
        }, plugin.SIGNING_KEY)
    monkeypatch.setattr(plugin.core, 'run_git_review', fake_run)
    value = json.loads(plugin.review_git_candidate({
        'repo': str(tmp_path), 'requirements': 'r', 'evidence': 'e',
    }))
    assert value['status'] == 'PASS'
    assert value['receipt']['reviewer_model'] == 'grok-4.5'
    assert seen['signing_key_path'] == plugin.SIGNING_KEY
    assert seen['max_source_bytes'] == 350_000
    assert seen['max_output_tokens'] == 8_192
    assert seen['usage_path'] == plugin.core.USAGE_LEDGER
    assert not {
        'daily_input_tokens', 'daily_output_tokens',
        'release_input_reserve', 'release_output_reserve',
        'allow_release_reserve',
    }.intersection(seen)
    event = json.loads(plugin.METRICS.read_text())
    assert event['status'] == 'PASS' and event['route_sha'] == 'route'
    assert 'secret' not in json.dumps(value)


def test_review_tool_fails_closed_on_any_exception(monkeypatch, tmp_path):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key', raising=False)
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl', raising=False)
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
        'code_review': {'author_model_families': ['gpt']},
    })
    monkeypatch.setattr(plugin.core, 'run_git_review', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('HTTP 504')))
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))
    assert value == {'status': 'INFRA_FAILED', 'error_class': 'HTTP_5XX'}


def test_review_tool_uses_preapproved_fallback_only_for_infrastructure_failure(monkeypatch, tmp_path):
    from hermes_code_review import core, plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {
            'hybgzs_grok45': configured_worker(),
            'cc_review_route': configured_fallback_worker(),
        }},
        'code_review': {
            'fallback_workers': ['cc_review_route'],
            'author_model_families': ['gpt'],
        },
    })
    called = []
    def fake_run(repo, name, worker, **kwargs):
        called.append(name)
        if name == 'hybgzs_grok45':
            raise core.ReviewHTTPError(503, '')
        snapshot = core.worker_snapshot(name, worker)
        result = {
            'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'clean'},
            'receipt': {'reviewer_model': snapshot['model'], 'review_head': 'h', 'review_index_tree': 't'},
            'route': core.public_route(snapshot),
            'metrics': {'input_tokens': 10, 'output_tokens': 5, 'elapsed_ms': 7},
        }
        return plugin.signing.sign_result(result, plugin.SIGNING_KEY)
    monkeypatch.setattr(plugin.core, 'run_git_review', fake_run)

    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))

    assert called == ['hybgzs_grok45', 'cc_review_route']
    assert value['status'] == 'PASS'
    assert value['fallback_used'] is True
    assert value['route']['name'] == 'cc_review_route'
    assert value['route']['model'] == 'claude-opus-4-8'


def test_review_tool_refuses_fallback_when_candidate_changes_between_routes(monkeypatch, tmp_path):
    from hermes_code_review import core, plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'main_token_reserve': {'workers': {
            'hybgzs_grok45': configured_worker(),
            'cc_review_route': configured_fallback_worker(),
        }},
        'code_review': {
            'workers': ['hybgzs_grok45', 'cc_review_route'],
            'author_model_families': ['gpt'],
        },
    })
    frozen = {'head': 'h', 'index_tree': 'tree', 'repo': tmp_path, 'diff': b'x', 'paths': ['x.py']}
    changed = frozen | {'index_tree': 'changed'}
    freezes = iter([frozen, changed])
    monkeypatch.setattr(plugin.core, 'freeze_git_candidate', lambda repo: next(freezes))
    called = []

    def fail_primary(repo, name, worker, **kwargs):
        called.append(name)
        raise core.ReviewHTTPError(503, '')

    monkeypatch.setattr(plugin.core, 'run_git_review', fail_primary)
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))
    assert called == ['hybgzs_grok45']
    assert value == {'status': 'INFRA_FAILED', 'error_class': 'STALE'}


def test_review_routes_reject_any_author_model_family(monkeypatch):
    from hermes_code_review import plugin
    workers = {
        'gpt-primary': configured_worker() | {'model': 'gpt-5.6-sol'},
        'grok': configured_worker(),
    }
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'main_token_reserve': {'workers': workers},
        'code_review': {
            'workers': ['gpt-primary', 'grok'],
            'author_model_families': ['gpt', 'claude'],
        },
    })
    with pytest.raises(RuntimeError, match='author model family'):
        plugin._routes()


def test_review_routes_require_distinct_reviewer_model_families(monkeypatch):
    from hermes_code_review import plugin
    workers = {
        'grok-a': configured_worker(),
        'grok-b': configured_worker() | {'base_url': 'https://other.example/v1'},
    }
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'main_token_reserve': {'workers': workers},
        'code_review': {
            'workers': ['grok-a', 'grok-b'],
            'author_model_families': ['gpt', 'claude'],
        },
    })
    with pytest.raises(RuntimeError, match='distinct model families'):
        plugin._routes()


def test_review_routes_accept_ordered_unique_non_author_families(monkeypatch):
    from hermes_code_review import plugin
    workers = {'grok': configured_worker(), 'kimi': configured_kimi_worker()}
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'main_token_reserve': {'workers': workers},
        'code_review': {
            'workers': ['grok', 'kimi'],
            'author_model_families': ['gpt', 'claude'],
        },
    })
    routes, _ = plugin._routes()
    assert [name for name, _worker, _snapshot in routes] == ['grok', 'kimi']


@pytest.mark.parametrize(
    ('gate_role', 'expected_blocks'),
    [('load_bearing', True), ('secondary', False)],
)
def test_infrastructure_failure_blocks_only_load_bearing_review(
    monkeypatch, tmp_path, gate_role, expected_blocks,
):
    from hermes_code_review import core, plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key', raising=False)
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl', raising=False)
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'main_token_reserve': {'workers': {'grok': configured_worker()}},
        'code_review': {
            'workers': ['grok'],
            'author_model_families': ['gpt', 'claude'],
        },
    })
    monkeypatch.setattr(
        plugin.core, 'run_git_review',
        lambda *a, **k: (_ for _ in ()).throw(core.ReviewHTTPError(504, '')),
    )
    value = json.loads(plugin.review_git_candidate({
        'repo': str(tmp_path), 'gate_role': gate_role,
    }))
    assert value['status'] == 'INFRA_FAILED'
    assert value['gate_role'] == gate_role
    assert value['blocks_handoff'] is expected_blocks


def test_current_pool_worker_rejects_removed_or_reordered_route(monkeypatch):
    from hermes_code_review import plugin

    workers = {
        'hybgzs_grok45': configured_worker(),
        'cc_review_route': configured_fallback_worker(),
    }
    config = {
        'main_token_reserve': {'workers': workers},
        'code_review': {
            'workers': ['hybgzs_grok45', 'cc_review_route'],
            'author_model_families': ['gpt'],
        },
    }
    monkeypatch.setattr(plugin.core, 'load_config', lambda: config)
    routes, _ = plugin._routes()
    expected = plugin._pool_identity(routes)
    config['code_review']['workers'] = ['cc_review_route', 'hybgzs_grok45']
    with pytest.raises(RuntimeError, match='reviewer pool changed'):
        plugin._current_pool_worker(expected, 'hybgzs_grok45')


def test_explicit_zero_per_request_bound_is_rejected():
    from hermes_code_review import plugin
    with pytest.raises(RuntimeError, match='must be a positive integer'):
        plugin._positive_setting({'max_input_tokens': 0}, 'max_input_tokens', 120_000)
    with pytest.raises(RuntimeError, match='must be a positive integer'):
        plugin._positive_setting({'max_input_tokens': True}, 'max_input_tokens', 120_000)
    with pytest.raises(RuntimeError, match='must be a positive integer'):
        plugin._positive_setting({'max_input_tokens': '120000'}, 'max_input_tokens', 120_000)


def test_review_tool_reuses_exact_signed_pass_without_remote_call(monkeypatch, tmp_path):
    from hermes_code_review import core, plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
        'code_review': {'author_model_families': ['gpt']},
    })
    snapshot = core.worker_snapshot(core.APPROVED_WORKER, configured_worker())
    plugin.signing.create_signing_key(plugin.SIGNING_KEY)
    cached = plugin.signing.sign_result({
        'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'cached clean'},
        'receipt': {'reviewer_model': snapshot['model'], 'review_head': 'h', 'review_index_tree': 't'},
        'route': core.public_route(snapshot),
        'metrics': {'input_tokens': 10, 'output_tokens': 5, 'elapsed_ms': 7},
        'reused': True,
    }, plugin.SIGNING_KEY)
    monkeypatch.setattr(plugin.core, 'run_git_review', lambda *a, **k: cached)

    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))

    assert value['status'] == 'PASS'
    assert value['reused'] is True
    assert value['fallback_used'] is False
    event = json.loads(plugin.METRICS.read_text().splitlines()[-1])
    assert event['input_tokens'] == 0
    assert event['output_tokens'] == 0


def test_review_tool_never_shops_for_a_pass_after_blocked_verdict(monkeypatch, tmp_path):
    from hermes_code_review import core, plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {
            'hybgzs_grok45': configured_worker(),
            'cc_review_route': configured_fallback_worker(),
        }},
        'code_review': {
            'fallback_workers': ['cc_review_route'],
            'author_model_families': ['gpt'],
        },
    })
    called = []
    def fake_run(repo, name, worker, **kwargs):
        called.append(name)
        snapshot = core.worker_snapshot(name, worker)
        result = {
            'verdict': {'passed': False, 'safe_to_commit': False, 'summary': 'blocked'},
            'receipt': {'reviewer_model': snapshot['model'], 'review_head': 'h', 'review_index_tree': 't'},
            'route': core.public_route(snapshot),
            'metrics': {'input_tokens': 10, 'output_tokens': 5, 'elapsed_ms': 7},
        }
        return plugin.signing.sign_result(result, plugin.SIGNING_KEY)
    monkeypatch.setattr(plugin.core, 'run_git_review', fake_run)

    value = json.loads(plugin.review_git_candidate({
        'repo': str(tmp_path), 'gate_role': 'secondary',
    }))

    assert called == ['hybgzs_grok45']
    assert value['status'] == 'BLOCKED'
    assert value['fallback_used'] is False
    assert value['blocks_handoff'] is True


def test_post_verdict_json_persistence_error_never_triggers_fallback(monkeypatch, tmp_path):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'main_token_reserve': {'workers': {
            'hybgzs_grok45': configured_worker(),
            'cc_review_route': configured_fallback_worker(),
        }},
        'code_review': {
            'workers': ['hybgzs_grok45', 'cc_review_route'],
            'author_model_families': ['gpt'],
        },
    })
    called = []

    def persistence_failure(repo, name, worker, **kwargs):
        called.append(name)
        raise OSError('/tmp/review_runs/result.json')

    monkeypatch.setattr(plugin.core, 'run_git_review', persistence_failure)
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))
    assert called == ['hybgzs_grok45']
    assert value['status'] == 'INFRA_FAILED'


def test_review_tool_fails_closed_when_metrics_sink_fails(monkeypatch, tmp_path):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
        'code_review': {'author_model_families': ['gpt']},
    })
    result = {
        'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'clean'},
        'receipt': {'reviewer_model': 'grok-4.5', 'review_head': 'h', 'review_index_tree': 't'},
        'route': {'name': 'hybgzs_grok45', 'model': 'grok-4.5', 'api_mode': 'chat_completions', 'route_sha': 'route'},
        'metrics': {'input_tokens': 10, 'output_tokens': 5, 'elapsed_ms': 7},
    }
    monkeypatch.setattr(plugin.core, 'run_git_review', lambda *a, **k: plugin.signing.sign_result(result, plugin.SIGNING_KEY))
    monkeypatch.setattr(plugin.observability, 'record_event', lambda *a, **k: (_ for _ in ()).throw(OSError('sink down')))
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))
    assert value['status'] == 'INFRA_FAILED'


def test_public_result_is_whitelisted_and_rejects_known_credential(monkeypatch, tmp_path):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
        'code_review': {'author_model_families': ['gpt']},
    })
    result = {
        'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'clean'},
        'receipt': {'reviewer_model': 'grok-4.5', 'review_head': 'h', 'review_index_tree': 't'},
        'route': {'name': 'hybgzs_grok45', 'model': 'grok-4.5', 'api_mode': 'chat_completions', 'route_sha': 'route', 'endpoint': 'https://private.invalid'},
        'metrics': {'input_tokens': 1, 'output_tokens': 1, 'elapsed_ms': 1, 'debug': 'must-not-escape'},
    }
    monkeypatch.setattr(plugin.core, 'run_git_review', lambda *a, **k: plugin.signing.sign_result(result, plugin.SIGNING_KEY))
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))
    text = json.dumps(value)
    assert value['status'] == 'PASS' and len(value['signature']['digest']) == 64
    assert 'private.invalid' not in text and 'must-not-escape' not in text
    result['verdict']['summary'] = configured_worker()['api_key']
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))
    assert value['status'] == 'INFRA_FAILED'


def test_status_tool_is_non_secret(monkeypatch, tmp_path):
    from hermes_code_review import __version__, core, plugin
    monkeypatch.setattr(plugin.core, 'USAGE_LEDGER', tmp_path / 'usage.json')
    monkeypatch.setattr(plugin.core.time, 'time', lambda: 1000)
    snapshot = core.worker_snapshot(core.APPROVED_WORKER, configured_worker())
    (tmp_path / 'usage.json').write_text(json.dumps({
        'day': '1970-01-01',
        'routes': {snapshot['route_sha']: {
            'input_tokens': 100, 'output_tokens': 10,
            'reserved_input_tokens': 20, 'reserved_output_tokens': 2,
        }},
        'reservations': {},
    }))
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
        'code_review': {'author_model_families': ['gpt']},
    })
    monkeypatch.setattr(
        plugin.core, '_request_json',
        lambda *a, **k: (_ for _ in ()).throw(AssertionError('network probe')),
    )
    value = json.loads(plugin.code_review_status({}))
    assert value['status'] == 'READY'
    assert value['worker'] == 'hybgzs_grok45' and value['model'] == 'grok-4.5'
    assert value['version'] == __version__
    assert value['usage'] == {
        'day_utc': '1970-01-01', 'input_used': 120, 'output_used': 12,
    }
    assert 'secret' not in json.dumps(value)


def test_status_tool_reports_usage_without_local_remaining_quota(monkeypatch, tmp_path):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin.core, 'USAGE_LEDGER', tmp_path / 'usage.json')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
        'code_review': {'author_model_families': ['gpt']},
    })
    value = json.loads(plugin.code_review_status({}))
    assert value['usage'] == {
        'day_utc': value['usage']['day_utc'], 'input_used': 0, 'output_used': 0,
    }
    assert 'input_remaining' not in value['usage']
    assert 'output_remaining' not in value['usage']


def test_status_tool_uses_ready_fallback_when_primary_circuit_is_open(monkeypatch, tmp_path):
    from hermes_code_review import core, plugin
    monkeypatch.setattr(plugin.core, 'STATE', tmp_path / 'health.json')
    monkeypatch.setattr(plugin.core, 'USAGE_LEDGER', tmp_path / 'usage.json')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {
            'hybgzs_grok45': configured_worker(),
            'cc_review_route': configured_fallback_worker(),
        }},
        'code_review': {
            'fallback_workers': ['cc_review_route'],
            'author_model_families': ['gpt'],
        },
    })
    primary = core.worker_snapshot(core.APPROVED_WORKER, configured_worker())
    core.record_failure(plugin.core.STATE, primary['route_sha'], threshold=1, cooldown=300, now=100)
    monkeypatch.setattr(plugin.core.time, 'time', lambda: 101)

    value = json.loads(plugin.code_review_status({}))

    assert value['status'] == 'READY'
    assert value['primary_status'] == 'CIRCUIT_OPEN'
    assert value['fallback'] == 'preapproved_infra_only'
    assert value['fallback_workers'][0]['worker'] == 'cc_review_route'
    assert value['fallback_workers'][0]['status'] == 'READY'


def test_status_tool_stays_truthful_when_all_routes_circuit_open(monkeypatch, tmp_path):
    """All-routes-open must NOT collapse to an opaque failure.

    Regression: the status tool used to raise and return a bare
    {status: INFRA_FAILED, error_class: CIRCUIT_OPEN}, discarding route
    identities, usage, and — critically — when the cooldown lapses. That
    blinded the operator to *when* to retry and invited retry-storms. The tool
    must instead report ALL_ROUTES_UNAVAILABLE with per-route status and the
    soonest retry_after_seconds.
    """
    from hermes_code_review import __version__, core, plugin
    monkeypatch.setattr(plugin.core, 'STATE', tmp_path / 'health.json')
    monkeypatch.setattr(plugin.core, 'USAGE_LEDGER', tmp_path / 'usage.json')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
        'code_review': {'author_model_families': ['gpt']},
    })
    snapshot = core.worker_snapshot(core.APPROVED_WORKER, configured_worker())
    core.record_failure(plugin.core.STATE, snapshot['route_sha'], threshold=1, cooldown=300, now=100)
    monkeypatch.setattr(plugin.core.time, 'time', lambda: 101)
    monkeypatch.setattr(
        plugin.core, '_request_json',
        lambda *a, **k: (_ for _ in ()).throw(AssertionError('network probe')),
    )

    value = json.loads(plugin.code_review_status({}))

    assert value['status'] == 'ALL_ROUTES_UNAVAILABLE'
    assert value['primary_status'] == 'CIRCUIT_OPEN'
    assert value['worker'] == 'hybgzs_grok45'
    assert value['version'] == __version__
    # Truthful cooldown: 300s cooldown opened at t=100, now t=101 -> ~299s left.
    assert value['retry_after_seconds'] == 299
    assert 'usage' in value


def test_status_tool_sanitizes_route_failures_and_never_probes_network(monkeypatch):
    from hermes_code_review import plugin
    monkeypatch.setattr(
        plugin.core, '_request_json',
        lambda *a, **k: (_ for _ in ()).throw(AssertionError('network probe')),
    )
    monkeypatch.setattr(
        plugin, '_routes',
        lambda: (_ for _ in ()).throw(RuntimeError('sensitive path blocked')),
    )

    value = json.loads(plugin.code_review_status({}))

    assert value == {'status': 'INFRA_FAILED', 'error_class': 'PRIVACY'}
    assert 'sensitive path blocked' not in json.dumps(value)
