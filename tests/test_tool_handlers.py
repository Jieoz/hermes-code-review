from __future__ import annotations

import json


def configured_worker():
    return {
        'provider': 'custom', 'base_url': 'https://review.example/v1',
        'api_key': 'secret', 'model': 'grok-4.5', 'api_mode': 'chat_completions',
        'enabled': True,
    }


def test_review_tool_returns_machine_pass(monkeypatch, tmp_path):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
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
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path), 'requirements': 'r', 'evidence': 'e'}))
    assert value['status'] == 'PASS'
    assert value['receipt']['reviewer_model'] == 'grok-4.5'
    assert seen['signing_key_path'] == plugin.SIGNING_KEY
    assert seen['max_source_bytes'] == 350_000
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
    })
    monkeypatch.setattr(plugin.core, 'run_git_review', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('HTTP 504')))
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))
    assert value == {'status': 'INFRA_FAILED', 'error_class': 'HTTP_5XX'}


def test_review_tool_fails_closed_when_metrics_sink_fails(monkeypatch, tmp_path):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
    })
    result = {
        'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'clean'},
        'receipt': {'reviewer_model': 'grok-4.5'},
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
    })
    result = {
        'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'clean'},
        'receipt': {'reviewer_model': 'grok-4.5'},
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


def test_status_tool_is_non_secret(monkeypatch):
    from hermes_code_review import __version__, plugin
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
    })
    monkeypatch.setattr(
        plugin.core, '_request_json',
        lambda *a, **k: (_ for _ in ()).throw(AssertionError('network probe')),
    )
    value = json.loads(plugin.code_review_status({}))
    assert value['status'] == 'READY'
    assert value['worker'] == 'hybgzs_grok45' and value['model'] == 'grok-4.5'
    assert value['version'] == __version__
    assert 'secret' not in json.dumps(value)


def test_status_tool_fails_closed_when_reviewer_circuit_is_open(monkeypatch, tmp_path):
    from hermes_code_review import core, plugin
    monkeypatch.setattr(plugin.core, 'STATE', tmp_path / 'health.json')
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'hybgzs_grok45'}}},
        'main_token_reserve': {'workers': {'hybgzs_grok45': configured_worker()}},
    })
    snapshot = core.worker_snapshot(core.APPROVED_WORKER, configured_worker())
    core.record_failure(plugin.core.STATE, snapshot['route_sha'], threshold=1, cooldown=300, now=100)
    monkeypatch.setattr(plugin.core.time, 'time', lambda: 101)
    monkeypatch.setattr(
        plugin.core, '_request_json',
        lambda *a, **k: (_ for _ in ()).throw(AssertionError('network probe')),
    )

    value = json.loads(plugin.code_review_status({}))

    assert value == {'status': 'INFRA_FAILED', 'error_class': 'CIRCUIT_OPEN'}


def test_status_tool_sanitizes_route_failures_and_never_probes_network(monkeypatch):
    from hermes_code_review import plugin
    monkeypatch.setattr(
        plugin.core, '_request_json',
        lambda *a, **k: (_ for _ in ()).throw(AssertionError('network probe')),
    )
    monkeypatch.setattr(
        plugin, '_route',
        lambda: (_ for _ in ()).throw(RuntimeError('sensitive path blocked')),
    )

    value = json.loads(plugin.code_review_status({}))

    assert value == {'status': 'INFRA_FAILED', 'error_class': 'PRIVACY'}
    assert 'sensitive path blocked' not in json.dumps(value)
