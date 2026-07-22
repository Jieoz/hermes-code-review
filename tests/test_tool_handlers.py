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
        'delegation': {'lanes': {'critic': {'worker': 'review'}}},
        'main_token_reserve': {'workers': {'review': configured_worker()}},
    })
    seen = {}
    def fake_run(*args, **kwargs):
        seen.update(kwargs)
        return {
            'verdict': {'passed': True, 'safe_to_commit': True, 'summary': 'clean'},
            'receipt': {'reviewer_model': 'grok-4.5', 'review_head': 'h', 'review_index_tree': 't'},
            'route': {'route_sha': 'route'},
            'metrics': {'input_tokens': 10, 'output_tokens': 5, 'elapsed_ms': 7},
        }
    monkeypatch.setattr(plugin.core, 'run_git_review', fake_run)
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path), 'requirements': 'r', 'evidence': 'e'}))
    assert value['status'] == 'PASS'
    assert value['receipt']['reviewer_model'] == 'grok-4.5'
    assert seen['signing_key_path'] == plugin.SIGNING_KEY
    event = json.loads(plugin.METRICS.read_text())
    assert event['status'] == 'PASS' and event['route_sha'] == 'route'
    assert 'secret' not in json.dumps(value)


def test_review_tool_fails_closed_on_any_exception(monkeypatch, tmp_path):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin, 'SIGNING_KEY', tmp_path / 'receipt.key', raising=False)
    monkeypatch.setattr(plugin, 'METRICS', tmp_path / 'metrics.jsonl', raising=False)
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'review'}}},
        'main_token_reserve': {'workers': {'review': configured_worker()}},
    })
    monkeypatch.setattr(plugin.core, 'run_git_review', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('HTTP 504')))
    value = json.loads(plugin.review_git_candidate({'repo': str(tmp_path)}))
    assert value == {'status': 'INFRA_FAILED', 'error': 'HTTP 504'}


def test_status_tool_is_non_secret(monkeypatch):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin.core, 'load_config', lambda: {
        'delegation': {'lanes': {'critic': {'worker': 'review'}}},
        'main_token_reserve': {'workers': {'review': configured_worker()}},
    })
    value = json.loads(plugin.code_review_status({}))
    assert value['status'] == 'READY'
    assert value['worker'] == 'review' and value['model'] == 'grok-4.5'
    assert 'secret' not in json.dumps(value)
