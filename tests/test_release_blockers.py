from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest


def approved_worker(**updates):
    value = {
        'provider': 'custom', 'base_url': 'https://review.example/v1',
        'api_key': 'secret', 'model': 'grok-4.5', 'api_mode': 'chat_completions', 'enabled': True,
    }
    value.update(updates)
    return value


def test_reviewer_identity_is_restricted_by_model_and_transport_not_provider_name():
    from hermes_code_review import core
    snapshot = core.worker_snapshot('hybgzs_grok45', approved_worker())
    assert snapshot['model'] == 'grok-4.5'
    assert snapshot['api_mode'] == 'chat_completions'
    assert 'endpoint' not in core.public_route(snapshot)
    assert 'token' not in json.dumps(core.public_route(snapshot))
    with pytest.raises(ValueError, match='must not contain credentials'):
        core.worker_snapshot('hybgzs_grok45', approved_worker(base_url='https://review.example/v1?token=x'))
    assert core.worker_snapshot('other-grok-route', approved_worker())['model'] == 'grok-4.5'
    with pytest.raises(ValueError, match='approved reviewer'):
        core.worker_snapshot('hybgzs_grok45', approved_worker(model='other'))
    with pytest.raises(ValueError, match='approved reviewer'):
        core.worker_snapshot('hybgzs_grok45', approved_worker(api_mode='anthropic_messages'))


def test_preapproved_fallback_reviewer_has_a_different_fixed_identity():
    from hermes_code_review import core
    fallback = approved_worker(
        base_url='https://fallback.example/v1', model='claude-opus-5',
        api_mode='anthropic_messages',
    )
    snapshot = core.worker_snapshot('oojj_opus48', fallback)
    assert snapshot['name'] == 'oojj_opus48'
    assert snapshot['model'] == 'claude-opus-5'
    assert snapshot['api_mode'] == 'anthropic_messages'
    with pytest.raises(ValueError, match='approved reviewer'):
        core.worker_snapshot('oojj_opus48', fallback | {'model': 'unknown-model'})

    gpt = approved_worker(model='gpt-5.6-sol')
    assert core.worker_snapshot('tool102345_gpt56', gpt)['model'] == 'gpt-5.6-sol'


def test_http_error_never_includes_provider_body(monkeypatch):
    from hermes_code_review import core
    error = core.ReviewHTTPError(504, 'Authorization: Bearer ***')
    assert str(error) == 'HTTP 504'
    assert 'Bearer' not in repr(error)

    class Response:
        status = 500
        closed = False
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def close(self): self.closed = True
        def read(self): return b'provider-private-body'
    response = Response()
    monkeypatch.setattr(core.urllib.request, 'urlopen', lambda *args, **kwargs: response)
    snapshot = {'api_mode': 'chat_completions', 'credential': 'x', 'extra_headers': {}, 'endpoint': 'https://review.example/v1/chat/completions'}
    with pytest.raises(core.ReviewHTTPError) as caught:
        core._request_json(snapshot, {}, 1)
    assert str(caught.value) == 'HTTP 500'
    assert 'private' not in repr(caught.value)
    assert response.closed is True


def test_negative_usage_is_rejected():
    from hermes_code_review import core
    payload = {'choices': [{'message': {'content': '{}'}}], 'usage': {'prompt_tokens': -1, 'completion_tokens': 2}}
    with pytest.raises(ValueError, match='usage'):
        core.extract_response(payload, 'chat_completions')


def test_provider_response_size_is_bounded(monkeypatch):
    from hermes_code_review import core
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit): return b'x' * limit
    monkeypatch.setattr(core.urllib.request, 'urlopen', lambda *a, **k: Response())
    snapshot = {'api_mode': 'chat_completions', 'credential': 'x', 'extra_headers': {}, 'endpoint': 'https://review.example/v1/chat/completions'}
    with pytest.raises(ValueError, match='size limit'):
        core._request_json(snapshot, {}, 1)


def _repo(path: Path):
    subprocess.run(['git', 'init', '-q', str(path)], check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.email', 't@example.invalid'], check=True)
    subprocess.run(['git', '-C', str(path), 'config', 'user.name', 'T'], check=True)
    (path / 'x.py').write_text('one\ntwo\n')
    subprocess.run(['git', '-C', str(path), 'add', 'x.py'], check=True)
    subprocess.run(['git', '-C', str(path), 'commit', '-qm', 'base'], check=True)
    (path / 'x.py').write_text('one\ntwo\nthree\n')
    subprocess.run(['git', '-C', str(path), 'add', 'x.py'], check=True)


def test_blocking_finding_references_must_exist_in_index(tmp_path):
    from hermes_code_review import core
    _repo(tmp_path)
    index_tree = subprocess.check_output(['git', '-C', str(tmp_path), 'write-tree'], text=True).strip()
    valid = {'p0': [], 'p1': [{'file': 'x.py', 'line': 3, 'issue': 'bug'}]}
    core.validate_finding_references(tmp_path, valid, index_tree=index_tree)
    bad_path = {'p0': [{'file': '../secret', 'line': 1, 'issue': 'bug'}], 'p1': []}
    with pytest.raises(ValueError, match='not present'):
        core.validate_finding_references(tmp_path, bad_path, index_tree=index_tree)
    bad_line = {'p0': [], 'p1': [{'file': 'x.py', 'line': 99, 'issue': 'bug'}]}
    with pytest.raises(ValueError, match='line is outside'):
        core.validate_finding_references(tmp_path, bad_line, index_tree=index_tree)


def test_public_plugin_errors_are_classified_not_echoed(monkeypatch):
    from hermes_code_review import plugin
    monkeypatch.setattr(plugin, '_routes', lambda: (_ for _ in ()).throw(RuntimeError('Bearer super-secret')))
    payload = json.loads(plugin.review_git_candidate({'repo': '/tmp/nope'}))
    assert payload == {'status': 'GATE_FAILED', 'error_class': 'PRIVACY'}
    assert 'secret' not in json.dumps(payload).lower()
