import pytest


@pytest.fixture(autouse=True)
def _isolated_direct_ledger(monkeypatch, tmp_path):
    """Tests must never append to the production direct-API ledger."""
    path = tmp_path / 'direct_api_calls.jsonl'
    monkeypatch.setenv('HERMES_DIRECT_API_LEDGER', str(path))
    return path
