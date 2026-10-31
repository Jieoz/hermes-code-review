"""Append review API calls to Hermes' unified direct-API ledger.

The plugin calls relays directly, outside Hermes' own API logging, so a relay
usage line could not be traced back to it. Same file and schema as
/opt/data/scripts/direct_api_ledger.py. No key, body, or query is recorded.
Best-effort: a ledger failure never affects a review.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

REQUEST_ID_HEADERS = ('x-oneapi-request-id', 'x-request-id', 'request-id', 'x-new-api-request-id',
                      'cf-ray', 'anthropic-request-id', 'openai-request-id')


def ledger_path() -> Path:
    home = Path(os.environ.get('HERMES_HOME', '/opt/data'))
    return Path(os.environ.get('HERMES_DIRECT_API_LEDGER', str(home / 'logs/direct_api_calls.jsonl')))


def request_id_from(headers) -> str:
    try:
        for name in REQUEST_ID_HEADERS:
            value = headers.get(name)
            if value:
                return str(value)[:128]
    except Exception:
        pass
    return ''


def record(*, worker: str, url: str, model: str, status, usage, elapsed_ms: float,
           request_id: str = '', error: str = '') -> None:
    try:
        usage = usage if isinstance(usage, dict) else {}
        inp = usage.get('input_tokens', usage.get('prompt_tokens'))
        out = usage.get('output_tokens', usage.get('completion_tokens'))
        parsed = urlparse(url)
        entry = {
            'ts': datetime.now().astimezone().isoformat(timespec='seconds'),
            'caller': 'code_review', 'worker': str(worker)[:96],
            'host': parsed.hostname or '', 'path': parsed.path[-64:], 'model': str(model)[:96],
            'status': status, 'in': inp if isinstance(inp, int) else None,
            'out': out if isinstance(out, int) else None, 'elapsed_ms': int(elapsed_ms),
            'request_id': request_id, 'stream': True, 'error': str(error)[:160], 'pid': os.getpid(),
        }
        path = ledger_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o640)
        with os.fdopen(fd, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, separators=(',', ':')) + '\n')
    except Exception:
        pass
