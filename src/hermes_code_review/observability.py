from __future__ import annotations

import fcntl
import json
import os
import re
import time
from pathlib import Path


def classify_error(message: str) -> str:
    text = message.lower()
    match = re.search(r'http\s+(\d{3})', text)
    if match:
        status = int(match.group(1))
        if status == 429:
            return 'HTTP_429'
        if 500 <= status <= 599:
            return 'HTTP_5XX'
        return 'HTTP_OTHER'
    if '1013' in text or 'no available account' in text:
        return 'NO_ACCOUNT'
    if 'timeout' in text or 'timed out' in text:
        return 'TIMEOUT'
    if 'verdict' in text or 'json' in text:
        return 'INVALID_VERDICT'
    if 'stale' in text:
        return 'STALE'
    if 'budget' in text:
        return 'BUDGET'
    if 'secret' in text or 'sensitive path' in text:
        return 'PRIVACY'
    return 'OTHER'


def record_event(path: Path, *, status: str, worker: str, model: str, route_sha: str,
                 elapsed_ms: int, input_tokens: int, output_tokens: int,
                 error: str = '') -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        'timestamp': int(time.time()),
        'status': status,
        'worker': worker,
        'model': model,
        'route_sha': route_sha,
        'elapsed_ms': int(elapsed_ms),
        'input_tokens': int(input_tokens),
        'output_tokens': int(output_tokens),
        'error_class': classify_error(error) if error else '',
    }
    line = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n'
    lock_path = path.with_name(f'.{path.name}.lock')
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with path.open('a', encoding='utf-8') as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
