from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import time
from pathlib import Path


_IDENTITY = re.compile(r'^[A-Za-z0-9_.:-]{0,128}$')


def _open_append(path: Path):
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        os.close(fd)
        raise ValueError('unsafe metrics file')
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'a', encoding='utf-8')


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
    if 'stale' in text:
        return 'STALE'
    if 'verdict' in text:
        return 'INVALID_VERDICT'
    if 'circuit open' in text:
        return 'CIRCUIT_OPEN'
    if 'budget' in text:
        return 'BUDGET'
    if 'secret' in text or 'sensitive path' in text:
        return 'PRIVACY'
    return 'OTHER'


def record_event(path: Path, *, status: str, worker: str, model: str, route_sha: str,
                 elapsed_ms: int, input_tokens: int, output_tokens: int,
                 error: str = '') -> None:
    if status not in {'PASS', 'BLOCKED', 'INFRA_FAILED', 'STALE', 'NEEDS_EVIDENCE'}:
        raise ValueError('invalid metrics status')
    if not all(_IDENTITY.fullmatch(value) for value in (worker, model, route_sha)):
        raise ValueError('unsafe metrics identity')
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
    with _open_append(lock_path) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with _open_append(path) as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
