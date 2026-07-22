from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path


def create_signing_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        _read_key(path)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(secrets.token_bytes(32))
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _read_key(path: Path) -> bytes:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError('receipt signing key must be a regular file')
    if info.st_mode & 0o077:
        raise ValueError('receipt signing key permissions must be 0600')
    key = path.read_bytes()
    if len(key) < 32:
        raise ValueError('receipt signing key must contain at least 32 bytes')
    return key


def _payload(result: dict) -> bytes:
    value = {k: result[k] for k in ('receipt', 'verdict', 'metrics') if k in result}
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sign_result(result: dict, key_path: Path) -> dict:
    key = _read_key(key_path)
    signed = copy.deepcopy(result)
    signed.pop('signature', None)
    digest = hmac.new(key, _payload(signed), hashlib.sha256).hexdigest()
    signed['signature'] = {'algorithm': 'hmac-sha256', 'digest': digest}
    return signed


def verify_result(result: dict, key_path: Path) -> None:
    signature = result.get('signature') if isinstance(result, dict) else None
    if not isinstance(signature, dict) or signature.get('algorithm') != 'hmac-sha256':
        raise ValueError('review signature missing or unsupported')
    expected = hmac.new(_read_key(key_path), _payload(result), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(signature.get('digest') or ''), expected):
        raise ValueError('review signature verification failed')
