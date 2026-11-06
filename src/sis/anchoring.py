"""Manual out-of-database checkpoints for rollback detection.

The checkpoint only has value when kept outside the database writer's control.
An unsigned checkpoint is NOT authenticated. An HMAC requires an external secret.
No web endpoint is offered for exporting or overwriting checkpoint files.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
from .errors import InvalidInput, RuleRejected
from .validation import canonical

FORMAT = "sis-audit-anchor-v1"
MAX_FILE = 4096


def _key():
    value = os.environ.get('SIS_ANCHOR_HMAC_KEY')
    if value is None:
        return None
    if len(value.encode('utf8')) < 32:
        raise InvalidInput('SIS_ANCHOR_HMAC_KEY must contain at least 32 UTF-8 bytes')
    return value.encode('utf8')


def _payload(registry):
    status = registry.verify_audit()
    if not status.get('valid'):
        raise RuleRejected('cannot checkpoint invalid audit: ' + status.get('reason', 'unknown'))
    return {'format': FORMAT, 'sequence': status['events_verified'],
            'head': status['head'], 'rules_verified': status['rules_verified']}


def _signed(payload, key):
    blob = canonical(payload).encode('utf8')
    return {'record': payload, 'auth': 'hmac-sha256' if key else 'unkeyed-sha256',
            'checksum': (hmac.new(key, blob, hashlib.sha256).hexdigest() if key
                         else hashlib.sha256(blob).hexdigest())}


def export_anchor(registry, path):
    """Create, never replace, a checkpoint. Move it to separately controlled storage."""
    key = _key()
    body = _signed(_payload(registry), key)
    target = Path(path)
    # O_EXCL prevents accidentally replacing an earlier trusted checkpoint.
    fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf8') as f:
            f.write(canonical(body) + '\n')
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    return {'created': True, 'path': str(target), 'sequence': body['record']['sequence'],
            'head': body['record']['head'], 'auth': body['auth'],
            'warning': 'Store outside the DB writer trust boundary; unsigned anchors require trusted custody'}


def verify_anchor_file(registry, path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_FILE:
        raise InvalidInput('anchor file exceeds size limit')
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidInput('invalid anchor JSON') from exc
    if not isinstance(obj, dict) or set(obj) != {'record', 'auth', 'checksum'}:
        raise InvalidInput('invalid anchor format')
    payload = obj['record']
    if not isinstance(payload, dict) or set(payload) != {'format', 'sequence', 'head', 'rules_verified'} or payload['format'] != FORMAT:
        raise InvalidInput('invalid anchor payload')
    if type(payload['sequence']) is not int or payload['sequence'] < 0 or type(payload['rules_verified']) is not int or payload['rules_verified'] < 0:
        raise InvalidInput('invalid anchor counters')
    if not isinstance(payload['head'], str) or len(payload['head']) != 64 or any(c not in '0123456789abcdef' for c in payload['head']):
        raise InvalidInput('invalid anchor digest')
    key = _key()
    if obj['auth'] not in ('hmac-sha256', 'unkeyed-sha256'):
        raise InvalidInput('unsupported anchor authentication')
    if obj['auth'] == 'hmac-sha256' and not key:
        return {'valid': False, 'reason': 'missing_hmac_key'}
    signed = _signed(payload, key if obj['auth'] == 'hmac-sha256' else None)
    if not isinstance(obj['checksum'], str) or not hmac.compare_digest(obj['checksum'], signed['checksum']):
        return {'valid': False, 'reason': 'checkpoint_authentication_failed'}
    current = registry.verify_audit()
    if not current['valid']:
        return {'valid': False, 'reason': 'invalid_registry', 'registry_reason': current['reason']}
    if current['events_verified'] < payload['sequence']:
        return {'valid': False, 'reason': 'checkpoint_mismatch',
                'checkpoint_sequence': payload['sequence'], 'registry_sequence': current['events_verified']}
    with registry.lock:
        if payload['sequence'] == 0:
            historical_head = '0' * 64
            past_rules = 0
        else:
            head_row = registry.conn.execute('SELECT event_hash FROM audit WHERE seq=?',
                                             (payload['sequence'],)).fetchone()
            historical_head = head_row[0] if head_row else None
            past_rules = sum(json.loads(x[0]).get('event') == 'rule_promoted'
                for x in registry.conn.execute('SELECT event_json FROM audit WHERE seq<=?',
                                               (payload['sequence'],)))
    if historical_head != payload['head'] or past_rules != payload['rules_verified']:
        return {'valid': False, 'reason': 'checkpoint_mismatch',
                'checkpoint_sequence': payload['sequence'], 'registry_sequence': current['events_verified']}
    return {'valid': True, 'sequence': payload['sequence'], 'head': payload['head'],
            'new_events_after_anchor': current['events_verified'] - payload['sequence'],
            'auth': obj['auth'], 'warning': ('unkeyed anchor authenticity depends on independent custody'
                                            if obj['auth'] == 'unkeyed-sha256' else 'HMAC secret must remain outside the DB writer trust boundary')}
