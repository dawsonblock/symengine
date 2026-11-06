"""SQLite registry whose rule projection is checked against a hash-linked audit log.

Not a trusted enclave: rewriting both DB tables can forge the entire history.
External anchoring is still required to detect truncation or full replacement.
Legacy 1.0 entries lacking projection evidence fail closed on prediction.
"""
import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from .errors import InvalidInput, RuleRejected
from .expression import evaluate, validate_ast
from .induction import generated_probes
from .validation import canonical, digest, check_inputs, input_schema, namespace_name, check_scalar


def utc():
    return datetime.now(timezone.utc).isoformat()


COLUMNS = ('id','namespace','schema_json','expression_json','train_digest','validation_digest',
           'train_count','validation_count','status','created_utc','feedback_positive','feedback_negative')


# Fields that cannot change once an authorized rule is promoted.
IMMUTABLE_COLUMNS = set(COLUMNS) - {'status', 'feedback_positive', 'feedback_negative'}


def _valid_projection(event, prior):
    """Validate event semantics, not just a matching hash or latest snapshot.

    An attacker who can rewrite the entire database can still forge a coherent
    history. Externally controlled anchor custody is required against that threat.
    """
    kind = event['event']
    p = event['projection']
    if set(p) != set(COLUMNS) or p['id'] != event['rule_id'] or p['namespace'] != event.get('namespace'):
        return False
    try:
        namespace_name(p['namespace'])
        validate_ast(p['expression_json'])
        schema = p['schema_json']
        if not isinstance(schema, dict) or not 1 <= len(schema) <= 16:
            return False
        allowed_types = {'str', 'int', 'bool'}
        for field, typ in schema.items():
            namespace_name(field)
            if isinstance(typ, list):
                if not 1 <= len(typ) <= 16 or any(t not in allowed_types for t in typ):
                    return False
            elif typ not in allowed_types:
                return False
        if p['id'] != digest({'namespace':p['namespace'], 'schema':schema, 'expr':p['expression_json']}):
            return False
        for field in ('train_digest', 'validation_digest'):
            if not isinstance(p[field], str) or len(p[field]) != 64 or any(x not in '0123456789abcdef' for x in p[field]):
                return False
        if not isinstance(p['created_utc'], str):
            return False
        for field in ('train_count','validation_count','feedback_positive','feedback_negative'):
            if type(p[field]) is not int or p[field] < 0:
                return False
        if p['train_count'] < 3 or p['validation_count'] < 2:
            return False
    except (InvalidInput, KeyError, TypeError, ValueError):
        return False
    if kind == 'rule_promoted':
        return (prior is None and p['status'] == 'active' and
                p['feedback_positive'] == p['feedback_negative'] == 0)
    if prior is None or any(p[f] != prior[f] for f in IMMUTABLE_COLUMNS):
        return False
    if kind == 'user_reported_feedback':
        matched = event.get('matched')
        if type(matched) is not bool or prior['status'] == 'retired':
            return False
        return (p['feedback_positive'] == prior['feedback_positive'] + int(matched)
                and p['feedback_negative'] == prior['feedback_negative'] + int(not matched)
                and p['status'] == (prior['status'] if matched else 'suspended'))
    if kind == 'rule_retired':
        return (prior['status'] != 'retired' and p['status'] == 'retired' and
                p['feedback_positive'] == prior['feedback_positive'] and
                p['feedback_negative'] == prior['feedback_negative'])
    return False


class Registry:
    def __init__(self, path='sis.sqlite3'):
        self.path = str(path)
        self.lock = threading.RLock()
        if self.path != ':memory:':
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA busy_timeout=10000')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY, namespace TEXT NOT NULL, schema_json TEXT NOT NULL,
            expression_json TEXT NOT NULL, train_digest TEXT NOT NULL,
            validation_digest TEXT NOT NULL, train_count INTEGER NOT NULL,
            validation_count INTEGER NOT NULL, status TEXT NOT NULL,
            created_utc TEXT NOT NULL, feedback_positive INTEGER NOT NULL DEFAULT 0,
            feedback_negative INTEGER NOT NULL DEFAULT 0)''')
        self.conn.execute('CREATE INDEX IF NOT EXISTS rules_lookup ON rules(namespace,status)')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS audit (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, event_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')
        self.conn.commit()

    def close(self):
        with self.lock:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _snapshot(self, rule_id):
        row = self.conn.execute('SELECT ' + ','.join(COLUMNS) + ' FROM rules WHERE id=?', (rule_id,)).fetchone()
        if row is None:
            raise RuleRejected('rule projection unexpectedly missing')
        result = dict(zip(COLUMNS, row))
        # Canonicalized JSON parsed here to match semantic rather than formatting differences.
        result['schema_json'] = json.loads(result['schema_json'])
        result['expression_json'] = json.loads(result['expression_json'])
        return result

    def _append(self, event):
        previous = self.conn.execute('SELECT event_hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        prev = previous[0] if previous else '0' * 64
        body = canonical(event)
        hv = hashlib.sha256((prev + '\n' + body).encode('utf8')).hexdigest()
        self.conn.execute('INSERT INTO audit(event_json,previous_hash,event_hash) VALUES(?,?,?)', (body,prev,hv))
        return hv

    def verify_audit(self):
        """Verify hash continuity AND final rule projection. Fails closed on v1 legacy rows.

        No external checkpoint = attacker with write permission can forge both log and table.
        """
        with self.lock:
            rows = self.conn.execute('SELECT seq,event_json,previous_hash,event_hash FROM audit ORDER BY seq').fetchall()
            rules = self.conn.execute('SELECT id FROM rules ORDER BY id').fetchall()
            previous = '0' * 64
            snapshots = {}
            count = 0
            for seq, body, prior, hashed in rows:
                if seq != count+1 or prior != previous or hashlib.sha256((previous+'\n'+body).encode('utf8')).hexdigest() != hashed:
                    return {'valid':False,'events_verified':count,'first_bad_seq':seq,'reason':'audit_hash_or_sequence_failure'}
                try:
                    event = json.loads(body)
                    if canonical(event) != body or not isinstance(event, dict):
                        raise ValueError('noncanonical or non-object event')
                except (ValueError, TypeError):
                    return {'valid':False,'events_verified':count,'first_bad_seq':seq,'reason':'invalid_audit_event'}
                event_kind = event.get('event')
                if event_kind in ('rule_promoted','user_reported_feedback','rule_retired'):
                    rid = event.get('rule_id')
                    if not isinstance(rid, str) or not isinstance(event.get('projection'), dict):
                        return {'valid':False,'events_verified':count,'first_bad_seq':seq,'reason':'legacy_or_missing_rule_projection'}
                    if event['projection'].get('id') != rid:
                        return {'valid':False,'events_verified':count,'first_bad_seq':seq,'reason':'projection_rule_mismatch'}
                    if event_kind == 'rule_promoted' and rid in snapshots:
                        return {'valid':False,'events_verified':count,'first_bad_seq':seq,'reason':'duplicate_rule_promotion'}
                    if event_kind != 'rule_promoted' and rid not in snapshots:
                        return {'valid':False,'events_verified':count,'first_bad_seq':seq,'reason':'unpromoted_rule_change'}
                    if not _valid_projection(event, snapshots.get(rid)):
                        return {'valid':False,'events_verified':count,'first_bad_seq':seq,'reason':'invalid_rule_transition'}
                    snapshots[rid] = event['projection']
                elif event_kind not in ():  # Unknown event kinds must not grant authority.
                    return {'valid':False,'events_verified':count,'first_bad_seq':seq,'reason':'unsupported_audit_event'}
                count += 1
                previous = hashed
            ids = {row[0] for row in rules}
            if ids != set(snapshots):
                return {'valid':False,'events_verified':count,'reason':'unaccounted_rule_or_missing_projection'}
            try:
                for rid in ids:
                    if self._snapshot(rid) != snapshots[rid]:
                        return {'valid':False,'events_verified':count,'reason':'rule_projection_mismatch','rule_id':rid}
            except (ValueError, TypeError, KeyError):
                return {'valid':False,'events_verified':count,'reason':'malformed_rule_projection'}
            return {'valid':True,'events_verified':count,'rules_verified':len(ids),'head':previous,
                    'warning':'no external anchor; full-history rewrite or suffix truncation cannot be excluded'}

    def _require_integrity(self):
        result = self.verify_audit()
        if not result['valid']:
            raise RuleRejected('rule database integrity cannot be verified: '+result['reason'])

    def promote(self, result, *, train=None, validation=None, max_candidates=12000,
                proposals=None, use_z3=False):
        """Re-induce from original examples before admitting a rule.

        A caller-supplied result or digest is NEVER sufficient evidence. This
        second pass prevents direct Python callers from forging promotion facts.
        The inputs and induction configuration must be supplied again.
        """
        if not isinstance(result, dict) or not isinstance(result.get('namespace'), str):
            raise RuleRejected('promotion result must be a valid induction record')
        if train is None or validation is None:
            raise RuleRejected('promotion requires original train and validation records for independent recomputation')
        from .induction import induce
        try:
            recomputed = induce(train, validation, namespace=result['namespace'],
                                max_candidates=max_candidates, proposals=proposals,
                                use_z3=use_z3)
        except (InvalidInput, KeyError, TypeError, ValueError) as exc:
            raise RuleRejected('unable to reproduce promotion study') from exc
        if canonical(recomputed) != canonical(result):
            raise RuleRejected('supplied induction result does not match independently recomputed evidence')
        if not isinstance(result, dict) or result.get('status') != 'locally_validated':
            raise RuleRejected('only unambiguous locally validated induction results can be promoted')
        if result.get('search_truncated') or result.get('distinguishing_probe'):
            raise RuleRejected('incomplete or ambiguous search cannot be promoted')
        if (type(result.get('train_count')) is not int or result['train_count'] < 3 or
            type(result.get('validation_count')) is not int or result['validation_count'] < 2 or
            result.get('validation_passed') != result['validation_count']):
            raise RuleRejected('insufficient training/validation evidence')
        name = namespace_name(result['namespace'])
        expr = validate_ast(result['rule'])
        schema = result['schema']
        key = digest({'namespace':name,'schema':schema,'expr':expr})
        with self.lock, self.conn:
            self._require_integrity()
            prior = self.conn.execute('SELECT id FROM rules WHERE id=?', (key,)).fetchone()
            if prior:
                return {'id':key,'created':False,'status':'already_exists'}
            # The grammar has no domain guards. Two active expressions with an
            # identical schema must not be admitted when they disagree on a
            # bounded, deterministic set of probes. This is a safety filter,
            # NOT a proof of equivalence outside these checked inputs.
            inputs_to_check = [ex['inputs'] for ex in train + validation]
            inputs_to_check.extend(generated_probes(train[0]['inputs'], limit=256))
            previous_rules = self.list_rules(name)
            for stored in previous_rules:
                if stored['schema'] != schema:
                    continue
                for probe in inputs_to_check:
                    try:
                        expected, proposed = evaluate(stored['rule'], probe), evaluate(expr, probe)
                    except (InvalidInput, KeyError, IndexError, TypeError, OverflowError):
                        continue
                    if type(expected) is not type(proposed) or expected != proposed:
                        raise RuleRejected('active rule conflict; admission rejected: '
                                           + canonical({'existing_rule_id':stored['id'],
                                                        'probe':probe,
                                                        'existing_output':expected,
                                                        'proposed_output':proposed}))
            self.conn.execute('''INSERT INTO rules
                (id,namespace,schema_json,expression_json,train_digest,validation_digest,train_count,validation_count,status,created_utc)
                VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (key,name,canonical(schema),canonical(expr),result['train_digest'],result['validation_digest'],
                 result['train_count'],result['validation_count'],'active',utc()))
            self._append({'event':'rule_promoted','rule_id':key,'namespace':name,
                          'projection':self._snapshot(key),'verification_scope':'locally supplied validation', 'at':utc()})
        return {'id':key,'created':True,'status':'active'}

    def list_rules(self, namespace='default', include_suspended=False):
        name = namespace_name(namespace)
        with self.lock:
            self._require_integrity()  # never expose unverified rules as usable knowledge
            q = '''SELECT id,schema_json,expression_json,status,train_count,validation_count,
                   feedback_positive,feedback_negative,created_utc FROM rules WHERE namespace=?'''
            if not include_suspended:
                q += " AND status='active'"
            rows = self.conn.execute(q+' ORDER BY created_utc,id', (name,)).fetchall()
        return [{'id':r[0],'schema':json.loads(r[1]),'rule':json.loads(r[2]),'status':r[3],
                 'train_count':r[4],'validation_count':r[5], 'feedback_positive':r[6],
                 'feedback_negative':r[7],'created_utc':r[8]} for r in rows]

    def predict(self, namespace, inputs, rule_id=None):
        namespace = namespace_name(namespace)
        inputs = check_inputs(inputs)
        with self.lock:
            integrity = self.verify_audit()
            if not integrity['valid']:
                return {'status':'abstain','reason':'rule registry integrity failed: '+integrity['reason']}
            schema = input_schema(inputs)
            applicable = [r for r in self.list_rules(namespace) if r['schema'] == schema and (rule_id is None or r['id'] == rule_id)]
            if not applicable:
                return {'status':'abstain','reason':'no active rule matches namespace and exact schema'}
            predictions = []
            for rule in applicable:
                try:
                    predictions.append((rule['id'],evaluate(rule['rule'],inputs)))
                except (InvalidInput, KeyError, IndexError, TypeError, OverflowError):
                    continue
            if not predictions:
                return {'status':'abstain','reason':'matching rules failed to evaluate'}
            if len({canonical(y) for _,y in predictions}) != 1:
                return {'status':'abstain','reason':'active rules disagree','rule_ids':[r for r,_ in predictions]}
            return {'status':'predicted','output':predictions[0][1],
                    'rule_ids':[r for r,_ in predictions],
                    'evidence':'local validation and in-DB integrity only; no independent performance guarantee'}

    def feedback(self, namespace, rule_id, inputs, observed_output):
        namespace = namespace_name(namespace)
        inputs = check_inputs(inputs)
        check_scalar(observed_output)
        with self.lock, self.conn:
            self._require_integrity()
            row = self.conn.execute('SELECT expression_json,schema_json,status FROM rules WHERE id=? AND namespace=?',
                                    (rule_id,namespace)).fetchone()
            if not row:
                raise InvalidInput('unknown rule id')
            if row[2] == 'retired':
                raise RuleRejected('retired rules cannot receive feedback')
            if json.loads(row[1]) != input_schema(inputs):
                raise InvalidInput('feedback input schema differs from rule schema')
            predicted = evaluate(json.loads(row[0]),inputs)
            if type(predicted) is not type(observed_output):
                raise InvalidInput('feedback output type differs from rule output')
            success = predicted == observed_output
            if success:
                self.conn.execute('UPDATE rules SET feedback_positive=feedback_positive+1 WHERE id=?',(rule_id,))
            else:
                self.conn.execute("UPDATE rules SET feedback_negative=feedback_negative+1,status='suspended' WHERE id=?",(rule_id,))
            self._append({'event':'user_reported_feedback','rule_id':rule_id,'namespace':namespace,
                          'projection':self._snapshot(rule_id),'inputs_digest':digest(inputs),
                          'observed_output_digest':digest(observed_output),
                          'predicted_output_digest':digest(predicted),'matched':success,'at':utc()})
            return {'matched':success,'status':self._snapshot(rule_id)['status'],
                    'evidence_origin':'user_reported'}

    def retire(self, namespace, rule_id):
        namespace = namespace_name(namespace)
        with self.lock, self.conn:
            self._require_integrity()
            row = self.conn.execute('SELECT status FROM rules WHERE id=? AND namespace=?', (rule_id,namespace)).fetchone()
            if not row:
                raise InvalidInput('unknown rule id')
            if row[0] == 'retired':
                return {'id':rule_id,'status':'retired','changed':False}
            self.conn.execute("UPDATE rules SET status='retired' WHERE id=?",(rule_id,))
            self._append({'event':'rule_retired','rule_id':rule_id,'namespace':namespace,
                          'projection':self._snapshot(rule_id),'at':utc()})
            return {'id':rule_id,'status':'retired','changed':True}
