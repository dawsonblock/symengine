"""Evaluator-custodied, one-use synthetic/local holdout scoring.

The vault is a *separate trust domain* only if the evaluator is operated by a
separate custodian with the secret and database withheld from developers.
This package never claims locally generated holdouts are independently sourced.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from collections import Counter
from datetime import datetime, timezone

from .errors import InvalidInput, RuleRejected
from .expression import evaluate, validate_ast
from .validation import canonical, check_examples, digest, input_schema, namespace_name
from .qualification import check_policy, DEFAULT_POLICY, assess
from .vault_storage import private_sqlite_path

MAX_VAULT_TASKS = 10000


def _key_from_env(name="SIS_EVAL_HMAC_KEY"):
    if not isinstance(name, str) or not name or len(name) > 128:
        raise InvalidInput("invalid key environment variable name")
    key = os.environ.get(name, "").encode("utf8")
    if len(key) < 32:
        raise RuleRejected(f"set {name} to a private secret of at least 32 UTF-8 bytes")
    return key


def _mac(key, obj):
    return hmac.new(key, canonical(obj).encode("utf8"), hashlib.sha256).hexdigest()


def _signed(key, obj, field):
    return {**obj, field: _mac(key, obj)}


def _check_signature(key, obj, field):
    if not isinstance(obj, dict) or type(obj.get(field)) is not str:
        raise RuleRejected("signature missing")
    unsigned = {k: v for k, v in obj.items() if k != field}
    if not hmac.compare_digest(obj[field], _mac(key, unsigned)):
        raise RuleRejected("signature verification failed")
    return unsigned


def _validate_dataset(data):
    if not isinstance(data, dict) or not set(data).issubset({'namespace','train','validation','test','shifted_test','task_id','qualification_policy'}):
        raise InvalidInput("evaluation dataset has unexpected fields")
    for required in ('train','validation','test'):
        if required not in data:
            raise InvalidInput(f"missing {required}")
    namespace = namespace_name(data.get('namespace', 'evaluation'))
    task_id = data.get('task_id', 'unnamed')
    if not isinstance(task_id, str) or not 1 <= len(task_id) <= 120:
        raise InvalidInput("task_id must be a nonempty string up to 120 characters")
    parts = {'train': check_examples(data['train'], minimum=3),
             'validation': check_examples(data['validation'], minimum=2),
             'test': check_examples(data['test'], minimum=2),
             'shifted_test': check_examples(data.get('shifted_test', []))}
    if parts['shifted_test'] and len(parts['shifted_test']) < 2:
        raise InvalidInput("shifted_test must be empty or contain at least 2 examples")
    schema = input_schema(parts['train'][0]['inputs'])
    output_type = type(parts['train'][0]['output'])
    unique = set()
    for section, records in parts.items():
        for record in records:
            if input_schema(record['inputs']) != schema or type(record['output']) is not output_type:
                raise InvalidInput("all partitions must share exact schema and output type")
            key = digest(record['inputs'])
            if key in unique:
                raise InvalidInput("overlapping or duplicate inputs across evaluation splits")
            unique.add(key)
    return namespace, task_id, parts, schema, output_type.__name__, unique


def _metrics(rule, examples, majority_key):
    attempted = correct = baseline_correct = runtime_failures = 0
    for example in examples:
        baseline_correct += canonical(example['output']) == majority_key
        try:
            outcome = evaluate(rule, example['inputs'])
            # `None` isn't a valid scalar output; it means abstention/error only.
            attempted += 1
            correct += type(outcome) is type(example['output']) and outcome == example['output']
        except (InvalidInput, KeyError, TypeError, ValueError, OverflowError, IndexError):
            runtime_failures += 1
    total = len(examples)
    return {
        'count':total, 'answered':attempted, 'correct':correct,
        'wrong':attempted-correct, 'abstained':total-attempted,
        'coverage':attempted/total if total else None,
        'accuracy_on_answered':correct/attempted if attempted else None,
        'overall_accuracy':correct/total if total else None,
        'train_majority_baseline_accuracy':baseline_correct/total if total else None,
        'runtime_failures':runtime_failures,
    }


class EvaluatorVault:
    """Handle only in evaluator-side process. Do not expose vault path or key to agent."""
    def __init__(self, path, *, key=None):
        self.path = private_sqlite_path(path, 'evaluator vault')
        self.key = key if key is not None else _key_from_env()
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise RuleRejected("evaluator secret must contain at least 32 bytes")
        self.conn = sqlite3.connect(str(self.path), timeout=15, isolation_level=None)
        self.conn.execute('PRAGMA busy_timeout=15000')
        self.conn.execute('PRAGMA journal_mode=DELETE')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS tasks (
            evaluation_id TEXT PRIMARY KEY, public_json TEXT NOT NULL,
            secret_json TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0,
            receipt_json TEXT
        )''')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS input_commitments (
            input_digest TEXT PRIMARY KEY, evaluation_id TEXT NOT NULL
        )''')
        self.lock = threading.RLock()

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def seal(self, data):
        namespace, task_id, parts, schema, output_type, input_hashes = _validate_dataset(data)
        policy = check_policy(data.get('qualification_policy', DEFAULT_POLICY))
        evaluation_id = uuid.uuid4().hex
        public = {
            'protocol':'sis-sealed-eval-v1', 'evaluation_id':evaluation_id,
            'qualification_policy':policy,
            'task_id':task_id, 'namespace':namespace,
            'train':parts['train'], 'validation':parts['validation'],
            'train_digest':digest(parts['train']), 'validation_digest':digest(parts['validation']),
            'schema':schema,'output_type':output_type,
            'test_count':len(parts['test']), 'shifted_test_count':len(parts['shifted_test']),
            'test_commitment':_mac(self.key, parts['test']),
            'shifted_test_commitment':_mac(self.key, parts['shifted_test']),
            'sealed_utc':datetime.now(timezone.utc).isoformat(),
            'evaluation_label':'custodian-sealed; independence not established by software',
        }
        public = _signed(self.key, public, 'seal_mac')
        secret = {'test':parts['test'], 'shifted_test':parts['shifted_test']}
        with self.lock:
            self.conn.execute('BEGIN IMMEDIATE')
            try:
                size = self.conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]
                if size >= MAX_VAULT_TASKS:
                    raise RuleRejected("vault task capacity exceeded")
                # Stops a known sample from silently being recycled across tasks
                # in the *same* vault. Not a global duplication guarantee.
                if any(self.conn.execute('SELECT 1 FROM input_commitments WHERE input_digest=?', (x,)).fetchone()
                       for x in input_hashes):
                    raise RuleRejected("an evaluation input was already sealed in this vault")
                self.conn.execute('INSERT INTO tasks(evaluation_id,public_json,secret_json) VALUES (?,?,?)',
                                  (evaluation_id,canonical(public),canonical(secret)))
                self.conn.executemany('INSERT INTO input_commitments VALUES (?,?)',
                                      [(d,evaluation_id) for d in sorted(input_hashes)])
                self.conn.execute('COMMIT')
            except BaseException:
                self.conn.execute('ROLLBACK')
                raise
        return public

    def _get_record(self, evaluation_id):
        if not isinstance(evaluation_id, str) or len(evaluation_id) != 32:
            raise InvalidInput("invalid evaluation_id")
        row = self.conn.execute('SELECT public_json,secret_json,used,receipt_json FROM tasks WHERE evaluation_id=?',
                                (evaluation_id,)).fetchone()
        if row is None:
            raise InvalidInput("evaluation task does not exist in this vault")
        return json.loads(row[0]), json.loads(row[1]), row[2], row[3]

    def _check_public(self, public, stored):
        _check_signature(self.key, public, 'seal_mac')
        if canonical(public) != canonical(stored):
            raise RuleRejected("public study differs from evaluator-sealed study")

    @staticmethod
    def make_submission(public, *, max_candidates=12000, use_z3=False):
        """Candidate-side helper. Never reads private test labels or vault."""
        from .induction import induce
        if not isinstance(public, dict) or public.get('protocol') != 'sis-sealed-eval-v1':
            raise InvalidInput("invalid public task")
        value = induce(public['train'],public['validation'],namespace=public['namespace'],
                       max_candidates=max_candidates,use_z3=use_z3)
        if value['status'] != 'locally_validated':
            return {'status':'no_qualified_candidate','induction':value}
        return {'status':'candidate','submission':{
            'evaluation_id':public['evaluation_id'],
            'public_digest':digest(public), 'rule':value['rule'],
        },'induction':value}

    def _validate_submission(self, public, submission):
        if not isinstance(submission, dict) or set(submission) != {'evaluation_id','public_digest','rule'}:
            raise InvalidInput("submission must have evaluation_id, public_digest and rule")
        if submission['evaluation_id'] != public['evaluation_id'] or submission['public_digest'] != digest(public):
            raise RuleRejected("candidate is not bound to sealed public task")
        rule = validate_ast(submission['rule'])
        for section in ('train','validation'):
            for example in public[section]:
                try:
                    output = evaluate(rule,example['inputs'])
                except (InvalidInput, TypeError, KeyError, ValueError, OverflowError, IndexError) as exc:
                    raise RuleRejected("candidate did not fit public train/validation") from exc
                if type(output) is not type(example['output']) or output != example['output']:
                    raise RuleRejected("candidate did not fit public train/validation")
        return rule

    def score(self, public, submission):
        """Consumes one admissible candidate atomically and reveals aggregates only."""
        if not isinstance(public, dict):
            raise InvalidInput("public task must be a JSON object")
        with self.lock:
            self.conn.execute('BEGIN IMMEDIATE')
            try:
                stored, secret, used, receipt_json = self._get_record(public.get('evaluation_id'))
                self._check_public(public, stored)
                if used:
                    raise RuleRejected("one-use holdout already consumed; never retune against this test")
                rule = self._validate_submission(public, submission)
                if _mac(self.key, secret['test']) != stored['test_commitment'] or _mac(self.key, secret['shifted_test']) != stored['shifted_test_commitment']:
                    raise RuleRejected("sealed test data do not match committed digests")
                train_outputs = [canonical(ex['output']) for ex in stored['train']]
                counts = Counter(train_outputs)
                majority_key = sorted(counts,key=lambda x: (-counts[x], x))[0]
                results = {group: _metrics(rule, secret[group], majority_key)
                           for group in ('test','shifted_test') if secret[group]}
                body = {
                    'protocol':'sis-evaluation-receipt-v1', 'evaluation_id':stored['evaluation_id'],
                    'public_digest':digest(stored), 'rule':rule, 'rule_digest':digest(rule),
                    'metrics':results, 'scored_utc':datetime.now(timezone.utc).isoformat(),
                    'statement':'one-use locally enforced holdout; independence and vault anti-rollback require external custody',
                }
                receipt = _signed(self.key, body, 'receipt_mac')
                self.conn.execute('UPDATE tasks SET used=1,receipt_json=? WHERE evaluation_id=? AND used=0',
                                  (canonical(receipt),stored['evaluation_id']))
                if self.conn.execute('SELECT changes()').fetchone()[0] != 1:
                    raise RuleRejected("one-use evaluation already consumed")
                self.conn.execute('COMMIT')
                return receipt
            except BaseException:
                self.conn.execute('ROLLBACK')
                raise

    def verify(self, public, receipt):
        """Custodian-side recheck of signatures, vault commitments, and scores."""
        with self.lock:
            stored, secret, used, receipt_json = self._get_record(public.get('evaluation_id'))
            self._check_public(public, stored)
            body = _check_signature(self.key,receipt,'receipt_mac')
            if not used or receipt_json is None or canonical(receipt) != receipt_json:
                raise RuleRejected("signed receipt is not the consumed record")
            if body['evaluation_id'] != public['evaluation_id'] or body['public_digest'] != digest(public):
                raise RuleRejected("receipt not bound to this sealed task")
            if digest(body['rule']) != body['rule_digest']:
                raise RuleRejected("receipt rule digest mismatch")
            if _mac(self.key, secret['test']) != stored['test_commitment'] or _mac(self.key, secret['shifted_test']) != stored['shifted_test_commitment']:
                raise RuleRejected("vault private test commitment mismatch")
            rule = self._validate_submission(public,{
                'evaluation_id':body['evaluation_id'],'public_digest':body['public_digest'],'rule':body['rule']})
            outputs = [canonical(ex['output']) for ex in public['train']]
            counts = Counter(outputs)
            majority = sorted(counts,key=lambda x:(-counts[x],x))[0]
            recomputed = {group: _metrics(rule, secret[group], majority)
                          for group in ('test','shifted_test') if secret[group]}
            if canonical(body['metrics']) != canonical(recomputed):
                raise RuleRejected("receipt aggregate scores differ from sealed test replay")
            return {'valid':True,'evaluation_id':public['evaluation_id'],
                    'rule_digest':body['rule_digest'], 'receipt_digest':digest(receipt),
                    'scope':'custodian-side replay of locally held labels, not proof of independent provenance'}

    def recover_receipt(self, public):
        """Return the committed receipt after an interrupted output-file write."""
        with self.lock:
            stored, secret, used, receipt_json = self._get_record(public.get('evaluation_id'))
            self._check_public(public, stored)
            if not used or receipt_json is None:
                raise RuleRejected('evaluation has no committed receipt to recover')
            receipt = json.loads(receipt_json)
            self.verify(public, receipt)
            return receipt

    def qualify(self, public, receipt):
        """Custodian-signed, policy-bound post-score gate. No rule promotion."""
        self.verify(public, receipt)  # independent recomputation from vault labels
        from .qualification import assess
        verdict = assess(public, receipt)
        body = {'protocol':'sis-qualification-v1', 'evaluation_id':public['evaluation_id'],
                'public_digest':digest(public), 'receipt_digest':digest(receipt),
                'assessment':verdict,
                'warning':'a policy pass is not proof of independent provenance or model intelligence'}
        return _signed(self.key, body, 'qualification_mac')

    def verify_qualification(self, public, receipt, qualification):
        """Revalidate custodian signature, source receipt and complete gate result."""
        self.verify(public, receipt)
        body = _check_signature(self.key, qualification, 'qualification_mac')
        if body.get('protocol') != 'sis-qualification-v1' or body.get('evaluation_id') != public.get('evaluation_id'):
            raise RuleRejected('qualification protocol or evaluation id mismatch')
        if body.get('public_digest') != digest(public) or body.get('receipt_digest') != digest(receipt):
            raise RuleRejected('qualification not bound to this public task and receipt')
        if body.get('assessment') != assess(public,receipt):
            raise RuleRejected('qualification assessment differs from verified policy')
        return {'valid':True,'evaluation_id':public['evaluation_id'],
                'status':body['assessment']['status'], 'qualification_digest':digest(qualification),
                'scope':'custodian-side policy and score replay; independent provenance not asserted'}
