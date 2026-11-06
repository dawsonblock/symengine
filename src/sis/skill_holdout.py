"""Evaluator-owned one-use sealed holdouts for procedural skill bundles.

The trust boundary is the evaluator's DB, HMAC key, and dataset custody. Local
unit tests prove software behavior but NOT custody independence or distribution.
"""
import hashlib
import hmac
import json
import math
import secrets
import sqlite3
from datetime import datetime, timezone
from .errors import InvalidInput, RuleRejected
from .validation import canonical, digest, check_examples, check_task_description, input_schema, namespace_name
from .qualification import wilson_lower
from .skill_bundle import validate_bundle, predict
from .vault_storage import private_sqlite_path

FMT='sis.skill_holdout.v1'
POLICY_FIELDS={'min_per_split','min_coverage','min_overall_accuracy','min_wilson_lower'}


def check_policy(policy):
    if not isinstance(policy,dict) or set(policy)!=POLICY_FIELDS:
        raise InvalidInput('skill holdout policy must supply four precommitted fields')
    n=policy['min_per_split']
    if type(n) is not int or not 10<=n<=256:
        raise InvalidInput('min_per_split must be between 10 and 256')
    values={}
    for key in POLICY_FIELDS-{'min_per_split'}:
        val=policy[key]
        if type(val) not in (int,float) or not math.isfinite(val) or not 0<=val<=1:
            raise InvalidInput('policy thresholds must be finite numbers between 0 and 1')
        values[key]=float(val)
    return {'min_per_split':n,**values}


def _check_dataset(dataset, bundle):
    legacy_fields={'study_id','holdout','shifted_holdout','excluded_inputs','policy'}
    if not isinstance(dataset,dict) or set(dataset) not in (legacy_fields,legacy_fields|{'task_description'}):
        raise InvalidInput('private skill dataset requires study_id, both splits, exclusions and policy')
    study_id=namespace_name(dataset['study_id'])
    description=check_task_description(dataset.get(
        'task_description','Apply the transformation demonstrated by the frozen skill to the input.'))
    policy=check_policy(dataset['policy'])
    train=dataset['excluded_inputs']
    if not isinstance(train,list) or len(train)>256:
        raise InvalidInput('excluded_inputs must be a list of at most 256 input records')
    from .validation import check_inputs
    train=[check_inputs(x) for x in train]
    if len({canonical(x) for x in train})!=len(train):
        raise InvalidInput('duplicate exclusion inputs')
    holdout=check_examples(dataset['holdout'],minimum=policy['min_per_split'])
    shifted=check_examples(dataset['shifted_holdout'],minimum=policy['min_per_split'])
    root=validate_bundle(bundle)[bundle['root_skill_id']]
    all_cases=holdout+shifted
    schema=root['schema']
    if any(input_schema(x['inputs'])!=schema for x in all_cases):
        raise InvalidInput('holdout schema differs from frozen skill')
    if any(input_schema(x)!=schema for x in train):
        raise InvalidInput('exclusion input schema differs from frozen skill')
    keys=[canonical(x['inputs']) for x in all_cases]
    if len(set(keys))!=len(keys) or set(keys)&{canonical(x) for x in train}:
        raise InvalidInput('holdout, shifted holdout and exclusions must be disjoint')
    return {'study_id':study_id,'task_description':description,'holdout':holdout,'shifted_holdout':shifted,'excluded_inputs':train,'policy':policy}


def _stamp():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _metrics(rows,bundle,index):
    answered=correct=0
    for row in rows:
        try:
            result=predict(bundle,row['inputs'],validated_index=index)
        except (InvalidInput,TypeError,KeyError,ValueError,IndexError):
            continue
        answered+=1
        if type(result) is type(row['output']) and result==row['output']:
            correct+=1
    total=len(rows)
    return {'count':total,'answered':answered,'correct':correct,
            'coverage':answered/total,'overall_accuracy':correct/total,
            'accuracy_on_answers':correct/answered if answered else None,
            'wilson_95_lower':wilson_lower(correct,total)}


def _assessment(metrics,policy):
    reasons=[]
    for name in ('holdout','shifted_holdout'):
        m=metrics[name]
        if m['count'] < policy['min_per_split']: reasons.append(name+':too_small')
        if m['coverage'] < policy['min_coverage']: reasons.append(name+':coverage')
        if m['overall_accuracy'] < policy['min_overall_accuracy']: reasons.append(name+':accuracy')
        if m['wilson_95_lower'] < policy['min_wilson_lower']: reasons.append(name+':uncertainty')
    return {'status':'policy_pass' if not reasons else 'policy_fail','reasons':reasons,
            'scope':'policy-relative evaluator scoring, not proof of external dataset independence'}


class SkillHoldoutVault:
    def __init__(self,path,*,key):
        if not isinstance(key,bytes) or len(key)<32:
            raise InvalidInput('evaluator HMAC key must contain at least 32 bytes')
        self.key=key
        self.path=private_sqlite_path(path,'skill holdout vault')
        self.conn=sqlite3.connect(str(self.path),timeout=30,isolation_level=None)
        self.conn.execute('PRAGMA busy_timeout=30000')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS sis_skill_holdout (
            id TEXT PRIMARY KEY, public TEXT NOT NULL, private TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0, receipt TEXT)''')
    def close(self): self.conn.close()
    def __enter__(self): return self
    def __exit__(self,*args): self.close()
    def _mac(self,value):
        return hmac.new(self.key,canonical(value).encode('utf8'),hashlib.sha256).hexdigest()
    def _signed(self,body):
        return {**body,'hmac_sha256':self._mac(body)}
    def _verify_signature(self,doc):
        if not isinstance(doc,dict) or 'hmac_sha256' not in doc:
            raise RuleRejected('missing evaluator signature')
        signature=doc['hmac_sha256']
        if not isinstance(signature,str) or not hmac.compare_digest(signature,self._mac({k:v for k,v in doc.items() if k!='hmac_sha256'})):
            raise RuleRejected('invalid evaluator HMAC')
    def seal(self,private_dataset,bundle):
        # Both exact candidate content and evaluation policy are frozen BEFORE a holdout can be scored.
        index=validate_bundle(bundle)
        dataset=_check_dataset(private_dataset,bundle)
        body={'format':FMT,'evaluation_id':digest({'nonce':secrets.token_hex(32),
               'candidate':bundle['bundle_digest'],'study':dataset['study_id']}),
              'study_id':dataset['study_id'],'bundle_digest':bundle['bundle_digest'],
              'root_skill_id':bundle['root_skill_id'],
              'holdout_count':len(dataset['holdout']),'shifted_holdout_count':len(dataset['shifted_holdout']),
              'excluded_count':len(dataset['excluded_inputs']),
              'policy':dataset['policy'],'created_at':_stamp(),
              'private_dataset_sha256':digest(dataset)}
        public=self._signed(body)
        self.conn.execute('INSERT INTO sis_skill_holdout(id,public,private) VALUES (?,?,?)',
                          (body['evaluation_id'],canonical(public),canonical(dataset)))
        return public
    def _get(self,public):
        self._verify_signature(public)
        if public.get('format')!=FMT or not isinstance(public.get('evaluation_id'),str):
            raise RuleRejected('unknown skill holdout manifest')
        row=self.conn.execute('SELECT public,private,used,receipt FROM sis_skill_holdout WHERE id=?',
                              (public['evaluation_id'],)).fetchone()
        if row is None or canonical(public)!=row[0]:
            raise RuleRejected('public manifest does not match private vault')
        dataset=json.loads(row[1])
        if digest(dataset)!=public['private_dataset_sha256']:
            raise RuleRejected('private holdout dataset was modified')
        return dataset,row[2],row[3]
    def _score(self,public,bundle,dataset):
        index=validate_bundle(bundle)
        if bundle['bundle_digest']!=public['bundle_digest'] or bundle['root_skill_id']!=public['root_skill_id']:
            raise RuleRejected('candidate bundle differs from precommitted snapshot')
        metrics={name:_metrics(dataset[name],bundle,index) for name in ('holdout','shifted_holdout')}
        body={'format':FMT+'.receipt','evaluation_id':public['evaluation_id'],
              'bundle_digest':bundle['bundle_digest'],'policy_digest':digest(public['policy']),
              'metrics':metrics,'assessment':_assessment(metrics,public['policy']),
              'scoring':'bounded offline interpreter; no model, tool or network access',
              'evaluated_at':_stamp()}
        return self._signed(body)
    def score(self,public,bundle):
        self.conn.execute('BEGIN IMMEDIATE')
        try:
            dataset,used,_=self._get(public)
            if used:
                raise RuleRejected('this sealed holdout has already been used')
            receipt=self._score(public,bundle,dataset)
            self.conn.execute('UPDATE sis_skill_holdout SET used=1,receipt=? WHERE id=? AND used=0',
                              (canonical(receipt),public['evaluation_id']))
            self.conn.execute('COMMIT')
            return receipt
        except BaseException:
            self.conn.execute('ROLLBACK')
            raise
    def recover_receipt(self,public,bundle):
        """Custodian-only recovery after scoring committed but writing receipt failed."""
        dataset,used,saved=self._get(public)
        if not used or not saved:
            raise RuleRejected('evaluation has no committed receipt to recover')
        receipt=json.loads(saved)
        self.verify(public,bundle,receipt)
        return receipt

    def verify(self,public,bundle,receipt):
        self._verify_signature(receipt)
        dataset,used,saved=self._get(public)
        if not used or saved!=canonical(receipt):
            raise RuleRejected('receipt was not committed by evaluator')
        if receipt.get('format')!=FMT+'.receipt':
            raise RuleRejected('unsupported holdout receipt')
        replay=self._score(public,bundle,dataset)
        # Time of scoring is metadata, not part of deterministic performance replay.
        comparable=lambda v: {k:x for k,x in v.items() if k not in ('evaluated_at','hmac_sha256')}
        if comparable(replay)!=comparable(receipt):
            raise RuleRejected('independent metric replay disagrees with receipt')
        return {'valid':True,'evaluation_id':public['evaluation_id'],
                'assessment':receipt['assessment'],'replayed':True,
                'qualification':'precommitted policy on private evaluator labels; provenance requires external custody'}
