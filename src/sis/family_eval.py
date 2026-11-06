"""Evaluator-custodied, family-grouped LLM qualification for SIS v2.0.

This module provides protocol precommitment, HMAC-authenticated evidence,
one-use experiment admission, evaluator-local labels, model error invalidation,
family-stratified reporting, Holm-adjusted McNemar tests and a conservative
qualification gate. No adapter deployment or registry mutation is provided.

Limits: family definitions and model identity are assertions from the operator;
HMAC proves only possession of a shared key, not independent evaluator identity.
We cannot certify no pretraining contamination or independent task novelty.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import sqlite3
from pathlib import Path
from .errors import InvalidInput, RuleRejected
from .validation import canonical, check_inputs, check_examples, check_task_description, digest, input_schema, namespace_name
from .skill_bundle import validate_bundle, predict
from .neural_eval import _call
from .paired_eval import exact_mcnemar_pvalue
from .vault_storage import private_sqlite_path

DATASET_FORMAT = 'sis.family_dataset.v2'
PROTOCOL_FORMAT = 'sis.family_protocol.v2'
REPORT_FORMAT = 'sis.family_report.v1'
ARMS = ('baseline', 'symbolic', 'adapted', 'placebo')


def _s(value, label, *, maxlen=128):
    if type(value) is not str or not 1 <= len(value) <= maxlen or any(ord(ch)<32 for ch in value):
        raise InvalidInput(f'invalid {label}')
    return value


def _families(families):
    if type(families) is not list or not 8 <= len(families) <= 32:
        raise InvalidInput('test requires 8-32 independently designated task families')
    ids=set(); keys=set(); ordered=[]; schema=None
    for group in families:
        if type(group) is not dict or set(group) != {'family_id','cases'}:
            raise InvalidInput('family requires only family_id and cases')
        family=_s(group['family_id'],'family_id',maxlen=80)
        if family in ids:
            raise InvalidInput('duplicate family_id')
        ids.add(family)
        cases=check_examples(group['cases'],minimum=8)
        if len(cases)>128:
            raise InvalidInput('maximum 128 cases per family')
        for row in cases:
            fingerprint=canonical(row['inputs'])
            if fingerprint in keys:
                raise InvalidInput('evaluation inputs must be unique across all families')
            keys.add(fingerprint)
            typ=input_schema(row['inputs'])
            if schema is None: schema=typ
            if typ != schema:
                raise InvalidInput('all cases must share frozen skill input schema')
        ordered.append({'family_id':family,'cases':cases})
    if sum(len(v['cases']) for v in ordered)>512:
        raise InvalidInput('maximum 512 test cases total')
    return ordered,ids,keys,schema


def validate_dataset(data,bundle):
    if type(data) is not dict or set(data) != {'format','experiment_id','namespace','task_description','test',
        'training_families','validation_families','excluded_inputs','max_tokens','include_placebo'}:
        raise InvalidInput('invalid family evaluation dataset format')
    if data['format'] != DATASET_FORMAT:
        raise InvalidInput('unsupported family dataset version')
    _s(data['experiment_id'],'experiment_id')
    namespace=namespace_name(data['namespace'])
    check_task_description(data['task_description'])
    if namespace != bundle['namespace']:
        raise InvalidInput('namespace does not match frozen skill')
    index=validate_bundle(bundle)
    families, test_ids, test_keys, schema = _families(data['test'])
    if schema != index[bundle['root_skill_id']]['schema']:
        raise InvalidInput('test schema differs from frozen skill')
    reserved=set()
    for field in ('training_families','validation_families'):
        values=data[field]
        if type(values) is not list or not 1 <= len(values) <= 128:
            raise InvalidInput(f'{field} must contain 1-128 family IDs')
        listed=[_s(x,field,maxlen=80) for x in values]
        if len(set(listed)) != len(listed) or set(listed)&(test_ids|reserved):
            raise InvalidInput('family leakage or duplicate across train/validation/test splits')
        reserved.update(listed)
    exclusions=data['excluded_inputs']
    if type(exclusions) is not list or not 1 <= len(exclusions) <= 4096:
        raise InvalidInput('excluded_inputs must contain declared train and validation input records')
    excluded=set()
    for row in exclusions:
        checked=check_inputs(row)
        if input_schema(checked) != schema:
            raise InvalidInput('excluded input schema mismatch')
        v=canonical(checked)
        if v in excluded or v in test_keys:
            raise InvalidInput('declared training/validation and test inputs overlap or duplicate')
        excluded.add(v)
    if type(data['max_tokens']) is not int or not 16<=data['max_tokens']<=512:
        raise InvalidInput('max_tokens outside permitted bounds')
    if type(data['include_placebo']) is not bool:
        raise InvalidInput('include_placebo must be bool')
    return families,index


def _mac(key,obj):
    if type(key) is not bytes or len(key)<32:
        raise InvalidInput('evaluator secret must be 32+ bytes')
    return hmac.new(key,canonical(obj).encode('utf8'),hashlib.sha256).hexdigest()


def precommit(private_dataset, bundle, *, key, baseline_id, adapted_id, policy=None):
    """Return public, signed metadata; retains no ground-truth labels in response."""
    families,_=validate_dataset(private_dataset,bundle)
    baseline_id=_s(baseline_id,'baseline model identifier',maxlen=256)
    adapted_id=_s(adapted_id,'adapted model identifier',maxlen=256)
    if baseline_id==adapted_id:
        raise InvalidInput('base and adapted model IDs must differ')
    params=policy or {'alpha':0.05,'minimum_gain':0.05,'require_placebo_win':True}
    if type(params) is not dict or set(params)!={'alpha','minimum_gain','require_placebo_win'}:
        raise InvalidInput('qualification policy needs alpha/minimum_gain/require_placebo_win')
    if (type(params['alpha']) not in (int,float) or not math.isfinite(params['alpha'])
            or not 0 < params['alpha'] <= 0.1):
        raise InvalidInput('alpha out of bounds')
    if (type(params['minimum_gain']) not in (int,float) or not math.isfinite(params['minimum_gain'])
            or not 0 <= params['minimum_gain'] <= 0.5):
        raise InvalidInput('minimum_gain out of bounds')
    if type(params['require_placebo_win']) is not bool:
        raise InvalidInput('require_placebo_win must be bool')
    if params['require_placebo_win'] and not private_dataset['include_placebo']:
        raise InvalidInput('placebo required by qualification policy')
    protocol={
        'format':PROTOCOL_FORMAT,
        'experiment_id':private_dataset['experiment_id'],
        'namespace':private_dataset['namespace'],
        'task_description':private_dataset['task_description'],
        'bundle_digest':bundle['bundle_digest'],
        'private_dataset_commitment':digest(private_dataset),
        'excluded_inputs_commitment':digest(private_dataset['excluded_inputs']),
        'training_families':sorted(private_dataset['training_families']),
        'validation_families':sorted(private_dataset['validation_families']),
        'test_family_counts':{g['family_id']:len(g['cases']) for g in families},
        'model_ids':{'baseline':baseline_id,'adapted':adapted_id},
        'policy':params,
        'max_tokens':private_dataset['max_tokens'],
        'include_placebo':private_dataset['include_placebo']
    }
    return {**protocol,'hmac_sha256':_mac(key,protocol)}


def validate_protocol(protocol,private_dataset,bundle,*,key):
    if type(protocol) is not dict or set(protocol) != {
        'format','experiment_id','namespace','task_description','bundle_digest','private_dataset_commitment',
        'excluded_inputs_commitment','training_families','validation_families',
        'test_family_counts','model_ids','policy','max_tokens','include_placebo','hmac_sha256'}:
        raise InvalidInput('invalid public protocol fields')
    sig=protocol['hmac_sha256']; body={k:v for k,v in protocol.items() if k!='hmac_sha256'}
    if type(sig) is not str or not hmac.compare_digest(_mac(key,body),sig):
        raise RuleRejected('invalid evaluator protocol signature')
    actual=precommit(private_dataset,bundle,key=key,
                     baseline_id=protocol['model_ids']['baseline'],
                     adapted_id=protocol['model_ids']['adapted'],policy=protocol['policy'])
    if actual!=protocol:
        raise RuleRejected('private dataset or frozen model configuration differs from precommitment')
    return True


def holm_adjust(pvalues):
    """Holm step-down family-wise error-rate correction."""
    if type(pvalues) is not dict or not pvalues or any(type(p) not in (int,float)
        or not math.isfinite(p) or not 0<=p<=1 for p in pvalues.values()):
        raise InvalidInput('invalid p values')
    sorted_pairs=sorted(pvalues.items(),key=lambda x:(x[1],x[0]))
    largest=0.0; result={}
    for rank,(key,p) in enumerate(sorted_pairs):
        largest=max(largest,min(1.0,p*(len(pvalues)-rank)))
        result[key]=largest
    return result


def _summary(records,names):
    flat=[row for group in records for row in group['cases']]
    n=len(flat)
    report={}
    for arm in names:
        correct=sum(row['arms'][arm]['correct'] for row in flat)
        answered=sum(row['arms'][arm]['status']=='answered' for row in flat)
        errors=sum(row['arms'][arm]['status']=='model_error' for row in flat)
        token_values=[row['arms'][arm]['usage'] for row in flat]
        total_tokens=(sum(value['total_tokens'] for value in token_values)
                     if all(isinstance(value,dict) and 'total_tokens' in value for value in token_values) else None)
        report[arm]={
            'correct':correct,'answered':answered,'model_errors':errors,
            'accuracy':correct/n,'coverage':answered/n,
            'total_latency_ms':round(sum(row['arms'][arm]['elapsed_ms'] for row in flat),3),
            'provider_total_tokens':total_tokens,
            'family_macro_accuracy':sum(sum(r['arms'][arm]['correct'] for r in g['cases'])/
                                         len(g['cases']) for g in records)/len(records)
        }
    comparisons={}
    for arm in names:
        if arm=='baseline':continue
        b=sum(row['arms']['baseline']['correct'] and not row['arms'][arm]['correct'] for row in flat)
        a=sum(row['arms'][arm]['correct'] and not row['arms']['baseline']['correct'] for row in flat)
        positive=sum(g['cases'] and (sum(r['arms'][arm]['correct'] for r in g['cases']) >
                       sum(r['arms']['baseline']['correct'] for r in g['cases'])) for g in records)
        negative=sum(g['cases'] and (sum(r['arms'][arm]['correct'] for r in g['cases']) <
                       sum(r['arms']['baseline']['correct'] for r in g['cases'])) for g in records)
        comparisons[arm]={
            'family_positive':positive,'family_negative':negative,
            'family_sign_p':exact_mcnemar_pvalue(negative,positive),
            'accuracy_delta':report[arm]['accuracy']-report['baseline']['accuracy'],
            'family_macro_delta':report[arm]['family_macro_accuracy']-report['baseline']['family_macro_accuracy'],
            'base_only_correct':b,'other_only_correct':a,'mcnemar_p':exact_mcnemar_pvalue(b,a)
        }
    adjusted=holm_adjust({k:v['mcnemar_p'] for k,v in comparisons.items()})
    family_adjusted=holm_adjust({k:v['family_sign_p'] for k,v in comparisons.items()})
    for arm in comparisons:
        comparisons[arm]['holm_adjusted_p']=adjusted[arm]
        comparisons[arm]['family_holm_adjusted_p']=family_adjusted[arm]
    family_detail={}
    for group in records:
        family_detail[group['family_id']]={
            'case_count':len(group['cases']),
            'accuracy':{name:sum(row['arms'][name]['correct'] for row in group['cases'])/
                             len(group['cases']) for name in names}}
    return report,comparisons,family_detail


def _qualification(arms,comparisons,by_family,policy,n,placebo):
    """Conservative gate; multiple tests adjusted, no positive claims on provider errors."""
    failed=[]
    if n < 64 or len(by_family) < 8:failed.append('minimum 64 test items from 8 distinct task families')
    if any(arm['model_errors'] for arm in arms.values()):failed.append('provider errors invalidate evidence')
    for target in ('symbolic','adapted'):
        c=comparisons[target]
        if c['accuracy_delta'] < policy['minimum_gain']:
            failed.append(f'{target}: insufficient gain over baseline')
        if c['family_holm_adjusted_p'] > policy['alpha']:
            failed.append(f'{target}: fails Holm-corrected family-level sign-test threshold')
        # Resist aggregate-only wins masking regressions in individual families.
        if any(values['accuracy'][target] < values['accuracy']['baseline'] for values in by_family.values()):
            failed.append(f'{target}: regression in at least one task family')
    if policy['require_placebo_win']:
        if not placebo:failed.append('placebo missing')
        elif arms['symbolic']['accuracy'] <= arms['placebo']['accuracy']:
            failed.append('symbolic assistance does not beat placebo')
    return {'status':'policy_pass' if not failed else 'policy_fail',
            'failures':failed,'limitation':'Internal policy pass does not certify unseen data or real-world transfer'}


def evaluate(private_dataset,protocol,bundle,baseline_client,adapted_client,*,key):
    """Evaluate frozen protocol; never send private answer labels to a model."""
    validate_protocol(protocol,private_dataset,bundle,key=key)
    if baseline_client is adapted_client:
        raise InvalidInput('separate baseline and adapted client instances required')
    families,index=validate_dataset(private_dataset,bundle)
    names=list(ARMS if private_dataset['include_placebo'] else ARMS[:3])
    records=[]; total=0
    for group in families:
        cases=[]
        for row in group['cases']:
            inp,gold=row['inputs'],row['output']
            try:
                hint=predict(bundle,inp,validated_index=index)
                available=type(hint) is type(gold)
            except (InvalidInput,ValueError,TypeError,KeyError,IndexError):
                hint=None;available=False
            base={'namespace':private_dataset['namespace'],'task_description':private_dataset['task_description'],'inputs':inp}
            users={'baseline':base,'adapted':base,
                   'symbolic':{**base,'sis_prediction':{
                        'status':'available' if available else 'unavailable',
                        'output':hint if available else None}}}
            if 'placebo' in names:
                users['placebo']={**base,'sis_prediction':{'status':'unavailable','output':None}}
            order=names[total%len(names):]+names[:total%len(names)]
            outcomes={}
            for name in order:
                client=adapted_client if name=='adapted' else baseline_client
                outcomes[name]=_call(client,users[name],gold,private_dataset['max_tokens'])
            cases.append({'arms':outcomes});total+=1
        records.append({'family_id':group['family_id'],'cases':cases})
    summaries,comparisons,by_family=_summary(records,names)
    gate=_qualification(summaries,comparisons,by_family,protocol['policy'],total,'placebo' in names)
    report={
        'format':REPORT_FORMAT,'experiment_id':protocol['experiment_id'],
        'protocol_commitment':digest(protocol),'status':'invalid_model_errors' if any(
            x['model_errors'] for x in summaries.values()) else 'evaluated',
        'case_count':total,'family_count':len(families),'arms':summaries,
        'comparisons':comparisons,'by_family':by_family,'qualification':gate,
        'gold_labels_sent_to_model':False,
        'limitations':['Family labels and training exclusions are provided by the dataset curator, not independently verified',
          'Input hash disjointness cannot detect semantic contamination or pretraining leakage',
          'Placebo is not tokenizer token-matched to the symbolic hint',
          'Item-level McNemar assumes independence; family-level sign test treats designated families as independent, which cannot be independently verified here',
          'Provider metadata, model identity, temperature and endpoint state cannot be attested by this library']
    }
    # Authenticates report bytes against the evaluator key; not proof of third-party evaluation.
    return {**report,'hmac_sha256':_mac(key,report)}


def verify_report(report,protocol,*,key):
    """Authenticate aggregate evaluator report and bind it to the public protocol.

    This verifies message authenticity and protocol matching, not the truth of
    independently acquired labels. A custodian may additionally inspect its
    vault and rerun a new separately precommitted evaluation as appropriate.
    """
    expected={'format','experiment_id','protocol_commitment','status',
              'case_count','family_count','arms','comparisons','by_family',
              'qualification','gold_labels_sent_to_model','limitations','hmac_sha256'}
    if type(report) is not dict or set(report)!=expected or report['format']!=REPORT_FORMAT:
        raise InvalidInput('unexpected evaluator report schema')
    if type(report['hmac_sha256']) is not str:
        raise RuleRejected('missing report signature')
    unsigned={k:v for k,v in report.items() if k!='hmac_sha256'}
    if not hmac.compare_digest(_mac(key,unsigned),report['hmac_sha256']):
        raise RuleRejected('evaluator report HMAC mismatch')
    if report['protocol_commitment'] != digest(protocol) or report['experiment_id']!=protocol['experiment_id']:
        raise RuleRejected('report is not bound to the specified signed protocol')
    sig=protocol.get('hmac_sha256')
    if type(sig) is not str or not hmac.compare_digest(_mac(key,{k:v for k,v in protocol.items() if k!='hmac_sha256'}),sig):
        raise RuleRejected('referenced protocol signature invalid')
    if report['family_count'] != len(protocol['test_family_counts']) or report['case_count']!=sum(protocol['test_family_counts'].values()):
        raise RuleRejected('evaluation family/count mismatch')
    return {'valid':True,'experiment_id':report['experiment_id'],
            'report_commitment':digest(report),'protocol_commitment':digest(protocol),
            'qualification':report['qualification']['status']}


class FamilyExperimentVault:
    """SQLite single-use admission. Separate custodian DB required for genuine independence.

    Reserving occurs BEFORE any external network calls. An interrupted run is
    intentionally spent; the evaluator must issue a new experiment ID to retry.
    """
    def __init__(self,path):
        self.path=private_sqlite_path(path,'family evaluation vault')
        self.con=sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        self.con.execute('PRAGMA busy_timeout=30000')
        self.con.execute('CREATE TABLE IF NOT EXISTS uses (experiment_id TEXT PRIMARY KEY, protocol_hash TEXT NOT NULL, status TEXT NOT NULL, report_hash TEXT)')

    def close(self): self.con.close()
    def __enter__(self): return self
    def __exit__(self,*args): self.close()

    def run(self,private_dataset,protocol,bundle,baseline_client,adapted_client,*,key):
        validate_protocol(protocol,private_dataset,bundle,key=key)
        self.con.execute('BEGIN IMMEDIATE')
        try:
            self.con.execute('INSERT INTO uses (experiment_id,protocol_hash,status) VALUES (?,?,?)',
                             (protocol['experiment_id'],digest(protocol),'reserved'))
            self.con.execute('COMMIT')
        except (sqlite3.IntegrityError,sqlite3.DatabaseError) as exc:
            self.con.execute('ROLLBACK')
            raise RuleRejected('experiment ID already used or vault admission failed') from exc
        result=evaluate(private_dataset,protocol,bundle,baseline_client,adapted_client,key=key)
        self.con.execute('UPDATE uses SET status=?,report_hash=? WHERE experiment_id=?',
                         ('complete',digest(result),protocol['experiment_id']))
        return result

    def get_status(self,experiment_id):
        row=self.con.execute('SELECT status,protocol_hash,report_hash FROM uses WHERE experiment_id=?',
                             (_s(experiment_id,'experiment ID'),)).fetchone()
        return None if row is None else {'status':row[0],'protocol_hash':row[1],'report_hash':row[2]}
