"""Frozen, read-only procedural skill closures for controlled offline evaluation.

A bundle pins exact ASTs and dependencies; its hash is a commitment, NOT an
independent attestation. Never permit a model to present a new bundle as a
previously qualified one without separately checking an evaluator receipt.
"""
import re
from .errors import InvalidInput, RuleRejected
from .validation import digest, namespace_name, check_inputs, input_schema
from .skill_program import validate_program, execute

HEXDIGEST = re.compile(r'^[0-9a-f]{64}$')
FORMAT = 'sis.skill_bundle.v1'


def _calls(node):
    if isinstance(node, dict):
        if node.get('op') == 'call':
            yield node.get('skill_id')
        for child in node.values():
            yield from _calls(child)
    elif isinstance(node, list):
        for child in node:
            yield from _calls(child)


def _safe_record(record, namespace):
    if not isinstance(record, dict):
        raise InvalidInput('invalid frozen skill record')
    required={'id','namespace','schema','program','train_digest','validation_digest','train_count','validation_count'}
    if set(record) != required or record['namespace'] != namespace:
        raise InvalidInput('frozen skill fields or namespace do not match')
    if any(not isinstance(record[k],str) or not HEXDIGEST.fullmatch(record[k]) for k in ('id','train_digest','validation_digest')):
        raise InvalidInput('invalid skill or evidence hash')
    if any(type(record[k]) is not int or record[k] < minimum for k,minimum in (('train_count',3),('validation_count',2))):
        raise InvalidInput('invalid skill evidence counts')
    if not isinstance(record['schema'],dict) or not 1 <= len(record['schema']) <= 16:
        raise InvalidInput('invalid frozen skill schema')
    # validate_program rejects unsupported ops and out-of-schema references.
    validate_program(record['program'],schema=record['schema'])
    if record['id'] != digest({'namespace':namespace,'schema':record['schema'],'program':record['program']}):
        raise InvalidInput('skill identity does not bind AST')


def validate_bundle(bundle):
    if not isinstance(bundle,dict) or set(bundle) != {'format','namespace','root_skill_id','audit_head','skills','bundle_digest'}:
        raise InvalidInput('invalid frozen skill bundle')
    if bundle['format'] != FORMAT:
        raise InvalidInput('unsupported skill bundle version')
    namespace=namespace_name(bundle['namespace'])
    if not all(isinstance(bundle[k],str) and HEXDIGEST.fullmatch(bundle[k]) for k in ('root_skill_id','audit_head','bundle_digest')):
        raise InvalidInput('invalid bundle commitment')
    if digest({k:v for k,v in bundle.items() if k!='bundle_digest'}) != bundle['bundle_digest']:
        raise InvalidInput('frozen bundle contents were modified')
    rows=bundle['skills']
    if not isinstance(rows,list) or not 1<=len(rows)<=24:
        raise InvalidInput('frozen skill closure must contain 1-24 skills')
    index={}
    for rec in rows:
        _safe_record(rec,namespace)
        if rec['id'] in index:
            raise InvalidInput('duplicate frozen skill')
        index[rec['id']]=rec
    if bundle['root_skill_id'] not in index:
        raise InvalidInput('frozen root missing')
    visited=set()
    def walk(sid,stack):
        if sid in stack or len(stack)>=4:
            raise InvalidInput('cyclic or deep frozen skill dependency')
        rec=index.get(sid)
        if rec is None:
            raise InvalidInput('incomplete frozen dependency closure')
        if sid in visited: return
        for child in set(_calls(rec['program'])):
            if child not in index:
                raise InvalidInput('missing frozen child skill')
            walk(child,stack+(sid,))
        visited.add(sid)
    walk(bundle['root_skill_id'],())
    if visited != set(index):
        raise InvalidInput('bundle contains unused skill records')
    return index


def freeze(catalog, namespace, skill_id):
    """Capture an integrity-checked snapshot; calls never depend on future DB state."""
    namespace=namespace_name(namespace)
    if not isinstance(skill_id,str) or not HEXDIGEST.fullmatch(skill_id):
        raise InvalidInput('skill_id must be a sha256 identifier')
    with catalog.lock:
        audit=catalog.verify()
        if not audit['valid']:
            raise RuleRejected('cannot freeze a compromised skill catalog')
        rows={}
        def gather(sid,stack):
            if sid in stack or len(stack)>=4:
                raise InvalidInput('cyclic or too deep dependency')
            if sid in rows: return
            rec=catalog._resolve(sid)
            if rec is None or rec['namespace']!=namespace:
                raise InvalidInput('only active same-namespace skill dependencies can be frozen')
            keep={k:rec[k] for k in ('id','namespace','schema','program','train_digest','validation_digest','train_count','validation_count')}
            _safe_record(keep,namespace)
            rows[sid]=keep
            for child in set(_calls(rec['program'])):
                gather(child,stack+(sid,))
        gather(skill_id,())
        body={'format':FORMAT,'namespace':namespace,'root_skill_id':skill_id,
              'audit_head':audit['head'],'skills':[rows[k] for k in sorted(rows)]}
        bundle={**body,'bundle_digest':digest(body)}
        validate_bundle(bundle)
        return bundle


def predict(bundle, inputs, *, validated_index=None):
    records=validated_index if validated_index is not None else validate_bundle(bundle)
    clean=check_inputs(inputs)
    root=records[bundle['root_skill_id']]
    if input_schema(clean) != root['schema']:
        raise InvalidInput('frozen skill input schema mismatch')
    def resolver(sid):
        rec=records.get(sid)
        return {**rec,'status':'active'} if rec is not None else None
    return execute(root['program'],clean,resolver,namespace=bundle['namespace'],_ids=(root['id'],))
