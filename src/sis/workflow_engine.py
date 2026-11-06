"""SIS v2.3: bounded, pure tabular tool workflow capture and replay.

This is NOT arbitrary shell/browser/tool learning. It supports deterministic,
read-only operations on in-memory JSON records. Tool capture hashes provide
consistency checks, NOT provenance authentication. An external evaluator must
provide independently verified outputs before a workflow is admitted.
"""
from copy import deepcopy
from .errors import InvalidInput
from .validation import check_scalar, canonical, digest, NAME, MAX_MAGNITUDE

MAX_ROWS = 128
MAX_FIELDS = 12
MAX_STEPS = 8
FILTERS = {'filter_eq','filter_gt','filter_lt'}
TERMINALS = {'count','sum','min','max','distinct_count'}


def validate_data(data):
    if type(data) is not dict or set(data) != {'rows'} or type(data['rows']) is not list:
        raise InvalidInput('data requires exactly a rows array')
    rows = data['rows']
    if not 1 <= len(rows) <= MAX_ROWS:
        raise InvalidInput('data requires 1-128 rows')
    schema = None
    cleaned = []
    for row in rows:
        if type(row) is not dict or not 1 <= len(row) <= MAX_FIELDS:
            raise InvalidInput('every row needs 1-12 typed fields')
        clean = {}
        for key,value in row.items():
            if type(key) is not str or not NAME.fullmatch(key):
                raise InvalidInput('invalid row field name')
            clean[key] = check_scalar(value)
        signature = {k: type(v).__name__ for k,v in sorted(clean.items())}
        if schema is not None and signature != schema:
            raise InvalidInput('row field names and types must agree')
        schema = signature
        cleaned.append(clean)
    return {'rows':cleaned}, schema


def validate_step(step, schema, terminal=False):
    if type(step) is not dict or type(step.get('op')) is not str:
        raise InvalidInput('workflow operation must be a typed object')
    op = step['op']
    if op in FILTERS:
        if terminal or set(step) != {'op','field','value'}:
            raise InvalidInput('invalid filter operation')
        field = step['field']
        if type(field) is not str or field not in schema:
            raise InvalidInput('unknown filter field')
        value = check_scalar(step['value'])
        if schema[field] != type(value).__name__:
            raise InvalidInput('filter constant type mismatch')
        if op != 'filter_eq' and type(value) is not int:
            raise InvalidInput('ordered filters require integer field')
        return {'op':op,'field':field,'value':value}
    if op in TERMINALS:
        if op == 'count':
            if set(step) != {'op'}:
                raise InvalidInput('count has no field')
            return {'op':op}
        if set(step) != {'op','field'}:
            raise InvalidInput('aggregation requires field')
        field = step['field']
        if type(field) is not str or field not in schema:
            raise InvalidInput('unknown aggregate field')
        if op in {'sum','min','max'} and schema[field] != 'int':
            raise InvalidInput('numeric aggregation requires integer field')
        return {'op':op,'field':field}
    raise InvalidInput('unknown workflow operation')


def validate_plan(plan, schema):
    if type(plan) is not list or not 1 <= len(plan) <= MAX_STEPS:
        raise InvalidInput('workflow must contain 1-8 operations')
    if type(plan[-1]) is not dict or plan[-1].get('op') not in TERMINALS:
        raise InvalidInput('workflow must end in one aggregation')
    if len(plan) > 1 and any(type(step) is not dict or step.get('op') not in FILTERS for step in plan[:-1]):
        raise InvalidInput('only filters may precede the final aggregation')
    checked = [validate_step(step,schema,terminal=(i == len(plan)-1)) for i,step in enumerate(plan)]
    return checked


def normalize_plan(plan, schema):
    """Exact-law normalization: independent filters commute and are idempotent.

    This is not empirical equivalence: it relies only on the semantics of pure
    row selection. Never reorder reductions or apply arithmetic identities.
    """
    checked = validate_plan(plan,schema)
    filters = {canonical(step):step for step in checked[:-1]}
    return [filters[key] for key in sorted(filters)] + [checked[-1]]


def _apply(rows, step):
    op = step['op']
    if op in FILTERS:
        field,val = step['field'],step['value']
        if op == 'filter_eq': return [r for r in rows if type(r[field]) is type(val) and r[field] == val]
        if op == 'filter_gt': return [r for r in rows if r[field] > val]
        return [r for r in rows if r[field] < val]
    if op == 'count': return len(rows)
    vals = [r[step['field']] for r in rows]
    if op == 'distinct_count': return len({(type(x).__name__, x) for x in vals})
    if op == 'sum':
        out=sum(vals)
        if abs(out)>MAX_MAGNITUDE: raise InvalidInput('aggregate overflow')
        return out
    if not vals: raise InvalidInput('min/max of empty set')
    return min(vals) if op=='min' else max(vals)


def execute_plan(data, plan):
    clean,schema = validate_data(data)
    ops = validate_plan(plan,schema)
    records=clean['rows']
    for step in ops:
        records = _apply(records,step)
    return check_scalar(records)


class WorkflowSession:
    """Instrument actual allowed operations, not after-the-fact LLM narration."""
    def __init__(self,data):
        self.data,self.schema=validate_data(data)
        self.rows=self.data['rows']
        self.events=[]
        self.head='0'*64
        self.completed=False
        self.output=None

    def call(self,operation):
        if self.completed or len(self.events)>=MAX_STEPS:
            raise InvalidInput('workflow already finished or at operation limit')
        op=validate_step(operation,self.schema)
        if len(self.events)==MAX_STEPS-1 and op['op'] in FILTERS:
            raise InvalidInput('last operation must be a terminal')
        result=_apply(self.rows,op)
        if op['op'] in FILTERS:
            observed={'matching_rows':len(result)}
            self.rows=result
        else:
            self.completed=True
            self.output=check_scalar(result)
            observed={'value':self.output}
        body={'index':len(self.events),'operation':op,'observed':observed,'prior':self.head}
        event={**body,'hash':digest(body)}
        self.events.append(event)
        self.head=event['hash']
        return deepcopy(observed)

    def capture(self):
        if not self.completed:
            raise InvalidInput('workflow needs a final aggregation')
        body={'version':1,'data':self.data,'events':self.events,'output':self.output,'head':self.head}
        return {**deepcopy(body),'capture_digest':digest(body),
                'evidence_scope':'bounded local replay; no independent execution attestation'}


def capture_plan(request):
    if type(request) is not dict or set(request) != {'data','plan'}:
        raise InvalidInput('workflow capture requires exactly data and plan')
    sess=WorkflowSession(request['data'])
    _,schema=validate_data(request['data'])
    for operation in validate_plan(request['plan'],schema):
        sess.call(operation)
    return sess.capture()


def replay_capture(capture):
    if type(capture) is not dict or set(capture) != {'version','data','events','output','head','capture_digest','evidence_scope'}:
        raise InvalidInput('invalid workflow capture envelope')
    if type(capture['version']) is not int or capture['version']!=1:
        raise InvalidInput('unsupported workflow capture version')
    if capture['evidence_scope'] != 'bounded local replay; no independent execution attestation':
        raise InvalidInput('modified capture qualification scope')
    sess=WorkflowSession(capture['data'])
    events=capture['events']
    if type(events) is not list or not 1<=len(events)<=MAX_STEPS:
        raise InvalidInput('malformed workflow events')
    for event in events:
        if type(event) is not dict or set(event)!={'index','operation','observed','prior','hash'}:
            raise InvalidInput('malformed workflow event')
        if event['prior'] != sess.head or event['hash'] != digest({k:v for k,v in event.items() if k!='hash'}):
            raise InvalidInput('workflow event hash invalid')
        try:
            actual=sess.call(event['operation'])
        except (InvalidInput, KeyError, ValueError, TypeError) as exc:
            raise InvalidInput('workflow event cannot be replayed') from exc
        if type(event['observed']) is not dict or actual != event['observed'] or event != sess.events[-1]:
            raise InvalidInput('workflow operation result or event differs from replay')
    if not sess.completed:
        raise InvalidInput('workflow recording lacks terminal operation')
    expected=sess.capture()
    if capture!=expected:
        raise InvalidInput('workflow capture differs from independently replayed events')
    _,schema=validate_data(sess.data)
    plan=[x['operation'] for x in sess.events]
    normal=normalize_plan(plan,schema)
    # Verify normalized plan on the very same input, including bounded runtime.
    if execute_plan(sess.data,normal)!=sess.output:
        raise InvalidInput('canonicalized workflow unexpectedly changed output')
    return {'data':sess.data,'schema':schema,'plan':plan,'normalized_plan':normal,
            'output':sess.output,'capture_digest':capture['capture_digest'],
            'fingerprint':digest({'schema':schema,'plan':normal})}
