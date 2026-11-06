"""Opt-in, operator-gated workflow registry for v2.3 tabular experiences.

Verification recomputes submitted captures and caller-provided labels. No LLM
can promote via the read-only model tool bridge. Hashes protect against partial
corruption, not a malicious database custodian who can rewrite every record.
"""
import json
from .errors import InvalidInput, RuleRejected
from .validation import canonical, digest, namespace_name, check_scalar
from .workflow_engine import validate_data, replay_capture, execute_plan


def _same(a,b):
    return type(a) is type(b) and a==b


class WorkflowCatalog:
    def __init__(self,connection,lock):
        self.conn=connection
        self.lock=lock
        with self.lock,self.conn:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS sis_tabular_workflows (
                id TEXT PRIMARY KEY, namespace TEXT NOT NULL, schema_json TEXT NOT NULL,
                plan_json TEXT NOT NULL, training_digest TEXT NOT NULL,
                validation_digest TEXT NOT NULL, status TEXT NOT NULL,
                record_digest TEXT NOT NULL)''')
            self.conn.execute('''CREATE TABLE IF NOT EXISTS sis_tabular_workflow_audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
                workflow_id TEXT NOT NULL, prior TEXT NOT NULL, hash TEXT NOT NULL)''')

    def _audit(self,action,workflow_id):
        record=self.conn.execute('SELECT seq,hash FROM sis_tabular_workflow_audit ORDER BY seq DESC LIMIT 1').fetchone()
        prior=record[1] if record else '0'*64
        number=(record[0]+1) if record else 1
        entry={'seq':number,'action':action,'id':workflow_id,'prior':prior}
        self.conn.execute('INSERT INTO sis_tabular_workflow_audit (action,workflow_id,prior,hash) VALUES (?,?,?,?)',
                          (action,workflow_id,prior,digest(entry)))

    def verify(self):
        with self.lock:
            rows=self.conn.execute('SELECT id,namespace,schema_json,plan_json,training_digest,validation_digest,status,record_digest FROM sis_tabular_workflows').fetchall()
            latest={}
            previous='0'*64
            index=0
            for seq,action,wid,prior,h in self.conn.execute('SELECT seq,action,workflow_id,prior,hash FROM sis_tabular_workflow_audit ORDER BY seq'):
                index+=1
                if index!=seq or prior!=previous or h!=digest({'seq':seq,'action':action,'id':wid,'prior':prior}):
                    raise RuleRejected('workflow audit chain corrupted')
                if action=='promote':
                    if wid in latest: raise RuleRejected('duplicate workflow promotion')
                    latest[wid]='active'
                elif action=='retire':
                    if latest.get(wid)!='active': raise RuleRejected('invalid workflow retirement')
                    latest[wid]='retired'
                else:
                    raise RuleRejected('unknown workflow audit action')
                previous=h
            if len(rows)!=len(latest):
                raise RuleRejected('workflow registry/audit cardinality mismatch')
            for wid,ns,sc,pl,tr,vl,status,seal in rows:
                try:
                    schema=json.loads(sc)
                    plan=json.loads(pl)
                except (ValueError,TypeError) as exc:
                    raise RuleRejected('workflow stored program corrupted') from exc
                body={'id':wid,'namespace':ns,'schema':schema,'plan':plan,'training':tr,'validation':vl}
                if seal!=digest(body) or wid!=digest({'namespace':ns,'schema':schema,'plan':plan}):
                    raise RuleRejected('workflow snapshot digest differs')
                if status!=latest.get(wid):
                    raise RuleRejected('workflow status inconsistent with audit')
            return {'status':'valid','workflows':len(rows),'audit_events':index,'scope':'local hash consistency only; not independent tamper-proof custody'}

    def _study(self,request):
        if type(request) is not dict or set(request)-{'namespace','promote','train_captures','validation'}:
            raise InvalidInput('unknown workflow study fields')
        ns=namespace_name(request.get('namespace','default'))
        promote=request.get('promote',False)
        if type(promote) is not bool: raise InvalidInput('promote must be Boolean')
        train=request.get('train_captures')
        test=request.get('validation')
        if type(train) is not list or not 3<=len(train)<=32:
            raise InvalidInput('workflow training requires 3-32 records')
        if type(test) is not list or not 2<=len(test)<=128:
            raise InvalidInput('workflow validation requires 2-128 records')
        seen=set()
        proposals={}
        schema=None
        positives=0
        failures=0
        train_evidence=[]
        for row in train:
            if type(row) is not dict or set(row)!={'capture','accepted','expected_output'} or type(row['accepted']) is not bool:
                raise InvalidInput('training requires capture, Boolean accepted, and independent expected_output')
            record=replay_capture(row['capture'])
            expected=check_scalar(row['expected_output'])
            if not _same(expected,record['output']) and row['accepted']:
                raise InvalidInput('accepted run disagrees with expected_output')
            if _same(expected,record['output']) and not row['accepted']:
                raise InvalidInput('failed run cannot equal expected_output')
            if type(expected) is not int:  # v2.3 terminal reducers all return integers
                raise InvalidInput('workflow expected output must be integer')
            if schema is None: schema=record['schema']
            if schema!=record['schema']: raise InvalidInput('different workflow input schemas')
            d=digest(record['data'])
            if d in seen: raise InvalidInput('training duplicate input data')
            seen.add(d)
            if row['accepted']:
                positives+=1
                proposals[record['fingerprint']]=record['normalized_plan']
            else:
                failures+=1
            train_evidence.append({'capture':record['capture_digest'],'accepted':row['accepted'],'expected':expected})
        if positives<3: raise InvalidInput('at least three successful verified captures required')
        if len(proposals)!=1:
            raise InvalidInput('different successful normalized workflows; split task families')
        candidate=next(iter(proposals.values()))
        qualification=[]
        for row in test:
            if type(row) is not dict or set(row)!={'data','expected_output'}:
                raise InvalidInput('validation requires data and integer expected_output only')
            expected=check_scalar(row['expected_output'])
            if type(expected) is not int:
                raise InvalidInput('validation expected output must be integer')
            clean,valschema=validate_data(row['data'])
            if valschema!=schema: raise InvalidInput('holdout schema differs from training')
            d=digest(clean)
            if d in seen: raise InvalidInput('train/validation or holdout overlap')
            seen.add(d)
            try:
                actual=execute_plan(clean,candidate)
            except (InvalidInput,ValueError,TypeError,KeyError):
                actual=None
            qualification.append({'data_digest':d,'pass':_same(actual,expected)})
        status='locally_validated' if all(x['pass'] for x in qualification) else 'validation_failed'
        result={'status':status,'namespace':ns,'schema':schema,'plan':candidate,
                'training_count':len(train),'accepted_count':positives,'corrected_failure_count':failures,
                'validation_count':len(test),'validation_passed':sum(x['pass'] for x in qualification),
                'training_digest':digest(train_evidence),'validation_digest':digest(qualification),
                'qualification':'caller-labeled local validation; neither independent custody nor unknown-family generalization'}
        return result

    def study(self,request):
        # All derived evidence reconstructed from raw captures and held-out data.
        result=self._study(request)
        if not request.get('promote',False):
            return result
        if result['status']!='locally_validated':
            return {**result,'promotion':{'status':'rejected','reason':'validation failed'}}
        with self.lock,self.conn:
            self.verify()
            recomputed=self._study(request)
            if canonical(recomputed)!=canonical(result):
                raise RuleRejected('workflow promotion replay mismatch')
            ns=result['namespace']; sc=result['schema']; plan=result['plan']
            wid=digest({'namespace':ns,'schema':sc,'plan':plan})
            active=self.conn.execute('SELECT id,plan_json FROM sis_tabular_workflows WHERE namespace=? AND schema_json=? AND status=?',
                                     (ns,canonical(sc),'active')).fetchall()
            if any(other!=wid for other,_ in active):
                raise RuleRejected('conflicting active workflow with same namespace and schema')
            existing=self.conn.execute('SELECT status FROM sis_tabular_workflows WHERE id=?',(wid,)).fetchone()
            if existing:
                if existing[0]=='active':
                    return {**result,'promotion':{'status':'already_active','workflow_id':wid}}
                raise RuleRejected('retired workflow cannot be silently reactivated')
            snapshot={'id':wid,'namespace':ns,'schema':sc,'plan':plan,
                      'training':result['training_digest'],'validation':result['validation_digest']}
            self.conn.execute('INSERT INTO sis_tabular_workflows VALUES (?,?,?,?,?,?,?,?)',
                              (wid,ns,canonical(sc),canonical(plan),result['training_digest'],
                               result['validation_digest'],'active',digest(snapshot)))
            self._audit('promote',wid)
            return {**result,'promotion':{'status':'active','workflow_id':wid}}

    def predict(self,request):
        if type(request) is not dict or set(request)-{'namespace','workflow_id','data'} or 'data' not in request:
            raise InvalidInput('workflow prediction requires data and optional workflow_id/namespace')
        ns=namespace_name(request.get('namespace','default'))
        data,schema=validate_data(request['data'])
        with self.lock:
            try: self.verify()
            except RuleRejected:
                return {'status':'abstain','reason':'workflow registry integrity failure'}
            rows=self.conn.execute('SELECT id,plan_json FROM sis_tabular_workflows WHERE namespace=? AND schema_json=? AND status=?',
                                   (ns,canonical(schema),'active')).fetchall()
            if 'workflow_id' in request:
                if type(request['workflow_id']) is not str or len(request['workflow_id'])!=64:
                    raise InvalidInput('invalid workflow identifier')
                rows=[r for r in rows if r[0]==request['workflow_id']]
            if len(rows)!=1:
                return {'status':'abstain','reason':'no unique active applicable workflow'}
            try: out=execute_plan(data,json.loads(rows[0][1]))
            except (InvalidInput,ValueError,TypeError,KeyError):
                return {'status':'abstain','reason':'workflow not executable on these records'}
            return {'status':'predicted','output':out,'workflow_id':rows[0][0],
                    'qualification':'locally_validated_only'}

    def list(self,namespace='default'):
        ns=namespace_name(namespace)
        with self.lock:
            self.verify()
            rows=self.conn.execute('SELECT id,schema_json,plan_json,status FROM sis_tabular_workflows WHERE namespace=?',(ns,)).fetchall()
            return [{'id':r[0],'schema':json.loads(r[1]),'plan':json.loads(r[2]),'status':r[3]} for r in rows]

    def retire(self,request):
        if type(request) is not dict or set(request)!={'namespace','workflow_id'}:
            raise InvalidInput('workflow retirement requires namespace and workflow_id')
        ns=namespace_name(request['namespace']); wid=request['workflow_id']
        if type(wid) is not str or len(wid)!=64:
            raise InvalidInput('invalid workflow ID')
        with self.lock,self.conn:
            self.verify()
            row=self.conn.execute('SELECT status FROM sis_tabular_workflows WHERE id=? AND namespace=?',(wid,ns)).fetchone()
            if row is None: raise InvalidInput('unknown workflow')
            if row[0]=='retired': return {'status':'retired','changed':False}
            self.conn.execute('UPDATE sis_tabular_workflows SET status=? WHERE id=?',('retired',wid))
            self._audit('retire',wid)
            return {'status':'retired','changed':True}
