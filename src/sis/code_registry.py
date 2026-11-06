"""v2.4 governed code transformation recipes, separate from v2.3 tabular registry.

This is evidence-gated *local* code rewriting, NOT a safe code execution sandbox.
Models receive only preview authority, never promotion or write authority.
"""
import json
import hashlib
from .code_learning import capture_repair, replay_repair, check_cases, transform, preview_patch, _recipe, _source, _file
from .errors import InvalidInput, RuleRejected
from .validation import canonical, digest, namespace_name

class CodeCatalog:
    def __init__(self, connection, lock):
        self.conn=connection;self.lock=lock
        with self.lock,self.conn:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS sis_code_recipes (
              id TEXT PRIMARY KEY, namespace TEXT NOT NULL, recipe_json TEXT NOT NULL,
              evidence_digest TEXT NOT NULL, status TEXT NOT NULL, record_digest TEXT NOT NULL)''')
            self.conn.execute('''CREATE TABLE IF NOT EXISTS sis_code_audit (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
              recipe_id TEXT NOT NULL, prior TEXT NOT NULL, hash TEXT NOT NULL)''')

    def _append(self,action,rid):
        previous=self.conn.execute('SELECT seq,hash FROM sis_code_audit ORDER BY seq DESC LIMIT 1').fetchone()
        seq=previous[0]+1 if previous else 1
        prior=previous[1] if previous else '0'*64
        self.conn.execute('INSERT INTO sis_code_audit (action,recipe_id,prior,hash) VALUES (?,?,?,?)',
                          (action,rid,prior,digest({'seq':seq,'action':action,'recipe_id':rid,'prior':prior})))

    def verify(self):
        with self.lock:
            previous='0'*64
            seq_expected=0
            states={}
            for seq,action,rid,prior,h in self.conn.execute('SELECT seq,action,recipe_id,prior,hash FROM sis_code_audit ORDER BY seq'):
                seq_expected+=1
                if seq!=seq_expected or prior!=previous or h!=digest({'seq':seq,'action':action,'recipe_id':rid,'prior':prior}):
                    raise RuleRejected('code audit chain invalid')
                if action=='promote' and rid not in states:
                    states[rid]='active'
                elif action=='retire' and states.get(rid)=='active':
                    states[rid]='retired'
                else: raise RuleRejected('invalid code recipe transition')
                previous=h
            rows=self.conn.execute('SELECT id,namespace,recipe_json,evidence_digest,status,record_digest FROM sis_code_recipes').fetchall()
            if len(rows)!=len(states): raise RuleRejected('code registry/audit cardinality mismatch')
            for rid,ns,text,evidence,status,seal in rows:
                try:
                    recipe=_recipe(json.loads(text));ns=namespace_name(ns)
                except (ValueError,KeyError,TypeError,InvalidInput) as exc:
                    raise RuleRejected('corrupt code recipe record') from exc
                body={'id':rid,'namespace':ns,'recipe':recipe,'evidence_digest':evidence}
                if (status!=states.get(rid) or seal!=digest(body) or
                    rid!=digest({'namespace':ns,'recipe':recipe})):
                    raise RuleRejected('code snapshot mismatch')
            return {'status':'valid','recipes':len(rows),'audit_events':seq_expected,
                    'scope':'local hash-linked evidence; not authenticated independent custody'}

    def _study(self,request):
        if type(request) is not dict or set(request)-{'namespace','promote','train_captures','validation'}:
            raise InvalidInput('invalid code-study request')
        ns=namespace_name(request.get('namespace','default'))
        if type(request.get('promote',False)) is not bool:
            raise InvalidInput('promote must be Boolean')
        train=request.get('train_captures');holdout=request.get('validation')
        if type(train) is not list or not 3<=len(train)<=32:
            raise InvalidInput('code study requires 3-32 captured repairs')
        if type(holdout) is not list or not 2<=len(holdout)<=64:
            raise InvalidInput('code study requires 2-64 withheld source programs')
        recipes={}; seen=set(); train_log=[]; accepted=0
        for capture in train:
            replay=replay_repair(capture)
            source_key=digest({'source_digest':replay['source_digest'],'function':replay['function']})
            if source_key in seen: raise InvalidInput('duplicate training source')
            seen.add(source_key)
            if replay['after']['passed']!=replay['after']['total']:
                raise InvalidInput('training trace did not solve all labeled tests')
            accepted+=1
            recipes[canonical(replay['recipe'])]=replay['recipe']
            train_log.append({'capture_digest':replay['capture_digest'],'original':replay['source_digest'],
                              'patched':replay['patched_digest']})
        if len(recipes)!=1:
            raise InvalidInput('multiple repair recipes; split into separate tasks')
        recipe=next(iter(recipes.values()))
        verdicts=[]
        for case in holdout:
            if type(case) is not dict or set(case)!={'source','filename','function','cases'}:
                raise InvalidInput('invalid withheld code study case')
            source=_source(case['source']);_file(case['filename'])
            key=digest({'source_digest':hashlib.sha256(source.encode('utf8')).hexdigest(),'function':case['function']})
            if key in seen: raise InvalidInput('training/holdout overlap')
            seen.add(key)
            before=check_cases(source,case['function'],case['cases'])
            try:
                after=check_cases(transform(source,case['function'],recipe),case['function'],case['cases'])
                ok=(before['passed']<before['total'] and after['passed']==after['total'])
            except InvalidInput:
                ok=False
            verdicts.append({'holdout_digest':key,'pass':ok})
        qualified=all(x['pass'] for x in verdicts)
        return {'status':'locally_validated' if qualified else 'validation_failed',
                'namespace':ns,'recipe':recipe,'training_count':len(train),
                'validation_count':len(holdout),'validation_passed':sum(x['pass'] for x in verdicts),
                'evidence_digest':digest({'train':train_log,'holdout':verdicts}),
                'qualification':'caller-labeled, AST-interpreted local code evaluation; no real code execution or independent holdout custodian'}

    def study(self, request):
        result=self._study(request)
        if not request.get('promote',False): return result
        if result['status']!='locally_validated':
            return {**result,'promotion':{'status':'rejected','reason':'withheld code tests failed'}}
        with self.lock,self.conn:
            self.verify()
            if canonical(self._study(request))!=canonical(result):
                raise RuleRejected('code promotion independent replay mismatch')
            ns=result['namespace'];recipe=result['recipe']
            rid=digest({'namespace':ns,'recipe':recipe})
            rows=self.conn.execute("SELECT id FROM sis_code_recipes WHERE namespace=? AND status='active'",(ns,)).fetchall()
            if any(other_id!=rid for (other_id,) in rows):
                raise RuleRejected('conflicting active recipe; use distinct namespace')
            previous=self.conn.execute('SELECT status FROM sis_code_recipes WHERE id=?',(rid,)).fetchone()
            if previous:
                if previous[0]=='active':return {**result,'promotion':{'status':'already_active','recipe_id':rid}}
                raise RuleRejected('retired recipe may not be silently reactivated')
            body={'id':rid,'namespace':ns,'recipe':recipe,'evidence_digest':result['evidence_digest']}
            self.conn.execute('INSERT INTO sis_code_recipes VALUES (?,?,?,?,?,?)',
                              (rid,ns,canonical(recipe),result['evidence_digest'],'active',digest(body)))
            self._append('promote',rid)
            return {**result,'promotion':{'status':'active','recipe_id':rid}}

    def list(self,namespace='default'):
        namespace=namespace_name(namespace)
        self.verify()
        with self.lock:
            records=self.conn.execute('SELECT id,recipe_json,status FROM sis_code_recipes WHERE namespace=? ORDER BY id',(namespace,)).fetchall()
            return [{'recipe_id':rid,'recipe':json.loads(recipe),'status':status} for rid,recipe,status in records]

    def preview(self,request):
        if type(request) is not dict or set(request)-{'namespace','recipe_id','source','filename','function'}:
            raise InvalidInput('invalid code preview request')
        try:self.verify()
        except RuleRejected:
            return {'status':'abstain','reason':'code registry integrity verification failed'}
        ns=namespace_name(request.get('namespace','default'))
        rid=request.get('recipe_id')
        if rid is not None and type(rid) is not str:
            raise InvalidInput('recipe_id must be string')
        with self.lock:
            records=self.conn.execute("SELECT id,recipe_json FROM sis_code_recipes WHERE namespace=? AND status='active'"+(" AND id=?" if rid else ''),
                                      (ns,rid) if rid else (ns,)).fetchall()
        if len(records)!=1:
            return {'status':'abstain','reason':'no unique active code recipe'}
        recipe=json.loads(records[0][1])
        try:
            preview=preview_patch({key:request[key] for key in ('source','filename','function')},recipe)
        except InvalidInput as exc:
            return {'status':'abstain','reason':str(exc)}
        return {**preview,'recipe_id':records[0][0],'qualification':'preview only, applicability to new code is unproven'}

    def retire(self,request):
        if type(request) is not dict or set(request)-{'recipe_id','namespace'} or type(request.get('recipe_id')) is not str:
            raise InvalidInput('recipe_id required for retirement')
        with self.lock,self.conn:
            self.verify()
            ns=namespace_name(request.get('namespace','default'))
            result=self.conn.execute("SELECT status FROM sis_code_recipes WHERE id=? AND namespace=?",(request['recipe_id'],ns)).fetchone()
            if not result or result[0]!='active':raise RuleRejected('no active recipe to retire')
            self.conn.execute("UPDATE sis_code_recipes SET status='retired' WHERE id=?",(request['recipe_id'],))
            self._append('retire',request['recipe_id'])
        return {'status':'retired','recipe_id':request['recipe_id']}
