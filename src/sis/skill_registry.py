"""Governed procedural skill catalog; does not alter the existing rule/audit tables.

Hash linked local events + semantic projection replay fail closed. This is NOT
an independent trust root: database owner can replace its entire history.
"""
import hashlib
import json
from .errors import InvalidInput, RuleRejected
from .validation import canonical, digest, check_inputs, check_scalar, check_examples, input_schema, namespace_name
from .induction import generated_probes
from .skill_program import execute, validate_program
from .skill_learning import study as discover, matches, check_study
from .registry import utc

FIELDS=('id','namespace','schema','program','train_digest','validation_digest',
        'train_count','validation_count','status','positive','negative')
IMMUTABLE=set(FIELDS)-{'status','positive','negative'}

class SkillCatalog:
    def __init__(self, conn, lock):
        self.conn,self.lock=conn,lock
        with self.lock,self.conn:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS sis_skills (
                id TEXT PRIMARY KEY, namespace TEXT NOT NULL, schema TEXT NOT NULL,
                program TEXT NOT NULL, train_digest TEXT NOT NULL, validation_digest TEXT NOT NULL,
                train_count INTEGER NOT NULL, validation_count INTEGER NOT NULL,
                status TEXT NOT NULL, positive INTEGER NOT NULL DEFAULT 0, negative INTEGER NOT NULL DEFAULT 0)''')
            self.conn.execute('''CREATE TABLE IF NOT EXISTS sis_skill_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,prior TEXT NOT NULL,hash TEXT NOT NULL)''')

    def _projection(self,sid):
        row=self.conn.execute('SELECT '+','.join(FIELDS)+' FROM sis_skills WHERE id=?',(sid,)).fetchone()
        if row is None: raise RuleRejected('skill disappeared from registry')
        record=dict(zip(FIELDS,row))
        for name in ('schema','program'): record[name]=json.loads(record[name])
        return record

    def _append(self,kind,sid):
        prior=self.conn.execute('SELECT hash FROM sis_skill_events ORDER BY seq DESC LIMIT 1').fetchone()
        before=prior[0] if prior else '0'*64
        entry={'event':kind,'skill_id':sid,'snapshot':self._projection(sid),'at':utc()}
        body=canonical(entry)
        hv=hashlib.sha256((before+'\n'+body).encode()).hexdigest()
        self.conn.execute('INSERT INTO sis_skill_events(event,prior,hash) VALUES (?,?,?)',(body,before,hv))

    def verify(self):
        with self.lock:
            history={}; prev='0'*64; count=0
            rows=self.conn.execute('SELECT seq,event,prior,hash FROM sis_skill_events ORDER BY seq').fetchall()
            for seq,body,before,hv in rows:
                if seq != count+1 or before!=prev or hv != hashlib.sha256((before+'\n'+body).encode()).hexdigest():
                    return {'valid':False,'reason':'skill audit hash or sequence failure','at_seq':seq}
                try:
                    event=json.loads(body)
                    if canonical(event)!=body or set(event)!={'event','skill_id','snapshot','at'}:
                        raise ValueError('event malformed')
                    s=event['snapshot']; sid=event['skill_id']; kind=event['event']
                    if set(s)!=set(FIELDS) or s['id']!=sid or sid!=digest({'namespace':s['namespace'],'schema':s['schema'],'program':s['program']}):
                        raise ValueError('skill projection identity mismatch')
                    namespace_name(s['namespace'])
                    validate_program(s['program'],schema=s['schema'])
                    if any(type(s[x]) is not int or s[x]<0 for x in ('train_count','validation_count','positive','negative')):
                        raise ValueError('invalid counters')
                    if s['train_count']<3 or s['validation_count']<2:
                        raise ValueError('insufficient evidence counts')
                    if any(type(s[x]) is not str or len(s[x])!=64 for x in ('train_digest','validation_digest')):
                        raise ValueError('invalid evidence hashes')
                    old=history.get(sid)
                    if kind=='promoted':
                        if old is not None or s['status']!='active' or (s['positive']!=0 or s['negative']!=0):
                            raise ValueError('invalid promotion transition')
                    elif kind in ('feedback_positive','feedback_negative','retired'):
                        if old is None or any(s[x]!=old[x] for x in IMMUTABLE):
                            raise ValueError('invalid immutable transition')
                        if kind=='feedback_positive' and not (old['status']=='active' and s['status']=='active' and s['positive']==old['positive']+1 and s['negative']==old['negative']):
                            raise ValueError('invalid success feedback')
                        if kind=='feedback_negative' and not (old['status']=='active' and s['status']=='suspended' and s['negative']==old['negative']+1 and s['positive']==old['positive']):
                            raise ValueError('invalid failure feedback')
                        if kind=='retired' and not (old['status'] in ('active','suspended') and s['status']=='retired' and s['positive']==old['positive'] and s['negative']==old['negative']):
                            raise ValueError('invalid retirement')
                    else: raise ValueError('unexpected skill event')
                    history[sid]=s
                except (ValueError,KeyError,TypeError,InvalidInput):
                    return {'valid':False,'reason':'invalid skill event transition','at_seq':seq}
                prev=hv; count+=1
            actual={r[0] for r in self.conn.execute('SELECT id FROM sis_skills')}
            if actual!=set(history):
                return {'valid':False,'reason':'skill projection lacks event'}
            try:
                if any(self._projection(sid)!=snapshot for sid,snapshot in history.items()):
                    return {'valid':False,'reason':'skill projection tampered'}
            except (ValueError,TypeError,KeyError):
                return {'valid':False,'reason':'invalid stored skill projection'}
            return {'valid':True,'skills_verified':len(history),'events_verified':count,'head':prev,
                    'warning':'database owner can rewrite consistent history; external custody is required'}

    def _trusted(self):
        result=self.verify()
        if not result['valid']:
            raise RuleRejected('skill audit integrity failure: '+result['reason'])

    def _resolve(self,sid):
        self._trusted()
        row=self.conn.execute('SELECT status FROM sis_skills WHERE id=?',(sid,)).fetchone()
        return self._projection(sid) if row and row[0]=='active' else None

    def list(self,namespace='default',include_inactive=False):
        namespace=namespace_name(namespace)
        with self.lock:
            self._trusted()
            q='SELECT id FROM sis_skills WHERE namespace=?'
            if not include_inactive: q+=" AND status='active'"
            ids=[r[0] for r in self.conn.execute(q+' ORDER BY id',(namespace,))]
            return [self._projection(sid) for sid in ids]

    def study(self,request):
        with self.lock:
            self._trusted()
            result=discover(request,resolver=self._resolve)
            if request.get('promote'):
                if result['status']!='locally_validated':
                    result['promotion']={'status':'rejected','reason':'skill requires unambiguous complete local validation'}
                else:
                    result['promotion']=self.promote(result,request)
            return result

    def promote(self,result,request):
        with self.lock,self.conn:
            self._trusted()
            # Original observations and complete search context required: recompute, never trust a supplied verdict.
            recalc=discover(request,resolver=self._resolve)
            if canonical(result)!=canonical(recalc) or result['status']!='locally_validated':
                raise RuleRejected('skill promotion cannot reproduce complete study')
            namespace=result['namespace']; schema=result['schema']; program=result['program']
            validate_program(program,schema=schema)
            sid=digest({'namespace':namespace,'schema':schema,'program':program})
            old=self.conn.execute('SELECT id FROM sis_skills WHERE id=?',(sid,)).fetchone()
            if old: return {'status':'already_exists','id':sid,'created':False}
            inputs=[e['inputs'] for e in request['train']+request['validation']]
            inputs.extend(generated_probes(request['train'][0]['inputs'],limit=128))
            for other in self.list(namespace):
                if other['schema']!=schema: continue
                for inp in inputs:
                    try:
                        a=execute(program,inp,self._resolve,namespace=namespace)
                        b=execute(other['program'],inp,self._resolve,namespace=namespace,_ids=(other['id'],))
                        if type(a) is not type(b) or a!=b:
                            raise RuleRejected('conflict with an already active skill; admission blocked')
                    except InvalidInput:
                        continue
            self.conn.execute('''INSERT INTO sis_skills
                (id,namespace,schema,program,train_digest,validation_digest,train_count,validation_count,status)
                VALUES (?,?,?,?,?,?,?,?,?)''',
                (sid,namespace,canonical(schema),canonical(program),result['train_digest'],
                 result['validation_digest'],result['train_count'],result['validation_count'],'active'))
            self._append('promoted',sid)
            return {'status':'active','id':sid,'created':True,'evidence':'caller-supplied local validation'}

    def predict(self,request):
        if not isinstance(request,dict): raise InvalidInput('skill prediction must be an object')
        namespace=namespace_name(request.get('namespace','default'))
        inputs=check_inputs(request.get('inputs'))
        wanted=request.get('skill_id')
        if wanted is not None and (not isinstance(wanted,str) or len(wanted)!=64):
            raise InvalidInput('skill_id must be a sha256 identity')
        with self.lock:
            try:
                self._trusted()
            except RuleRejected:
                return {'status':'abstain','reason':'skill catalog integrity failure'}
            rules=[r for r in self.list(namespace) if r['schema']==input_schema(inputs) and (wanted is None or r['id']==wanted)]
            answers=[]
            for r in rules:
                try:
                    answers.append((r['id'],execute(r['program'],inputs,self._resolve,namespace=namespace,_ids=(r['id'],))))
                except (InvalidInput,KeyError,IndexError,TypeError):
                    continue
            if not answers:
                return {'status':'abstain','reason':'no executable active skill with matching schema'}
            if len({canonical(out) for _,out in answers})!=1:
                return {'status':'abstain','reason':'active procedural skills disagree'}
            return {'status':'predicted','output':answers[0][1],'skill_ids':[sid for sid,_ in answers],
                    'qualification':'locally_validated_only'}

    def feedback(self,request):
        if not isinstance(request,dict): raise InvalidInput('skill feedback requires an object')
        namespace=namespace_name(request.get('namespace','default'))
        sid=request.get('skill_id')
        inputs=check_inputs(request.get('inputs'))
        observed=check_scalar(request.get('observed_output'))
        with self.lock,self.conn:
            self._trusted()
            record=self._resolve(sid)
            if not record or record['namespace']!=namespace or input_schema(inputs)!=record['schema']:
                raise InvalidInput('skill inactive, unknown or input schema mismatched')
            predicted=execute(record['program'],inputs,self._resolve,namespace=namespace,_ids=(sid,))
            if type(predicted) is not type(observed): raise InvalidInput('skill feedback output type differs')
            ok=predicted==observed
            if ok:
                self.conn.execute('UPDATE sis_skills SET positive=positive+1 WHERE id=?',(sid,))
            else:
                self.conn.execute("UPDATE sis_skills SET negative=negative+1,status='suspended' WHERE id=?",(sid,))
            self._append('feedback_positive' if ok else 'feedback_negative',sid)
            return {'matched':ok,'status':'active' if ok else 'suspended','origin':'operator_reported'}

    def retire(self,request):
        if not isinstance(request,dict) or not isinstance(request.get('skill_id'),str):
            raise InvalidInput('retire skill requires skill_id')
        namespace=namespace_name(request.get('namespace','default'))
        sid=request['skill_id']
        with self.lock,self.conn:
            self._trusted()
            rec=self.conn.execute('SELECT status FROM sis_skills WHERE id=? AND namespace=?',(sid,namespace)).fetchone()
            if not rec: raise InvalidInput('unknown skill')
            if rec[0]=='retired': return {'status':'retired','changed':False}
            self.conn.execute("UPDATE sis_skills SET status='retired' WHERE id=?",(sid,))
            self._append('retired',sid)
            return {'status':'retired','changed':True}

    def freeze(self, namespace, skill_id):
        from .skill_bundle import freeze
        return freeze(self, namespace, skill_id)

    def benchmark(self,request):
        if not isinstance(request,dict): raise InvalidInput('benchmark request must be an object')
        namespace=namespace_name(request.get('namespace','default'))
        with self.lock:
            self._trusted()
        cases=check_examples(request.get('cases'),minimum=1)
        if len(cases)>256: raise InvalidInput('too many benchmark cases')
        correct=predicted=0
        for case in cases:
            pred=self.predict({'namespace':namespace,'inputs':case['inputs'],**({'skill_id':request['skill_id']} if 'skill_id' in request else {})})
            if pred['status']=='predicted':
                predicted+=1
                if type(pred['output']) is type(case['output']) and pred['output']==case['output']:
                    correct+=1
        count=len(cases)
        return {'count':count,'predicted':predicted,'correct':correct,'coverage':predicted/count,
                'accuracy_on_predictions':correct/predicted if predicted else None,
                'accuracy_overall':correct/count,
                'evidence':'caller-supplied dataset; no independent provenance or contamination guarantee'}
