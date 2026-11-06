"""Constrained procedural skill discovery from labeled input/output episodes.

Candidate proposals may be supplied by an operator or LLM but cannot approve
or promote themselves. Labeled validation is separately supplied by caller.
"""
from .errors import InvalidInput
from .validation import canonical, digest, check_examples, input_schema, namespace_name
from .induction import generated_probes
from .skill_program import execute, validate_program


def inp(name): return {'op':'input','name':name}
def var(name): return {'op':'var','name':name}
def const(value): return {'op':'const','value':value}
def binary(fn,a,b): return {'op':'binary','fn':fn,'left':a,'right':b}


def enumerate_programs(schema):
    scalar = [name for name,typ in schema.items() if not isinstance(typ,list)]
    ints = [name for name in scalar if schema[name]=='int']
    lists = [name for name,typ in schema.items() if isinstance(typ,list) and all(t=='int' for t in typ)]
    for name in scalar:
        yield inp(name)
        if name in ints:
            for fn in ('neg','abs'):
                yield {'op':'unary','fn':fn,'arg':inp(name)}
        elif schema[name]=='bool':
            yield {'op':'unary','fn':'not','arg':inp(name)}
        elif schema[name]=='str':
            for fn in ('upper','lower'):
                yield {'op':'unary','fn':fn,'arg':inp(name)}
    for name in ints:
        for n in (-3,-2,-1,0,1,2,3):
            for fn in ('add','sub','mul'):
                yield binary(fn,inp(name),const(n))
        for other in ints:
            for fn in ('add','sub','mul','min','max','lt','gt','eq'):
                yield binary(fn,inp(name),inp(other))
    for name in lists:
        base = {'op':'fold','field':name,'item':'element','acc':'accumulator',
                'initial':const(0),'body':binary('add',var('accumulator'),var('element'))}
        yield base
        count = {'op':'fold','field':name,'item':'element','acc':'accumulator',
                 'initial':const(0),'body':binary('add',var('accumulator'),const(1))}
        yield count
        prod = {'op':'fold','field':name,'item':'element','acc':'accumulator',
                'initial':const(1),'body':binary('mul',var('accumulator'),var('element'))}
        yield prod
        for n in ints:
            for fn in ('add','sub','mul'):
                yield binary(fn,base,inp(n))
        # Conditional composition over a bounded fold.
        for n in ints:
            yield {'op':'let','name':'total','value':base,'body':
                   {'op':'if','condition':binary('gt',var('total'),inp(n)),
                    'then':var('total'),'else':inp(n)}}


def check_study(train, validation):
    train = check_examples(train,minimum=3)
    validation = check_examples(validation,minimum=2)
    schema = input_schema(train[0]['inputs'])
    if any(input_schema(x['inputs']) != schema or type(x['output']) is not type(train[0]['output']) for x in validation):
        raise InvalidInput('validation schema/output type differs from training')
    train_keys = [canonical(x['inputs']) for x in train]
    val_keys = [canonical(x['inputs']) for x in validation]
    if len(set(train_keys)) != len(train_keys) or len(set(val_keys)) != len(val_keys) or set(train_keys).intersection(val_keys):
        raise InvalidInput('train and validation inputs must be disjoint and unique')
    return train, validation, schema


def matches(program, rows, *, resolver=None, namespace='default'):
    try:
        for row in rows:
            result = execute(program,row['inputs'],resolver,namespace=namespace)
            if type(result) is not type(row['output']) or result != row['output']:
                return False
        return True
    except (InvalidInput, ValueError, IndexError, KeyError, TypeError):
        return False


def distinguish(best, competitor, inputs, *, resolver=None, namespace='default'):
    for probe in generated_probes(inputs, limit=256):
        try:
            a=execute(best,probe,resolver,namespace=namespace)
            b=execute(competitor,probe,resolver,namespace=namespace)
            if type(a) is not type(b) or a!=b:
                return {'inputs':probe,'best_output':a,'alternative_output':b}
        except (InvalidInput, IndexError, KeyError, ValueError):
            continue
    return None


def study(request, *, resolver=None):
    if not isinstance(request,dict):
        raise InvalidInput('skill study request must be object')
    namespace=namespace_name(request.get('namespace','default'))
    train, validation, schema=check_study(request.get('train'), request.get('validation'))
    proposals=request.get('proposals',[])
    if not isinstance(proposals,list) or len(proposals)>16:
        raise InvalidInput('proposals must be a list of at most 16 skill ASTs')
    max_candidates=request.get('max_candidates',3000)
    if type(max_candidates) is not int or not 1<=max_candidates<=5000:
        raise InvalidInput('max_candidates must be between 1 and 5000')
    # Proposals are searched first; validation is not consulted to rank candidates.
    pool=list(proposals)+list(enumerate_programs(schema))
    seen=set(); fits=[]; tested=0; truncated=False
    for program in pool:
        key=digest(program)
        if key in seen: continue
        seen.add(key)
        if tested>=max_candidates:
            truncated=True
            break
        tested+=1
        try:
            validate_program(program,schema=schema)
            if matches(program,train,resolver=resolver,namespace=namespace):
                fits.append(program)
        except (InvalidInput, KeyError, TypeError, ValueError):
            continue
    # Prefer fewer nodes rather than proposal order, deterministically.
    def size(program):
        def descend(obj):
            if isinstance(obj,dict): return 1+sum(descend(x) for x in obj.values() if isinstance(x,(dict,list)))
            if isinstance(obj,list): return sum(descend(x) for x in obj)
            return 0
        return descend(program)
    fits.sort(key=lambda x:(size(x),digest(x)))
    best=fits[0] if fits else None
    ambiguous=None
    if best:
        for competitor in fits[1:]:
            ambiguous=distinguish(best,competitor,train[0]['inputs'],resolver=resolver,namespace=namespace)
            if ambiguous: break
    # Evaluate held-aside validation only for the single selected candidate.
    passed=sum(matches(best,[r],resolver=resolver,namespace=namespace) for r in validation) if best else 0
    if not best: status='search_incomplete' if truncated else 'no_skill'
    elif truncated: status='search_incomplete'
    elif ambiguous: status='ambiguous'
    elif passed!=len(validation): status='validation_failed'
    else: status='locally_validated'
    return {'namespace':namespace,'status':status,'program':best,'schema':schema,
            'train_digest':digest(train),'validation_digest':digest(validation),
            'train_count':len(train),'validation_count':len(validation),'validation_passed':passed,
            'candidates_evaluated':tested,'fitting_candidates':len(fits),'search_truncated':truncated,
            'distinguishing_probe':ambiguous,
            'verification_scope':'deterministic bounded candidate search and caller-supplied disjoint validation, not independent holdout proof'}
