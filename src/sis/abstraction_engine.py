"""Conservative abstraction from replayed real tool captures to v2.1 skills.

Group only identical generalized data-flow programs. A missing dependency is
not guessed; value coincidence alone is not proof. Caller-provided labels
remain explicitly separate from tool execution results.
"""
from .errors import InvalidInput
from .experience_events import replay_capture
from .validation import check_inputs,check_scalar,digest,input_schema


def abstract_captures(request):
    if not isinstance(request,dict) or set(request)-{'namespace','promote','max_candidates','train_captures','validation'}:
        raise InvalidInput('invalid experience-abstraction request')
    train=request.get('train_captures')
    validation=request.get('validation')
    if not isinstance(train,list) or not 3 <= len(train) <= 32:
        raise InvalidInput('train_captures must contain 3-32 labeled records')
    if not isinstance(validation,list) or not 2 <= len(validation) <= 256:
        raise InvalidInput('validation requires 2-256 independently labeled records')
    if type(request.get('promote',False)) is not bool:
        raise InvalidInput('promote must be boolean')
    train_episodes=[]
    groups={}
    digests=[]
    seen_inputs=set()
    schema=None
    train_success=0
    train_fail=0
    for row in train:
        if not isinstance(row,dict) or set(row)-{'capture','accepted','correct_output'} or not {'capture','accepted'}<=set(row):
            raise InvalidInput('train record must include capture and accepted outcome')
        if type(row['accepted']) is not bool:
            raise InvalidInput('accepted must be a Boolean, independently reported outcome')
        replayed=replay_capture(row['capture'])
        inputs=replayed['inputs']
        this_schema=input_schema(inputs)
        if schema is None: schema=this_schema
        if schema!=this_schema:
            raise InvalidInput('all episodes must use one input schema')
        fingerprint=digest(inputs)
        if fingerprint in seen_inputs:
            raise InvalidInput('duplicate training inputs')
        seen_inputs.add(fingerprint)
        episode={'inputs':inputs,'accepted':row['accepted'],
                 'observed_output':replayed['observed_output'], 'steps':replayed['steps']}
        if row['accepted']:
            if 'correct_output' in row:
                raise InvalidInput('accepted captures cannot contain corrected outputs')
            train_success+=1
            groups.setdefault(replayed['fingerprint'],[]).append(replayed)
        else:
            if 'correct_output' not in row:
                raise InvalidInput('failed capture requires independent corrected output')
            episode['correct_output']=check_scalar(row['correct_output'])
            train_fail+=1
        train_episodes.append(episode)
        digests.append(replayed['capture_digest'])
    # Fail closed on mixed successful procedures rather than picking the one
    # that performed best on the validation labels.
    if len(groups)!=1:
        raise InvalidInput('successful executions disagree on generalized program; split task families first')
    if train_success<3:
        raise InvalidInput('at least three successful consistent traces required')
    val_eps=[]
    for row in validation:
        if not isinstance(row,dict) or set(row)!={'inputs','output'}:
            raise InvalidInput('validation records require exactly inputs and output')
        inputs=check_inputs(row['inputs'])
        if input_schema(inputs)!=schema:
            raise InvalidInput('validation schema differs from captured task')
        if digest(inputs) in seen_inputs:
            raise InvalidInput('validation input overlaps training inputs')
        seen_inputs.add(digest(inputs))
        val_eps.append({'inputs':inputs,'accepted':True,
                        'observed_output':check_scalar(row['output'])})
    return {'namespace':request.get('namespace','default'),'promote':request.get('promote',False),
            'max_candidates':request.get('max_candidates',3000),
            'train_episodes':train_episodes,'validation_episodes':val_eps}, {
            'captures_replayed':len(train),'successful_captures':train_success,
            'corrected_failures':train_fail,'distinct_successful_programs':len(groups),
            'program_fingerprint':next(iter(groups)),
            'capture_set_digest':digest(digests),
            'trust_boundary':'tools replayed locally; correctness labels supplied externally; no independent attestation',
            'abstraction':'typed data-flow generalization from explicitly tracked arguments',
            'validation_isolation':'validation cases contain no tool traces or proposals'}
