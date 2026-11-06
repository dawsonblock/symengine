"""v2.1 typed execution-trace -> verified procedural candidate induction.

This parser never executes trace text, Python, or model-provided tools. A
trace is a list of *declarative* SIS AST steps. Replaying a claimed trace
establishes only consistency with the interpreter, not real-world truth.

Train-derived candidate programs are checked independently against labeled
training and held-aside validation through the existing SkillCatalog.study().
Validation traces are intentionally disallowed to prevent proposal leakage.
"""

from .errors import InvalidInput
from .experience import transform_episodes
from .skill_program import execute, validate_program
from .validation import check_inputs, check_scalar, input_schema, digest, NAME

MAX_STEPS = 6
MAX_TRACE_ROWS = 32


def compile_trace(steps, inputs):
    """Check a fully specified trace and compile it to a bounded SIS AST.

    Each step is {name, expr, value}. `expr` sees original input fields and
    prior step names through SIS lexical variables. `value` is the claimed
    intermediate result; it is recomputed and checked with strict JSON types.
    """
    clean = check_inputs(inputs)
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise InvalidInput('steps must contain 1-6 typed program operations')
    names = set()
    intermediate = []
    for idx, step in enumerate(steps):
        if not isinstance(step, dict) or set(step) != {'name', 'expr', 'value'}:
            raise InvalidInput('trace steps require exactly name, expr, value')
        name = step['name']
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in names:
            raise InvalidInput('duplicate or invalid trace step name')
        names.add(name)
        value = check_scalar(step['value'])
        intermediate.append((name, step['expr'], value))
        # Each prefix is statically checked for references to undefined/future
        # locals; replay uses original inputs only, with no skill-call resolver.
        prefix = _as_program(intermediate)
        validate_program(prefix, schema=input_schema(clean))
        try:
            actual = execute(prefix, clean)
        except (InvalidInput, ValueError, IndexError, KeyError, TypeError) as exc:
            raise InvalidInput(f'trace step {idx} cannot be replayed') from exc
        if type(actual) is not type(value) or actual != value:
            raise InvalidInput(f'trace step {idx} value mismatches interpreter replay')
    return _as_program(intermediate)


def _as_program(intermediate):
    result = {'op':'var', 'name':intermediate[-1][0]}
    for name, expr, _ in reversed(intermediate):
        result = {'op':'let', 'name':name, 'value':expr, 'body':result}
    return result


def transform_traces(request):
    """Create a regular skill study plus descriptive trace-verification data.

    Only successful, interpreter-consistent TRAIN trajectories are proposals;
    failure corrections still require an external label. No trace step,
    including an apparently successful one, can be treated as a trusted oracle.
    """
    if not isinstance(request, dict):
        raise InvalidInput('trace request must be an object')
    allowed = {'namespace', 'train_episodes', 'validation_episodes',
               'max_candidates', 'promote'}
    if set(request) - allowed:
        raise InvalidInput('unknown trace-study request fields')
    if type(request.get('promote', False)) is not bool:
        raise InvalidInput('promote must be boolean')

    sanitized = {k:v for k,v in request.items() if k in ('namespace','max_candidates','promote')}
    trace_digests = []
    programs = {}
    checked_steps = 0
    successful_traces = 0
    rejected_traces = 0
    for split in ('train', 'validation'):
        episodes = request.get(split + '_episodes')
        if not isinstance(episodes, list) or not 1 <= len(episodes) <= 256:
            raise InvalidInput(split + '_episodes must contain 1-256 episodes')
        clean = []
        for episode in episodes:
            if not isinstance(episode, dict) or set(episode)-{'inputs','observed_output','accepted','correct_output','trace','steps'}:
                raise InvalidInput('invalid trace episode fields')
            if split == 'validation' and 'steps' in episode:
                raise InvalidInput('validation trace steps are forbidden to prevent hypothesis leakage')
            clean.append({key:value for key,value in episode.items() if key!='steps'})
            if split == 'train' and 'steps' in episode:
                if type(episode.get('accepted')) is not bool:
                    raise InvalidInput('trace accepted flag must be boolean')
                inputs = check_inputs(episode.get('inputs'))
                claimed = check_scalar(episode.get('observed_output'))
                program = compile_trace(episode['steps'], inputs)
                actual = execute(program, inputs)
                if type(actual) is not type(claimed) or actual != claimed:
                    raise InvalidInput('trace final value differs from observed_output')
                checked_steps += len(episode['steps'])
                trace_digests.append(digest({'inputs':inputs,'steps':episode['steps']}))
                if episode['accepted']:
                    programs[digest(program)] = program
                    successful_traces += 1
                else:
                    rejected_traces += 1
        sanitized[split + '_episodes'] = clean
    study_request, evidence = transform_episodes(sanitized)
    if len(programs) > 16:
        raise InvalidInput('trace study generated over 16 distinct candidate programs')
    # Never merge caller proposals with traced candidates: prevent laundering an
    # unexecuted hypothesis as a replay-verified execution procedure.
    study_request['proposals'] = [programs[k] for k in sorted(programs)]
    evidence.update({
        'trace_programs':len(programs),
        'successful_train_traces':successful_traces,
        'failed_train_traces_replayed_but_not_proposed':rejected_traces,
        'trace_steps_replayed':checked_steps,
        'trace_set_digest':digest(trace_digests),
        'trace_evidence':'locally replayed, caller-claimed; not independently authenticated',
        'validation_trace_usage':'forbidden; validation labels used only in existing acceptance gate',
    })
    return study_request, evidence
