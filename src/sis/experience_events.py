"""Instrumented, allowlisted, pure-tool execution captures for SIS v2.2.

This is an execution-boundary adapter, not a privileged witness or independent
truth source. Captured tool results are recomputed by the SIS interpreter.
Hash chaining detects partial edits, but anyone able to rewrite a complete
capture can recalculate the unkeyed hashes. External labels remain necessary.
"""
from dataclasses import dataclass
from .errors import InvalidInput
from .skill_program import execute
from .validation import NAME, check_inputs, check_scalar, digest, input_schema

MAX_EVENTS = 6  # v2.1 trace compiler's independent bound
TOOLS = frozenset({'add','sub','mul','min','max','eq','lt','gt','and','or','concat'})


@dataclass(frozen=True)
class Tracked:
    """A value plus its data-flow reference; only valid within one session."""
    session: object
    reference: dict
    value: object


class InstrumentedSession:
    def __init__(self, inputs):
        self.inputs = check_inputs(inputs)
        if any(isinstance(x, list) for x in self.inputs.values()):
            raise InvalidInput('v2.2 observed tool capture accepts scalar input fields only')
        self.events = []
        self.results = {}
        self.head = '0'*64

    def input(self, name):
        if name not in self.inputs:
            raise InvalidInput('unknown input reference')
        return Tracked(self, {'input':name}, self.inputs[name])

    def literal(self, value):
        return Tracked(self, {'literal':check_scalar(value)}, value)

    def previous(self, name):
        if name not in self.results:
            raise InvalidInput('unknown prior result')
        return Tracked(self, {'step':name}, self.results[name])

    def infer(self, value):
        """Recover provenance of a concrete tool argument, only if unambiguous.

        An equal input and prior intermediate, two equal inputs, or any equal
        candidates are ambiguous. Explicit input()/previous()/literal() resolves
        the ambiguity. Never claim a hidden data dependency from value equality.
        """
        value = check_scalar(value)
        references = []
        for name, known in self.inputs.items():
            if type(known) is type(value) and known == value:
                references.append({'input':name})
        for name, known in self.results.items():
            if type(known) is type(value) and known == value:
                references.append({'step':name})
        if len(references) > 1:
            raise InvalidInput('ambiguous provenance: explicitly bind the tool argument')
        return Tracked(self, references[0] if references else {'literal':value}, value)

    def _operand(self, value):
        if isinstance(value, Tracked):
            if value.session is not self:
                raise InvalidInput('cross-session references prohibited')
            ref = value.reference
            expected = self._resolve(ref)
            if type(expected) is not type(value.value) or expected != value.value:
                raise InvalidInput('tracked operand mutated')
            return value
        return self.infer(value)

    def _resolve(self, ref):
        if not isinstance(ref, dict) or len(ref) != 1:
            raise InvalidInput('operand reference must have exactly one source')
        if set(ref) == {'input'}:
            name = ref['input']
            if type(name) is not str or name not in self.inputs:
                raise InvalidInput('unknown input')
            return self.inputs[name]
        if set(ref) == {'step'}:
            name = ref['step']
            if type(name) is not str or name not in self.results:
                raise InvalidInput('unknown or forward step reference')
            return self.results[name]
        if set(ref) == {'literal'}:
            return check_scalar(ref['literal'])
        raise InvalidInput('unsupported operand source')

    def call(self, tool, *, left, right, step_id=None):
        if tool not in TOOLS or type(tool) is not str:
            raise InvalidInput('tool is not on the pure execution allowlist')
        if len(self.events) >= MAX_EVENTS:
            raise InvalidInput('too many tool operations')
        step_id = step_id or f'step_{len(self.events)+1}'
        if not isinstance(step_id, str) or not NAME.fullmatch(step_id) or step_id in self.results or step_id in self.inputs:
            raise InvalidInput('invalid, duplicate or conflicting step ID')
        lhs, rhs = self._operand(left), self._operand(right)
        values = {'left':lhs.value, 'right':rhs.value}
        # The operation is implemented by the existing bounded SIS interpreter.
        out = execute({'op':'binary','fn':tool,
                       'left':{'op':'input','name':'left'},
                       'right':{'op':'input','name':'right'}},values)
        body = {'id':step_id, 'tool':tool, 'bindings':{'left':lhs.reference,'right':rhs.reference},
                'resolved':values, 'result':out, 'prior':self.head}
        event = {**body, 'hash':digest(body)}
        self.events.append(event)
        self.results[step_id] = out
        self.head = event['hash']
        return Tracked(self, {'step':step_id}, out)

    def capture(self, output=None):
        if not self.events:
            raise InvalidInput('at least one executed tool call is required')
        if output is None:
            output = self.previous(self.events[-1]['id'])
        if not isinstance(output, Tracked) or output.session is not self:
            raise InvalidInput('output must reference a result recorded by this session')
        if set(output.reference) != {'step'}:
            raise InvalidInput('output must be a tracked step result')
        # Current trace compiler requires the final step to represent the answer.
        if output.reference['step'] != self.events[-1]['id']:
            raise InvalidInput('output must refer to the final step')
        return {'version':1, 'inputs':dict(self.inputs), 'events':[dict(e) for e in self.events],
                'observed_output':output.value, 'head':self.head,
                'capture_digest':digest({'inputs':self.inputs,'head':self.head,'output':output.value}),
                'evidence_scope':'local deterministic replay; no external attestation or outcome oracle'}


def replay_capture(capture):
    """Check all serialized records and replay the complete tool execution."""
    if not isinstance(capture, dict) or set(capture) != {'version','inputs','events','observed_output','head','capture_digest','evidence_scope'}:
        raise InvalidInput('invalid captured execution envelope')
    if type(capture['version']) is not int or capture['version'] != 1:
        raise InvalidInput('unsupported capture version')
    if capture['evidence_scope'] != 'local deterministic replay; no external attestation or outcome oracle':
        raise InvalidInput('capture evidence scope modified')
    session = InstrumentedSession(capture['inputs'])
    events = capture['events']
    if not isinstance(events,list) or not 1 <= len(events) <= MAX_EVENTS:
        raise InvalidInput('capture requires 1-6 tool events')
    from .trace_learning import compile_trace
    steps = []
    for index, event in enumerate(events):
        if not isinstance(event,dict) or set(event) != {'id','tool','bindings','resolved','result','prior','hash'}:
            raise InvalidInput('malformed tool event')
        if event['prior'] != session.head:
            raise InvalidInput('tool capture hash chain broken')
        body = {k:v for k,v in event.items() if k!='hash'}
        if event['hash'] != digest(body):
            raise InvalidInput('recorded tool event digest mismatch')
        bindings = event['bindings']
        if not isinstance(bindings,dict) or set(bindings) != {'left','right'}:
            raise InvalidInput('tool arguments missing provenance')
        lhs = session._resolve(bindings['left'])
        rhs = session._resolve(bindings['right'])
        if not isinstance(event['resolved'],dict) or set(event['resolved']) != {'left','right'}:
            raise InvalidInput('incorrect resolved argument shape')
        for k,value in [('left',lhs),('right',rhs)]:
            actual = event['resolved'][k]
            if type(actual) is not type(value) or actual != value:
                raise InvalidInput('resolved value differs from provenance')
        val = session.call(event['tool'], left=Tracked(session,bindings['left'],lhs),
                           right=Tracked(session,bindings['right'],rhs), step_id=event['id'])
        if type(val.value) is not type(event['result']) or val.value != event['result']:
            raise InvalidInput('tool result differs from replay')
        if session.events[-1] != event:
            raise InvalidInput('tool event mismatch after replay')
        def expr(ref):
            if set(ref)=={'input'}: return {'op':'input','name':ref['input']}
            if set(ref)=={'step'}: return {'op':'var','name':ref['step']}
            return {'op':'const','value':ref['literal']}
        steps.append({'name':event['id'], 'expr':{'op':'binary','fn':event['tool'],
                         'left':expr(bindings['left']),'right':expr(bindings['right'])},
                      'value':event['result']})
    out = check_scalar(capture['observed_output'])
    if type(out) is not type(session.events[-1]['result']) or out != session.events[-1]['result']:
        raise InvalidInput('captured answer differs from final executed operation')
    if capture['head'] != session.head or capture['capture_digest'] != digest({'inputs':session.inputs,'head':session.head,'output':out}):
        raise InvalidInput('capture envelope digest mismatch')
    program = compile_trace(steps,session.inputs)
    return {'inputs':session.inputs,'steps':steps,'observed_output':out,
            'program':program,'fingerprint':digest(program),'capture_digest':capture['capture_digest'],
            'events_replayed':len(events)}


def capture_plan(request):
    """Replayable CLI example adapter. Real agents should use InstrumentedSession.call."""
    if not isinstance(request,dict) or set(request) != {'inputs','calls'}:
        raise InvalidInput('capture plan requires exactly inputs and calls')
    session=InstrumentedSession(request['inputs'])
    calls=request['calls']
    if not isinstance(calls,list) or not 1 <= len(calls) <= MAX_EVENTS:
        raise InvalidInput('plan must contain 1-6 calls')
    def binding(spec):
        if not isinstance(spec,dict) or len(spec)!=1:
            raise InvalidInput('plan operand must reference input, prior step, or literal')
        if set(spec)=={'input'}: return session.input(spec['input'])
        if set(spec)=={'step'}: return session.previous(spec['step'])
        if set(spec)=={'literal'}: return session.literal(spec['literal'])
        raise InvalidInput('unsupported plan binding')
    for call in calls:
        if not isinstance(call,dict) or set(call) != {'id','tool','left','right'}:
            raise InvalidInput('plan tool call requires id, tool, left, right')
        session.call(call['tool'],left=binding(call['left']),right=binding(call['right']),step_id=call['id'])
    return session.capture()
