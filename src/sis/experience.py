"""Conservative transformation of caller-labeled execution episodes into skill studies.

Failure trajectories are not treated as success. A separately supplied correct
output is required to learn from a failed episode. Traces are bounded metadata,
NOT interpreted as program semantics or independent evidence.
"""
from .errors import InvalidInput
from .validation import check_inputs, check_scalar, canonical, digest


def transform_episodes(request):
    if not isinstance(request,dict):
        raise InvalidInput('experience request must be an object')
    result={k:v for k,v in request.items() if k in ('namespace','proposals','max_candidates','promote')}
    meta={'accepted':0,'corrected_failures':0,'trace_events':0}
    traces=[]
    for label in ('train','validation'):
        episodes=request.get(label+'_episodes')
        if not isinstance(episodes,list) or not 1<=len(episodes)<=256:
            raise InvalidInput(label+'_episodes must be a list of 1-256 records')
        output=[]
        for episode in episodes:
            if not isinstance(episode,dict) or set(episode)-{'inputs','observed_output','accepted','correct_output','trace'}:
                raise InvalidInput('unknown or invalid episode fields')
            if type(episode.get('accepted')) is not bool:
                raise InvalidInput('episode accepted must be a boolean')
            inputs=check_inputs(episode.get('inputs'))
            observed=check_scalar(episode.get('observed_output'))
            trace=episode.get('trace',[])
            if not isinstance(trace,list) or len(trace)>32 or any(not isinstance(x,str) or len(x)>128 for x in trace):
                raise InvalidInput('trace metadata must contain at most 32 short strings')
            traces.append(digest(trace));meta['trace_events']+=len(trace)
            if episode['accepted']:
                if 'correct_output' in episode:
                    raise InvalidInput('accepted episodes must not specify a correction')
                truth=observed
                meta['accepted']+=1
            else:
                if 'correct_output' not in episode:
                    raise InvalidInput('failed episode requires a trusted corrected output')
                truth=check_scalar(episode['correct_output'])
                if type(truth) is not type(observed) or truth==observed:
                    raise InvalidInput('failed episode correction must have same type and differ from observed output')
                meta['corrected_failures']+=1
            output.append({'inputs':inputs,'output':truth})
        result[label]=output
    meta['trace_digest']=digest(traces)
    meta['qualification']='labels and corrections are caller-supplied, not independently authenticated'
    meta['trace_usage']='traces are bounded metadata, not used as induction oracles'
    return result,meta
