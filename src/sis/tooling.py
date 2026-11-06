"""Portable JSON tool schemas; wire into an agent framework of your choice."""

TOOLS = [
    {
        'type': 'function',
        'function': {
            'name': 'sis_predict',
            'description': 'Look up locally validated bounded symbolic rules. Returns abstain on uncertainty.',
            'parameters': {
                'type': 'object', 'additionalProperties': False,
                'properties': {
                    'namespace': {'type': 'string'},
                    'inputs': {'type': 'object', 'description': 'Typed inputs matching registered rule schema'},
                    'rule_id': {'type': 'string'},
                },
                'required': ['inputs'],
            },
        },
    },
    {
        'type': 'function',
        'function': {
            'name':'sis_transfer',
            'description':'Apply an active, locally validated source rule to a manually mapped target schema. Target accuracy is NOT verified. Read-only.',
            'parameters': {
                'type':'object','additionalProperties':False,
                'properties':{
                    'source_namespace':{'type':'string'},
                    'rule_id':{'type':'string'},
                    'field_map':{'type':'object','additionalProperties':{'type':'string'}},
                    'inputs':{'type':'object'},
                },
                'required':['source_namespace','rule_id','field_map','inputs'],
            },
        },
    },
    {
        'type': 'function',
        'function': {
            'name': 'sis_suggest_queries',
            'description': 'Propose UNLABELED experiments to distinguish symbolic hypotheses. Obtain real labels separately.',
            'parameters': {
                'type': 'object', 'additionalProperties': False,
                'properties': {
                    'train': {'type': 'array', 'items': {'type': 'object'}},
                    'limit': {'type': 'integer', 'minimum': 1, 'maximum': 32},
                }, 'required': ['train'],
            },
        },
    },
    {
        'type': 'function',
        'function': {
            'name': 'sis_skill_predict',
            'description': 'Run a locally validated, active, bounded procedural skill; read-only and abstain-capable.',
            'parameters': {
                'type': 'object', 'additionalProperties': False,
                'properties': {
                    'namespace': {'type': 'string'},
                    'inputs': {'type': 'object'},
                    'skill_id': {'type': 'string'},
                },
                'required': ['inputs'],
            },
        },
    },
    {
        'type':'function',
        'function':{
            'name':'sis_workflow_predict',
            'description':'Execute a locally validated read-only tabular workflow. Results are bounded and may abstain; never changes the catalog.',
            'parameters':{
                'type':'object','additionalProperties':False,
                'properties':{
                    'namespace':{'type':'string'},
                    'workflow_id':{'type':'string'},
                    'data':{'type':'object','additionalProperties':False,
                        'properties':{'rows':{'type':'array','items':{'type':'object'}}},
                        'required':['rows']}
                },'required':['data']
            }
        }
    },
    {
        'type':'function',
        'function':{
            'name':'sis_code_preview',
            'description':'Preview an active, locally checked bounded Python AST repair. Read-only: no patch applied, no Python executed.',
            'parameters':{'type':'object','additionalProperties':False,
                'properties':{
                    'namespace':{'type':'string'},'recipe_id':{'type':'string'},
                    'source':{'type':'string'},'filename':{'type':'string'},'function':{'type':'string'}
                },'required':['source','filename','function']}
        }
    }

]


def definitions():
    # Copy before returning so callers cannot modify library constant.
    import copy
    return copy.deepcopy(TOOLS)
