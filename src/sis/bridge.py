"""Small OpenAI-tool-call-style dispatcher for any agent that can call Python.

Read-only by design. Rule promotion requires a separately controlled Service.study.
"""
import json
from .errors import InvalidInput
from .service import Service
from .tooling import definitions


class ToolBridge:
    def __init__(self, service: Service):
        self.service = service

    def tools(self):
        return definitions()

    def invoke(self, name, arguments):
        if not isinstance(name, str):
            raise InvalidInput('tool name must be a string')
        if isinstance(arguments, str):
            if len(arguments) > 128_000:
                raise InvalidInput('tool arguments exceed 128 KiB')
            try:
                arguments = json.loads(arguments)
            except ValueError as exc:
                raise InvalidInput('tool arguments are not JSON') from exc
        if not isinstance(arguments, dict):
            raise InvalidInput('tool arguments must be an object')
        if name == 'sis_predict':
            if set(arguments) - {'namespace','inputs','rule_id'}:
                raise InvalidInput('unknown sis_predict arguments')
            return self.service.predict(arguments)
        if name == 'sis_transfer':
            if set(arguments) - {'source_namespace','rule_id','field_map','inputs'}:
                raise InvalidInput('unknown sis_transfer arguments')
            return self.service.transfer(arguments)
        if name == 'sis_suggest_queries':
            if set(arguments) - {'train','limit'}:
                raise InvalidInput('unknown sis_suggest_queries arguments')
            return self.service.query(arguments)
        if name == 'sis_skill_predict':
            if set(arguments) - {'namespace','inputs','skill_id'}:
                raise InvalidInput('unknown sis_skill_predict arguments')
            return self.service.skill_predict(arguments)
        if name == 'sis_workflow_predict':
            if set(arguments) - {'namespace','data','workflow_id'}:
                raise InvalidInput('unknown sis_workflow_predict arguments')
            return self.service.workflow_predict(arguments)
        if name == 'sis_code_preview':
            if set(arguments)-{'namespace','recipe_id','source','filename','function'}:
                raise InvalidInput('unknown sis_code_preview arguments')
            return self.service.code_preview(arguments)
        raise InvalidInput('unknown or disallowed tool: '+name[:64])
