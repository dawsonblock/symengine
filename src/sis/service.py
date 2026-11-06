"""API-agnostic orchestration. Induction results are never accepted from clients as evidence."""
from .errors import InvalidInput
from .induction import induce
from .active import suggest_queries
from .evaluation import benchmark as run_benchmark
from .tooling import definitions
from .model import CompatibleLLM
from .registry import Registry
from .transfer import transfer_result, map_expression
from .validation import check_inputs
from .skill_registry import SkillCatalog
from .workflow_registry import WorkflowCatalog
from .code_registry import CodeCatalog


class Service:
    def __init__(self, db_path="sis.sqlite3", *, enable_llm=False):
        self.registry = Registry(db_path)
        self.skills = SkillCatalog(self.registry.conn, self.registry.lock)
        self.workflows = WorkflowCatalog(self.registry.conn, self.registry.lock)
        self.code = CodeCatalog(self.registry.conn, self.registry.lock)
        self.enable_llm = enable_llm

    def study(self, request):
        if not isinstance(request, dict):
            raise InvalidInput("request must be a JSON object")
        train, validation = request.get("train"), request.get("validation", [])
        proposals = []
        if request.get("use_llm"):
            if not self.enable_llm:
                raise InvalidInput("LLM calls are disabled; opt in with SIS_ENABLE_LLM=1")
            # Explicit opt-in required for every study; train data is transmitted externally.
            from .validation import check_examples
            checked = check_examples(train, minimum=3)
            proposals.append(CompatibleLLM().propose(checked))
        result = induce(train, validation, namespace=request.get("namespace", "default"),
                        max_candidates=request.get("max_candidates", 12000), proposals=proposals,
                        use_z3=request.get("use_z3", False))
        if request.get("promote", False):
            if result["status"] == "locally_validated":
                result["promotion"] = self.registry.promote(
                    result, train=train, validation=validation,
                    max_candidates=request.get("max_candidates", 12000),
                    proposals=proposals, use_z3=request.get("use_z3", False))
            else:
                result["promotion"] = {"status": "rejected", "reason": "promotion requires unambiguous locally validated evidence"}
        return result

    def query(self, request):
        if not isinstance(request, dict):
            raise InvalidInput("request must be a JSON object")
        return suggest_queries(request.get("train"), max_candidates=request.get("max_candidates",12000),
                               max_hypotheses=request.get("max_hypotheses",48),
                               max_probes=request.get("max_probes",256),limit=request.get("limit",5))

    def benchmark(self, request):
        # NEVER persists its holdout labels or promotes any rule.
        return run_benchmark(request)

    def tools(self):
        return definitions()

    def retire(self, request):
        if not isinstance(request, dict) or not isinstance(request.get('rule_id'), str):
            raise InvalidInput('retire requires rule_id')
        return self.registry.retire(request.get('namespace','default'),request['rule_id'])

    def predict(self, request):
        if not isinstance(request, dict):
            raise InvalidInput("request must be an object")
        return self.registry.predict(request.get("namespace", "default"), request["inputs"], request.get("rule_id"))

    def predict_batch(self, request):
        """Bounded read-only batch prediction with per-item abstention semantics."""
        if not isinstance(request, dict):
            raise InvalidInput("batch request must be an object")
        records = request.get("inputs")
        if not isinstance(records, list) or not (1 <= len(records) <= 64):
            raise InvalidInput("inputs must be a list of 1-64 input objects")
        from .validation import check_inputs
        checked = [check_inputs(item) for item in records]  # fail before any inference
        namespace = request.get("namespace", "default")
        rule_id = request.get("rule_id")
        if rule_id is not None and not isinstance(rule_id, str):
            raise InvalidInput("rule_id must be a string")
        results = [self.registry.predict(namespace, item, rule_id) for item in checked]
        return {"namespace": namespace, "count": len(results), "results": results,
                "predicted": sum(r["status"] == "predicted" for r in results),
                "abstained": sum(r["status"] == "abstain" for r in results)}

    def transfer(self, request):
        """Read-only cross-schema inference; target rule is NEVER promoted."""
        if not isinstance(request, dict):
            raise InvalidInput('transfer request must be an object')
        namespace = request.get('source_namespace', 'default')
        rid = request.get('rule_id')
        if not isinstance(rid, str):
            raise InvalidInput('transfer requires exact source rule_id')
        inputs = check_inputs(request.get('inputs'))
        source_rules = [x for x in self.registry.list_rules(namespace) if x['id'] == rid]
        if not source_rules:
            raise InvalidInput('source rule does not exist or is not active')
        return transfer_result(source_rules[0], inputs, request.get('field_map'))

    def transfer_batch(self, request):
        """Read-only, bounded, schema-checked cross-task batch."""
        if not isinstance(request, dict):
            raise InvalidInput('transfer batch request must be an object')
        records = request.get('inputs')
        if not isinstance(records, list) or not 1 <= len(records) <= 64:
            raise InvalidInput('inputs must contain 1-64 target records')
        checked = [check_inputs(x) for x in records]
        namespace = request.get('source_namespace','default')
        rid = request.get('rule_id')
        if not isinstance(rid, str):
            raise InvalidInput('transfer requires exact source rule_id')
        source_rules = [x for x in self.registry.list_rules(namespace) if x['id'] == rid]
        if not source_rules:
            raise InvalidInput('source rule does not exist or is not active')
        source = source_rules[0]
        mapping = request.get('field_map')
        # Validate ALL records before producing any output.
        for item in checked:
            map_expression(source['rule'],source['schema'],item,mapping)
        results = [transfer_result(source,item,mapping) for item in checked]
        return {'count':len(results),'results':results,
                'predicted':sum(r['status']=='predicted' for r in results),
                'abstained':sum(r['status']=='abstain' for r in results),
                'qualification':'unvalidated_target_hypothesis'}

    def chat(self, request):
        if not self.enable_llm:
            raise InvalidInput("LLM calls are disabled; enable SIS_ENABLE_LLM=1")
        if not isinstance(request, dict) or not isinstance(request.get("question"), str):
            raise InvalidInput("chat request requires a question")
        result = self.predict(request)
        if result["status"] != "predicted":
            return {"status": "abstain", "registry_prediction": result,
                    "reason": "No grounded symbolic output; external model was not called"}
        return CompatibleLLM().answer_with_rule(request["question"], result)

    def feedback(self, request):
        if not isinstance(request, dict):
            raise InvalidInput("request must be an object")
        return self.registry.feedback(request.get("namespace", "default"), request["rule_id"],
                                      request["inputs"], request["observed_output"])

    def list_rules(self, namespace="default", include_suspended=False):
        return self.registry.list_rules(namespace, include_suspended)

    # v1.7 governed procedural skill subsystem, isolated from v1.0-1.6 rule tables.
    def skill_study(self, request):
        return self.skills.study(request)

    def skill_predict(self, request):
        return self.skills.predict(request)

    def skill_feedback(self, request):
        return self.skills.feedback(request)

    def skill_retire(self, request):
        return self.skills.retire(request)

    def skill_benchmark(self, request):
        return self.skills.benchmark(request)

    def skill_list(self, namespace='default', include_inactive=False):
        return self.skills.list(namespace, include_inactive)

    def skill_freeze(self, namespace, skill_id):
        return self.skills.freeze(namespace, skill_id)

    def skill_audit(self):
        return self.skills.verify()

    def experience_study(self, request):
        from .experience import transform_episodes
        normalized, metadata = transform_episodes(request)
        result = self.skills.study(normalized)
        result['experience'] = metadata
        return result

    def trace_study(self, request):
        """Offline typed trace induction; never exposed through the model tool bridge."""
        from .trace_learning import transform_traces
        normalized, metadata = transform_traces(request)
        result = self.skills.study(normalized)
        result['trace_learning'] = metadata
        return result

    # v2.2 observed-tool experience abstraction, kept outside the LLM tool bridge.
    def experience_capture(self, request):
        from .experience_events import capture_plan
        return capture_plan(request)

    def experience_induce(self, request):
        from .abstraction_engine import abstract_captures
        normalized, evidence = abstract_captures(request)
        result = self.trace_study(normalized)
        result['abstraction'] = evidence
        return result

    # v2.3: bounded tabular workflow learning; caller labels remain untrusted.
    def workflow_capture(self,request):
        from .workflow_engine import capture_plan
        return capture_plan(request)

    def workflow_study(self,request):
        return self.workflows.study(request)

    def workflow_predict(self,request):
        return self.workflows.predict(request)

    def workflow_list(self,namespace='default'):
        return self.workflows.list(namespace)

    def workflow_audit(self):
        return self.workflows.verify()

    def workflow_retire(self,request):
        return self.workflows.retire(request)

    # v2.4: operator-gated learning of bounded pure code edits.
    def code_capture(self, request):
        from .code_learning import capture_repair
        return capture_repair(request)

    def code_study(self, request):
        return self.code.study(request)

    def code_preview(self, request):
        return self.code.preview(request)

    def code_list(self, namespace='default'):
        return self.code.list(namespace)

    def code_retire(self, request):
        return self.code.retire(request)

    def code_audit(self):
        return self.code.verify()
