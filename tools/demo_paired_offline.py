#!/usr/bin/env python3
"""Deterministic, fully OFFLINE fake model integration demonstration (NOT an LLM benchmark)."""
import json
import tempfile
from pathlib import Path
from sis.paired_eval import run_paired
from sis.service import Service


class FakeModel:
    def complete_with_metadata(self, messages, max_tokens=128):
        data = json.loads(messages[-1]['content'])
        inputs = data['task_inputs']
        prediction = data.get('sis_read_only_prediction', {})
        answer = prediction['answer'] if prediction.get('status') == 'predicted' else -1
        return json.dumps({'abstain':False,'answer':answer}), {'prompt_tokens':20,'completion_tokens':8}


def main():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        service = Service(Path(tmp)/'knowledge.sqlite3')
        try:
            study = json.loads((root/'examples/arithmetic_study.json').read_text())
            assert service.study(study)['promotion']['status'] == 'active'
            data = json.loads((root/'examples/paired_eval_synthetic.json').read_text())
            result = run_paired(data, FakeModel(), service, model_label='FAKE_DETERMINISTIC_FIXTURE')
            print(json.dumps({'model':result['model'], 'status':result['status'],
                              'paired':result['paired'], 'warning':'SYNTHETIC FAKE MODEL ONLY: not LLM evaluation'},indent=2))
        finally:
            service.registry.close()


if __name__ == '__main__':
    main()
