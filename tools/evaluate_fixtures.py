#!/usr/bin/env python3
"""Local synthetic regression only. Not third-party holdout evidence."""
import json
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from sis.service import Service

ROOT = Path(__file__).resolve().parents[1]

def main():
    with tempfile.TemporaryDirectory() as temp:
        service = Service(str(Path(temp) / 'eval.db'))
        results = {}
        try:
            for name in ('arithmetic_study.json', 'sequence_study.json', 'ambiguous_study.json'):
                req = json.loads((ROOT / 'examples' / name).read_text('utf8'))
                result = service.study(req)
                status = result['status']
                results[name] = {'status': status, 'validation_passed': result['validation_passed'],
                                 'validation_total': result['validation_count'],
                                 'promoted': result.get('promotion', {}).get('status') == 'active',
                                 'candidates_evaluated': result['candidates_evaluated']}
            assert results['arithmetic_study.json']['promoted']
            assert results['sequence_study.json']['promoted']
            assert not results['ambiguous_study.json']['promoted']
            print(json.dumps({'evidence_type':'local_synthetic_demo', 'results':results,
                              'caution':'Not an independent holdout, transfer-learning, or LLM improvement experiment.'}, indent=2))
        finally:
            service.registry.close()

if __name__ == '__main__':
    main()
