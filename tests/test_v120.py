"""v1.2.0 regression tests: promotion trust boundary, checkpoints, batching."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sis.anchoring import export_anchor, verify_anchor_file
from sis.errors import InvalidInput, RuleRejected
from sis.induction import induce
from sis.service import Service

ROOT = Path(__file__).resolve().parents[1]

def study():
    return json.loads((ROOT / 'examples' / 'arithmetic_study.json').read_text())


class ModelRedirectTests(unittest.TestCase):
    def test_redirect_refused(self):
        from sis.model import _NoRedirect
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, 'redirect', {},
                                                           'https://other-server.example/v1/chat/completions'))


class PromotionRecomputeTests(unittest.TestCase):
    def setUp(self):
        self.s = Service(':memory:')
        self.case = study()
        self.induced = induce(self.case['train'], self.case['validation'],
                             namespace=self.case['namespace'])

    def tearDown(self):
        self.s.registry.close()

    def test_unsubstantiated_direct_promotion_is_rejected(self):
        with self.assertRaises(RuleRejected):
            self.s.registry.promote(self.induced)

    def test_valid_recomputation_allows_promotion(self):
        info = self.s.registry.promote(self.induced, train=self.case['train'],
                      validation=self.case['validation'])
        self.assertEqual(info['status'], 'active')
        self.assertTrue(self.s.registry.verify_audit()['valid'])

    def test_forged_counts_and_digest_denied(self):
        for key, value in [('validation_passed', 10000), ('validation_digest', 'f'*64),
                           ('search_truncated', True), ('status', 'provisional')]:
            with self.subTest(key=key):
                forged = dict(self.induced)
                forged[key] = value
                with self.assertRaises(RuleRejected):
                    self.s.registry.promote(forged, train=self.case['train'], validation=self.case['validation'])
        self.assertEqual(self.s.registry.verify_audit()['events_verified'], 0)

    def test_mismatched_ground_truth_denied(self):
        changed = study()
        changed['validation'][0]['output'] = 12345
        with self.assertRaises(RuleRejected):
            self.s.registry.promote(self.induced, train=changed['train'], validation=changed['validation'])

    def test_altered_search_budget_denied(self):
        with self.assertRaises(RuleRejected):
            self.s.registry.promote(self.induced, train=self.case['train'],
                                    validation=self.case['validation'], max_candidates=100)

    def test_service_study_can_promote_verified_result(self):
        req = study()
        out = self.s.study(req)
        self.assertEqual(out['promotion']['status'], 'active')
        self.assertEqual(self.s.predict({'namespace':req['namespace'],'inputs':{'a':10,'b':5}})['output'], 15)


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.s = Service(':memory:')
        self.s.study(study())

    def tearDown(self):
        self.s.registry.close()

    def test_batch_matches_individual_inference(self):
        batch = {'namespace': 'arithmetic_demo', 'inputs': [{'a':1,'b':2},{'a':-3,'b':15},{'a':6,'b':6}]}
        res = self.s.predict_batch(batch)
        self.assertEqual(res['count'],3)
        self.assertEqual(res['predicted'],3)
        self.assertEqual([r['output'] for r in res['results']], [3,12,12])

    def test_mixed_schema_abstains_per_record(self):
        res = self.s.predict_batch({'namespace':'arithmetic_demo','inputs':[{'a':1,'b':2},{'t':'x'}]})
        self.assertEqual(res['predicted'],1)
        self.assertEqual(res['abstained'],1)

    def test_batch_rejects_invalid_count_and_types(self):
        for items in ([], [{'a':1}]*65, 'abc', [{'a': object()}]):
            with self.subTest(items=str(items)[:30]), self.assertRaises(InvalidInput):
                self.s.predict_batch({'inputs':items})

    def test_missing_namespace_does_not_leak_rules(self):
        r=self.s.predict_batch({'inputs':[{'a':1,'b':2}]})
        self.assertEqual(r['predicted'],0)


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name)/'rules.db'
        self.anchor = Path(self.temp.name)/'checkpoint.json'
        self.s = Service(str(self.db))
        self.s.study(study())

    def tearDown(self):
        self.s.registry.close()
        self.temp.cleanup()

    def test_export_verify_and_no_overwrite(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SIS_ANCHOR_HMAC_KEY', None)
            checkpoint=export_anchor(self.s.registry,self.anchor)
            self.assertEqual(checkpoint['auth'],'unkeyed-sha256')
            self.assertTrue(verify_anchor_file(self.s.registry,self.anchor)['valid'])
            with self.assertRaises(FileExistsError):
                export_anchor(self.s.registry,self.anchor)

    def test_hmac_requires_correct_secret(self):
        with patch.dict(os.environ, {'SIS_ANCHOR_HMAC_KEY':'k'*48}):
            exported = export_anchor(self.s.registry,self.anchor)
            self.assertEqual(exported['auth'],'hmac-sha256')
            self.assertTrue(verify_anchor_file(self.s.registry,self.anchor)['valid'])
        with patch.dict(os.environ, {'SIS_ANCHOR_HMAC_KEY':'q'*48}):
            r = verify_anchor_file(self.s.registry,self.anchor)
            self.assertFalse(r['valid'])
            self.assertEqual(r['reason'],'checkpoint_authentication_failed')
        with patch.dict(os.environ, {'SIS_ANCHOR_HMAC_KEY':'short'}):
            with self.assertRaises(InvalidInput):
                verify_anchor_file(self.s.registry,self.anchor)

    def test_registry_truncation_even_when_consistent_detected(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SIS_ANCHOR_HMAC_KEY', None)
            export_anchor(self.s.registry,self.anchor)
            self.s.registry.conn.execute('DELETE FROM audit')
            self.s.registry.conn.execute('DELETE FROM rules')
            self.s.registry.conn.commit()
            # SQLite-only checks accept a rewritten empty history.
            self.assertTrue(self.s.registry.verify_audit()['valid'])
            response=verify_anchor_file(self.s.registry,self.anchor)
            self.assertFalse(response['valid'])
            self.assertEqual(response['reason'],'checkpoint_mismatch')

    def test_checksum_mutation_fails(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SIS_ANCHOR_HMAC_KEY', None)
            export_anchor(self.s.registry,self.anchor)
            obj=json.loads(self.anchor.read_text())
            obj['record']['sequence']=999
            self.anchor.write_text(json.dumps(obj))
            self.assertEqual(verify_anchor_file(self.s.registry,self.anchor)['reason'],
                             'checkpoint_authentication_failed')

    def test_new_events_preserve_anchored_prefix(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SIS_ANCHOR_HMAC_KEY', None)
            export_anchor(self.s.registry,self.anchor)
            rid=self.s.list_rules('arithmetic_demo')[0]['id']
            self.s.feedback({'namespace':'arithmetic_demo','rule_id':rid,
                            'inputs':{'a':1,'b':1},'observed_output':2})
            verified = verify_anchor_file(self.s.registry,self.anchor)
            self.assertTrue(verified['valid'])
            self.assertEqual(verified['new_events_after_anchor'],1)


if __name__ == '__main__':
    unittest.main()
