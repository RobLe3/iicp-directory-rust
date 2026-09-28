"""Negative controls for the installed TCP discovery observer; no admission."""
import copy
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
import pre1_installed_discovery as probe


class InstalledDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.contract = probe.read_contract(Path(__file__).resolve().parents[1] / 'parity/behavior-contract-v1.json')

    def response(self, ids=None, scores=None):
        ids = ['fixture-http-ranking'] if ids is None else ids
        scores = [0.878] if scores is None else scores
        return 200, {'count': len(ids), 'nodes': [
            {'node_id': key, 'score': score} for key, score in zip(ids, scores)]}

    def test_fixture_bytes_are_pinned(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'fixture.json'; path.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'fixture differs'): probe.read_contract(path)
            link = Path(root) / 'link'; link.symlink_to(path)
            with self.assertRaises(ValueError): probe.read_contract(link)

    def test_limit_is_checked_against_actual_order(self):
        case = self.contract['eligibility_cases'][0]
        request = Mock(side_effect=[self.response(['eligible', 'fallback-capability'], [0.9, 0.8]),
                                   self.response(['eligible'], [0.9])])
        result = probe.observe_selection(request, case, 'eligibility_cases')
        self.assertEqual(result['eligible_ids'], ['eligible', 'fallback-capability'])
        self.assertIn('limit=1', request.call_args.args[0])
        request = Mock(side_effect=[self.response(['eligible', 'fallback-capability'], [0.9, 0.8]),
                                   self.response(['fallback-capability'], [0.8])])
        with self.assertRaisesRegex(ValueError, 'limit differs'):
            probe.observe_selection(request, case, 'eligibility_cases')

    def test_missing_model_is_empty_not_primitive_score(self):
        case = self.contract['ranking_cases'][2]
        value = probe.observe_selection(Mock(side_effect=[self.response([], []), self.response([], [])]), case, 'ranking_cases')
        self.assertEqual(value['scores'], [])
        with self.assertRaisesRegex(ValueError, 'eligibility differs'):
            probe.observe_selection(Mock(return_value=self.response(scores=[0.578])), case, 'ranking_cases')

    def test_ranking_must_match_actual_contract(self):
        case = self.contract['ranking_cases'][0]
        with self.assertRaisesRegex(ValueError, 'ranking differs'):
            probe.observe_selection(Mock(return_value=self.response(scores=[0.888])), case, 'ranking_cases')

    def test_projection_rejects_duplicate_bad_count_nonfinite_and_boolean(self):
        for result in (self.response(['a', 'a'], [0.9, 0.8]), self.response(scores=[float('nan')]),
                       self.response(scores=[True]), self.response(scores=[1.1]),
                       (401, {'count': 0, 'nodes': []}), (200, {'count': True, 'nodes': []}),
                       self.response(['a', 'b'], [0.5, 0.9])):
            with self.subTest(result=result), self.assertRaises(ValueError): probe.selection_values(*result)

    def test_sql_literals_do_not_interpolate_fixture_strings(self):
        sql = Mock(); probe.seed_node(sql, {'id': "x';DELETE FROM nodes;--", 'models': ['model-a']})
        query = sql.call_args.args[0]
        self.assertNotIn("x';DELETE", query)
        self.assertIn('CONVERT(0x', query)
        self.assertIn('NOW()', query)
        for value in (float('nan'), float('inf'), object()):
            with self.assertRaises(ValueError): probe.literal(value)

    def pricing(self, actual, status=201):
        return Mock(side_effect=[(status, {'node_id': 'fixture-http-price'}),
            (200, {'count': 1, 'nodes': [{'node_id': 'fixture-http-price', 'score': 0.5,
                'pricing': {'credit_cost_multiplier': actual}}]})])

    def test_pricing_reads_discovery_not_registration_payload(self):
        case = self.contract['pricing_cases'][0]
        request = self.pricing(0.15)
        self.assertEqual(probe.observe_pricing(request, case), 0.15)
        self.assertEqual(request.call_args_list[0].args[1]['pricing']['credit_cost_multiplier'], 100.0)
        self.assertEqual(request.call_args_list[0].args[1]['transport_method'], 'direct_ipv4')
        self.assertTrue(request.call_args_list[1].args[0].startswith('/v1/discover?'))

    def test_pricing_failure_never_becomes_pass(self):
        case = self.contract['pricing_cases'][0]
        for actual in (True, float('nan'), 100.0, None):
            with self.assertRaises(ValueError): probe.observe_pricing(self.pricing(actual), case)
        with self.assertRaises(ValueError): probe.observe_pricing(self.pricing(0.15, 422), case)

    def test_anonymous_restricted_discovery_must_fail(self):
        with self.assertRaisesRegex(ValueError, 'anonymous discovery admitted'):
            probe.observe(Mock(), Mock(return_value=(200, {})), Mock(), Mock(), self.contract, 'restricted')
        with self.assertRaises(ValueError):
            probe.observe(Mock(), Mock(), Mock(), Mock(), self.contract, 'other')

    def test_all_observations_are_runtime_results_with_bounded_scope(self):
        sql, membership = Mock(), Mock()
        import unittest.mock as mock
        projection = {'eligible_ids': [], 'recommendation_order': [], 'scores': []}
        with mock.patch.object(probe, 'observe_selection', return_value=projection), \
             mock.patch.object(probe, 'observe_pricing', side_effect=[0.15, 3.0, 19.5, 0.1]):
            result = probe.observe(Mock(), Mock(return_value=(401, {})), sql, membership, self.contract, 'restricted')
        self.assertEqual(len(result['observations']), 9)
        self.assertIs(result['qualification_credit'], False)
        self.assertIs(result['production_endpoint_validation'], False)
        self.assertEqual(membership.call_count, 9)
        self.assertEqual(sql.call_args.args[0], 'DELETE FROM capabilities; DELETE FROM availability_windows; DELETE FROM nodes;')


if __name__ == '__main__': unittest.main()
