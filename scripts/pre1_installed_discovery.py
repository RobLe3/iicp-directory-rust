"""Installed Rust TCP observations using the owning probe's isolated SQL/runtime.

No server, database, or admission authority is created here. The owning adapter
supplies the actual installed listener and restricted membership issuer.
"""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path
from urllib.parse import urlencode

FIXTURE_SHA256 = '61f84608db554cf2a3da02c46e01f27c77e57c9553ade0da8c5a017860d73f3f'
INTENT = 'urn:iicp:intent:llm:chat:v1'


def read_contract(path):
    path = Path(path)
    raw = path.read_bytes()
    if path.is_symlink() or hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('installed discovery fixture differs')
    return json.loads(raw)


def literal(value):
    if value is None:
        return 'NULL'
    if type(value) in (int, float):
        if not math.isfinite(value):
            raise ValueError('nonfinite fixture SQL value')
        return str(value)
    if type(value) is bool:
        return '1' if value else '0'
    if isinstance(value, (dict, list)):
        value = json.dumps(value, separators=(',', ':'))
    if not isinstance(value, str):
        raise ValueError('unsupported fixture SQL value')
    return "CONVERT(0x" + value.encode().hex() + " USING utf8mb4)"


def clear_nodes(sql):
    # Only called inside the owning disposable fixture database.
    sql('DELETE FROM capabilities; DELETE FROM availability_windows; DELETE FROM nodes;')


def seed_node(sql, node):
    values = {
        'id': node['id'], 'endpoint': 'http://127.0.0.1:1', 'region': node.get('region', 'eu-west'),
        'available': True, 'status': 'active', 'public_reachable': True,
        'node_token_hash': 'synthetic-unused-fixture-hash',
        'load': node.get('load', 0.2), 'active_jobs': node.get('active_jobs', 2),
        'max_concurrent': node.get('max_concurrent', 10), 'tokens_per_min': 10000,
        'reputation_score': node.get('reputation') if node.get('reputation') is not None else 0.5,
        'tasks_total': node.get('tasks', 0), 'health_models': node.get('health_models'),
        'backend': node.get('backend'), 'backend_stability':
            {'backend_state': node['backend_state'], 'reason_class': 'ok'} if 'backend_state' in node else None,
        'pricing_credits_per_1000': node.get('pricing'),
        'sdk_version': '0.7.68' if node.get('sdk_current', True) else None,
        'cx_public_key': {'fixture': True} if node.get('cx_key', True) else None,
    }
    columns = ','.join('`' + key + '`' for key in values)
    sql('INSERT INTO nodes (' + columns + ',last_seen) VALUES (' +
        ','.join(literal(value) for value in values.values()) + ',NOW());' +
        'INSERT INTO capabilities (node_id,intent,models,max_tokens) VALUES (' +
        ','.join(literal(value) for value in (node['id'], INTENT, node['models'], 4096)) + ');')


def selection_values(status, body):
    if status != 200 or not isinstance(body, dict) or 'error' in body:
        raise ValueError('installed discovery response differs')
    rows = body.get('nodes')
    if not isinstance(rows, list) or type(body.get('count')) is not int or body['count'] != len(rows):
        raise ValueError('installed discovery count differs')
    ids = [row['node_id'] for row in rows]
    scores = [row['score'] for row in rows]
    if (any(not isinstance(value, str) for value in ids) or len(set(ids)) != len(ids)
            or any(type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1 for value in scores)
            or scores != sorted(scores, reverse=True)):
        raise ValueError('installed recommendation projection differs')
    return ids, scores


def observe_selection(request, case, group):
    query = {'intent': INTENT, 'limit': 50}
    for field in ('model', 'qos', 'min_reputation', 'region'):
        value = case.get('requested_' + field, case.get(field))
        if value is not None:
            query[field] = value
    ids, scores = selection_values(*request('/v1/discover?' + urlencode(query)))
    expected = (sorted(case['expected_ids']) if group == 'eligibility_cases' else
                [] if case['requested_model'] == 'missing-model' else ['fixture-http-ranking'])
    if sorted(ids) != expected:
        raise ValueError('installed eligibility differs: ' + case['name'])
    if group == 'ranking_cases' and ids and scores != [case['expected']]:
        raise ValueError('installed ranking differs: ' + case['name'])
    limited, _ = selection_values(*request('/v1/discover?' + urlencode({**query, 'limit': 1})))
    if limited != ids[:1]:
        raise ValueError('installed discovery limit differs: ' + case['name'])
    return {'eligible_ids': sorted(ids), 'recommendation_order': ids, 'scores': scores}


def observe_pricing(request, case):
    # This topology declaration exercises registration pricing, not dial-back
    # reachability. It is the existing owning registration fixture boundary.
    body = {'node_id': 'fixture-http-price', 'endpoint': 'https://1.1.1.1', 'region': 'eu-west',
        'nat_type': 'public', 'transport_method': 'direct_ipv4',
        'capabilities': [{'intent': INTENT, 'models': case['models'], 'max_tokens': 4096}],
        'limits': {'max_concurrent': 10, 'tokens_per_min': 10000},
        'pricing': {'credit_cost_multiplier': case['declared']}}
    status, value = request('/v1/register', body)
    if status != 201 or value.get('node_id') != 'fixture-http-price':
        raise ValueError('installed pricing registration differs: ' + case['name'])
    status, value = request('/v1/discover?' + urlencode({'intent': INTENT, 'model': case['models'][0]}))
    ids, _ = selection_values(status, value)
    if ids != ['fixture-http-price']:
        raise ValueError('installed pricing provider not discovered')
    actual = value['nodes'][0].get('pricing', {}).get('credit_cost_multiplier')
    if type(actual) not in (int, float) or not math.isfinite(actual) or round(actual, 6) != case['expected']:
        raise ValueError('installed discovery pricing differs: ' + case['name'])
    return round(actual, 6)


def observe(request, raw_request, sql, membership, contract, mode):
    if mode not in {'public', 'restricted', 'local-only'}:
        raise ValueError('installed discovery mode differs')
    observations = {}
    for group in ('eligibility_cases', 'ranking_cases', 'pricing_cases'):
        for case in contract[group]:
            clear_nodes(sql)
            if mode == 'restricted' and raw_request('/v1/discover?intent=' + INTENT)[0] != 401:
                raise ValueError('installed anonymous discovery admitted')
            if group == 'pricing_cases':
                actual = observe_pricing(request, case)
            else:
                candidates = case['candidates'] if group == 'eligibility_cases' else [
                    {'id': 'fixture-http-ranking', **case['node']}]
                for node in candidates:
                    seed_node(sql, node)
                    if mode == 'restricted':
                        membership(node['id'])
                actual = observe_selection(request, case, group)
            observations[group + '/' + case['name']] = actual
    clear_nodes(sql)
    return {'scope': 'installed-rust-tcp-discovery-and-registration-pricing', 'mode': mode,
        'fixture_sha256': 'sha256:' + FIXTURE_SHA256, 'observations': observations,
        'qualification_credit': False, 'production_endpoint_validation': False}
