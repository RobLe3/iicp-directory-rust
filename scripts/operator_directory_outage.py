"""Component-owned pause/resume control for a disposable SDK probe.

No discovery of unrelated containers; no socket or host credentials in probe.
The owner must retain the returned receipt alongside the final probe digest.
"""
import json
import re
import time

CONTROL = '/probe/scripts/pre1_directory_outage.py'
SCHEMA = 'iicp.directory-outage-control.v1'


class Owner:
    def __init__(self, call, probe, app, label_key, label_value, image):
        self.call = call
        if not re.fullmatch('[A-Za-z0-9_.-]+', label_key):
            raise ValueError('owner_label_key')
        self.key, self.label, self.image = label_key, label_value, image
        self.probe = self.inspect(probe)['id']
        self.app = self.inspect(app)['id']
        self.app_name = app
        self.pending = False
        self.nonce = None
        self.observed = []
        self.verify()

    def inspect(self, container):
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', container):
            raise ValueError('container_identity')
        fields = {'id': '.Id', 'image': '.Image', 'running': '.State.Running',
                  'paused': '.State.Paused', 'network': '.HostConfig.NetworkMode',
                  'owner': '(index .Config.Labels "' + self.key + '")'}
        template = '{' + ','.join('"'+key+'":{{json '+value+'}}' for key, value in fields.items()) + '}'
        raw = self.call(['inspect', '--format', template, container], 10)
        if len(raw) > 4096:
            raise ValueError('inspection_limit')
        value = json.loads(raw)
        if not re.fullmatch('[0-9a-f]{64}', str(value.get('id', ''))):
            raise ValueError('inspection_identity')
        if value.get('owner') != self.label:
            raise ValueError('container_owner_mismatch')
        return value

    def verify(self):
        probe, app = self.inspect(self.probe), self.inspect(self.app)
        if probe['image'] != self.image or probe['running'] is not True or probe['paused'] is not False:
            raise ValueError('probe_not_running')
        if probe['network'] not in ('container:' + self.app, 'container:' + self.app_name):
            raise ValueError('probe_namespace_mismatch')
        if app['running'] is not True:
            raise ValueError('app_not_running')
        return app

    def request(self, sequence):
        raw = self.call(['exec', self.probe, 'python3', CONTROL, 'read', str(sequence)], 10)
        if len(raw) > 1024:
            raise ValueError('request_limit')
        value = json.loads(raw)
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError('request_object')
        expected = {'schema': SCHEMA, 'sequence': sequence,
                    'action': {1: 'pause', 2: 'resume'}[sequence], 'nonce': value.get('nonce')}
        if value != expected or type(value.get('sequence')) is not int:
            raise ValueError('request_identity')
        if not isinstance(value['nonce'], str) or not re.fullmatch('[0-9a-f]{32}', value['nonce']):
            raise ValueError('request_nonce')
        if self.nonce is not None and self.nonce != value['nonce']:
            raise ValueError('request_nonce_changed')
        self.nonce = value['nonce']
        return value

    def transition(self, sequence):
        app = self.verify()
        if sequence == 1:
            if app['paused'] is not False:
                raise ValueError('app_already_paused')
            self.pending = True  # Before API call: timeout may hide completed pause.
            self.call(['pause', self.app], 10)
        else:
            self.call(['unpause', self.app], 10)
        paused = sequence == 1
        if self.inspect(self.app)['paused'] is not paused:
            raise ValueError('pause_state_not_observed')
        if not paused:
            self.pending = False
        self.observed.append({1: 'pause', 2: 'resume'}[sequence])
        self.call(['exec', self.probe, 'python3', CONTROL, 'ack', str(sequence), self.nonce], 10)

    def snapshot(self):
        return {'schema': 'iicp.directory-outage-control-observation.v1',
                'nonce': self.nonce, 'probe_id': self.probe, 'app_id': self.app,
                'observed': list(self.observed), 'recovery_pending': self.pending,
                'non_authorizing': True, 'qualification_credit': 0}

    def run(self):
        sequence = 1
        deadline = time.monotonic() + 1800
        try:
            while sequence <= 2:
                if time.monotonic() >= deadline:
                    raise RuntimeError('outage_control_deadline')
                self.verify()
                if self.request(sequence) is not None:
                    self.transition(sequence)
                    sequence += 1
                    deadline = min(deadline, time.monotonic() + 150)
                else:
                    time.sleep(1)
            return {'schema': 'iicp.directory-outage-owner.v1', 'status': 'PASS',
                    'nonce': self.nonce, 'probe_id': self.probe, 'app_id': self.app,
                    'image': self.image, 'observed': self.observed,
                    'non_authorizing': True, 'qualification_credit': 0}
        finally:
            if self.pending:
                self.inspect(self.app)  # Retain ownership guard during recovery.
                self.call(['unpause', self.app], 10)
                if self.inspect(self.app)['paused'] is not False:
                    raise RuntimeError('outage_recovery_unverified')
                self.pending = False
