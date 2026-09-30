"""Fail-closed tests for the bounded, per-namespace comparative port lease."""
import errno
import json
import socket
import unittest
from unittest.mock import patch

import pre1_comparative_topology as topology
import pre1_package_execution as adapter


class ComparativeTopologyTests(unittest.TestCase):
    def test_packaged_output_is_exact_and_bounded(self):
        context = {"scenario_id": "no-dual-authority", "component": "directory-rust", "mode": "local-only"}
        assertion = "installed_comparative_authority_exclusion"
        value = topology.result("directory-rust", "local-only",
                                {"peer_port": 8091, "address_families": ["ipv4"]})
        output = "IICP_PRE1_DIRECTORY_TOPOLOGY " + json.dumps(value) + "\nIICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion
        self.assertEqual(adapter.directory_output_exit_code(0, output, context, assertion, None), 0)
        for altered in ({**value, "global_authority_established": True},
                        {**value, "own_http_observed": False},
                        {**value, "peer_port": 8090}):
            bad = "IICP_PRE1_DIRECTORY_TOPOLOGY " + json.dumps(altered) + "\nIICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion
            self.assertEqual(adapter.directory_output_exit_code(0, bad, context, assertion, None), 2)
        self.assertEqual(adapter.directory_output_exit_code(17, output, context, assertion, None), 17)

    def test_requires_linux_and_isolation_check(self):
        with patch.object(topology.sys, "platform", "darwin"):
            with self.assertRaisesRegex(ValueError, "isolated Linux"):
                with topology.hold_peer_port("directory-rust", lambda: None):
                    pass
        with self.assertRaisesRegex(ValueError, "isolated Linux"):
            with topology.hold_peer_port("unknown", lambda: None):
                pass

    def test_lease_excludes_peer_bind_and_rechecks_isolation(self):
        checks = []
        with socket.socket() as temporary:
            temporary.bind(("127.0.0.1", 0))
            port = temporary.getsockname()[1]
        with patch.object(topology.sys, "platform", "linux"), \
                patch.dict(topology.PORTS, {"directory-rust": port, "directory-php": port + 1}, clear=True), \
                patch.object(topology.Path, "exists", return_value=False):
            with topology.hold_peer_port("directory-php", lambda: checks.append(True)) as lease:
                self.assertEqual(lease, {"peer_port": port, "address_families": ["ipv4"]})
                with socket.socket() as competitor:
                    with self.assertRaises(OSError) as refusal:
                        competitor.bind(("127.0.0.1", port))
                    self.assertEqual(refusal.exception.errno, errno.EADDRINUSE)
                self.assertIs(topology.result("directory-php", "local-only", lease)[
                    "global_authority_established"], False)
        self.assertEqual(len(checks), 2)


if __name__ == "__main__":
    unittest.main()
