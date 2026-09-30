"""Fail-closed tests for the bounded, per-namespace comparative port lease."""
import errno
import json
import os
import socket
import sys
import unittest
from unittest.mock import Mock, patch

import pre1_comparative_topology as topology
import pre1_package_execution as adapter


class ComparativeTopologyTests(unittest.TestCase):
    def test_exclusive_bind_retries_time_wait_without_socket_reuse(self):
        guard = Mock()
        guard.bind.side_effect = [OSError(errno.EADDRINUSE, "TIME_WAIT"), None]
        checks = []
        with patch.object(topology, "listening_ports", return_value=set()), \
                patch.object(topology.time, "sleep") as sleep:
            topology.bind_exclusive_peer(guard, "0.0.0.0", 8090,
                                         lambda: checks.append(True))
        self.assertEqual(guard.bind.call_count, 2)
        self.assertEqual(len(checks), 2)
        sleep.assert_called_once_with(0.25)

    def test_exclusive_bind_refuses_listener_or_permanent_occupancy(self):
        guard = Mock()
        guard.bind.side_effect = OSError(errno.EADDRINUSE, "occupied")
        with patch.object(topology, "listening_ports", return_value={8090}):
            with self.assertRaisesRegex(ValueError, "peer listener"):
                topology.bind_exclusive_peer(guard, "0.0.0.0", 8090, lambda: None)
        with patch.object(topology, "listening_ports", return_value=set()), \
                patch.object(topology.time, "monotonic", side_effect=[0, 76]):
            with self.assertRaisesRegex(ValueError, "remained occupied"):
                topology.bind_exclusive_peer(guard, "0.0.0.0", 8090, lambda: None)

    @unittest.skipUnless(sys.platform == "linux", "requires Linux procfs")
    def test_kernel_listener_table_reports_real_declared_port(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 8090))
            server.listen(1)
            self.assertEqual(topology.listening_ports(), {8090})

    def test_packaged_output_is_exact_and_bounded(self):
        context = {"scenario_id": "no-dual-authority", "component": "directory-rust", "mode": "local-only"}
        assertion = "installed_comparative_authority_exclusion"
        value = topology.result("directory-rust", "local-only",
                                {"peer_port": 8091, "address_families": ["ipv4"],
                                 "own_listener_observations": 1})
        output = "IICP_PRE1_DIRECTORY_TOPOLOGY " + json.dumps(value) + "\nIICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion
        self.assertEqual(adapter.directory_output_exit_code(0, output, context, assertion, None), 0)
        for altered in ({**value, "global_authority_established": True},
                        {**value, "own_http_observed": False},
                        {**value, "peer_port": 8090},
                        {**value, "own_listener_observations": 0}):
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
                self.assertEqual(lease, {"peer_port": port, "address_families": ["ipv4"],
                                         "own_listener_observations": 0})
                with socket.socket() as competitor:
                    with self.assertRaises(OSError) as refusal:
                        competitor.bind(("127.0.0.1", port))
                    self.assertEqual(refusal.exception.errno, errno.EADDRINUSE)
                if os.uname().sysname == "Linux":
                    with socket.socket() as reuse_competitor:
                        reuse_competitor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        with self.assertRaises(OSError) as refusal:
                            reuse_competitor.bind(("127.0.0.1", port))
                        self.assertEqual(refusal.exception.errno, errno.EADDRINUSE)
                with patch.object(topology, "listening_ports", return_value={port + 1}):
                    topology.observe_own_listener("directory-php", lease, lambda: checks.append(True))
                self.assertIs(topology.result("directory-php", "local-only", lease)[
                    "global_authority_established"], False)
        self.assertEqual(len(checks), 4)

    def test_listener_observation_refuses_missing_or_peer_listener(self):
        lease = {"own_listener_observations": 0}
        for ports in (set(), {8091}, {8090, 8091}):
            with patch.object(topology, "listening_ports", return_value=ports):
                with self.assertRaisesRegex(ValueError, "listener or peer exclusion"):
                    topology.observe_own_listener("directory-rust", lease, lambda: None)
        self.assertEqual(lease["own_listener_observations"], 0)


if __name__ == "__main__":
    unittest.main()
