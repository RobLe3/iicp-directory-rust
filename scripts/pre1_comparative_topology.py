"""Bounded, owner-local comparative Directory qualification control.

This proves exclusion only on the declared peer port in one loopback-only test
namespace. It never grants production Genesis authority or qualification credit
by itself; the normal component driver must verify its output and bindings.
"""
from contextlib import ExitStack, contextmanager
import errno
from pathlib import Path
import socket
import sys

PORTS = {"directory-rust": 8090, "directory-php": 8091}
SCHEMA = "iicp.pre1-directory-comparative-topology.v1"


@contextmanager
def hold_peer_port(component, isolation_check):
    if sys.platform != "linux" or component not in PORTS or not callable(isolation_check):
        raise ValueError("comparative Directory control requires isolated Linux")
    isolation_check()
    peer = next(port for name, port in PORTS.items() if name != component)
    families = [(socket.AF_INET, "0.0.0.0", "127.0.0.1", "ipv4")]
    if Path("/proc/net/tcp6").exists():
        families.append((socket.AF_INET6, "::", "::1", "ipv6"))
    with ExitStack() as sockets:
        for family, wildcard, loopback, _ in families:
            guard = sockets.enter_context(socket.socket(family, socket.SOCK_STREAM))
            if family == socket.AF_INET6:
                guard.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            guard.bind((wildcard, peer))
            with socket.socket(family, socket.SOCK_STREAM) as competitor:
                if family == socket.AF_INET6:
                    competitor.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                try:
                    competitor.bind((loopback, peer))
                except OSError as error:
                    if error.errno != errno.EADDRINUSE:
                        raise ValueError("comparative bind refusal is inconclusive") from error
                else:
                    raise ValueError("comparative peer bind was admitted")
        try:
            yield {"peer_port": peer, "address_families": [row[3] for row in families]}
        finally:
            isolation_check()


def result(component, mode, lease):
    if component not in PORTS or mode not in {"local-only", "public", "restricted"}:
        raise ValueError("comparative Directory result context differs")
    if not isinstance(lease, dict) or lease.get("peer_port") != next(
            port for name, port in PORTS.items() if name != component):
        raise ValueError("comparative Directory port differs")
    if lease.get("address_families") not in (["ipv4"], ["ipv4", "ipv6"]):
        raise ValueError("comparative Directory address families differ")
    return {"schema": SCHEMA, "component": component, "mode": mode,
            "peer_port": lease["peer_port"], "address_families": lease["address_families"],
            "own_http_observed": True,
            "scope": "declared-peer-port-in-one-isolated-network-namespace",
            "global_authority_established": False}
