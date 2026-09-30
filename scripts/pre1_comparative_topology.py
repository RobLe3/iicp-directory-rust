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


def listening_ports():
    """Read only the declared ports from bounded Linux kernel listener tables."""
    observed = set()
    for name in ("tcp", "tcp6"):
        path = Path("/proc/net") / name
        if name == "tcp6" and not path.exists():
            continue
        with path.open("rb") as stream:
            raw = stream.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("comparative listener table exceeds bound")
        lines = raw.decode("ascii").splitlines()
        if not lines or "local_address" not in lines[0]:
            raise ValueError("comparative listener table differs")
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 4:
                raise ValueError("comparative listener row differs")
            if fields[3] == "0A":
                port = int(fields[1].rsplit(":", 1)[1], 16)
                if port in PORTS.values():
                    observed.add(port)
    return observed


def observe_own_listener(component, lease, isolation_check):
    if component not in PORTS or not callable(isolation_check) or not isinstance(lease, dict):
        raise ValueError("comparative listener context differs")
    isolation_check()
    if listening_ports() != {PORTS[component]}:
        raise ValueError("installed Directory listener or peer exclusion differs")
    lease["own_listener_observations"] += 1


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
            yield {"peer_port": peer, "address_families": [row[3] for row in families],
                   "own_listener_observations": 0}
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
    count = lease.get("own_listener_observations")
    if type(count) is not int or not 1 <= count <= 10000:
        raise ValueError("comparative Directory installed listener was not observed")
    return {"schema": SCHEMA, "component": component, "mode": mode,
            "peer_port": lease["peer_port"], "address_families": lease["address_families"],
            "own_listener_observations": count,
            "own_http_observed": True,
            "scope": "declared-peer-port-in-one-isolated-network-namespace",
            "global_authority_established": False}
