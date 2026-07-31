# Public Genesis read-only assessment — 2026-07-31

**Result:** verified negative result. No production mutation, replica registration,
snapshot credential, node identifier, endpoint, route, credential, or event payload was
retained.

Two fresh runs fetched the public Genesis DID, retained event stream, and public registry.
Both runs produced the same decision:

| Check | Run 1 | Run 2 |
|---|---:|---:|
| Public nodes | 7 | 7 |
| Reconstructed active nodes | 7 | 7 |
| Missing public nodes | 1 | 1 |
| Extra reconstructed nodes | 1 | 1 |
| Invalid signatures | 0 | 0 |
| Chain failures | 0 | 0 |
| Complete public reconstruction | no | no |

The retained public log contained an unsigned historical prefix followed by a verifiable
signed suffix. The assessment never applied unsigned events. The signed suffix was valid,
but it did not reproduce the current public node set exactly. An authenticated snapshot is
therefore required before a Rust shadow can claim complete production-state parity.

This result does not authorize the replica-registration write needed to obtain a snapshot.
It also does not authorize a persistent shadow, public listener, routing change, deployment,
or Genesis cutover. The next stage requires separate approval for an isolated replica
registration and snapshot credential.
