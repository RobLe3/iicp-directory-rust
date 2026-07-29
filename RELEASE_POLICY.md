# Release and compatibility policy

## Status and authority

The IICP specification, OpenAPI projection and versioned behavior fixtures are
implementation-neutral authority. PHP is the currently deployed Genesis
flavor. Rust is the second official flavor and remains an operator preview
until persistent REACH and rollback gates pass.

The first completed public preview is `v0.1.1`. The `v0.1.0` tag is retained as a failed publication attempt and has no release assets. A Rust release does not
authorize Genesis deployment, database mutation or PHP deprecation.

## Compatibility

Every release records:

- Rust implementation version and source commit;
- compatible HTTP-contract fixture;
- compatible behavior-contract fixture;
- compatible database schema contract;
- PHP baseline used for parity evidence.

Route acknowledgement is insufficient. Authorization, response projection,
signing, persistence, concurrency, retention and failure behavior must match
the declared shared contracts. Rust-specific operational hardening may exceed
the PHP baseline without changing the wire contract.

## Immutability and support

Tags and release artifacts are immutable. Corrections receive a new version.
Pre-1.0 releases may change Rust-specific operator interfaces, but documented
HTTP and integrity behavior changes require shared-contract review.

Security fixes target the latest preview. Production support and a stable
deprecation policy begin only after Rust is promoted from operator preview to
a supported alternative.

## PHP transition

Publishing Rust does not deprecate PHP. Deprecation can be announced only
after persistent production-equivalent evidence, PHP-to-Rust migration and
rollback rehearsal, operator recovery validation and an explicit maintainer
decision. The target review window is six months; retirement may occur within
six to twelve months only if those evidence gates pass.
