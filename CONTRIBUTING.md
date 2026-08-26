# Contributing

Changes must preserve the control-plane boundary and the versioned PHP/Rust
parity contract. Protocol changes require a corresponding proposal in the IICP
specification repository.

Use this repository's issue forms for reproducible Rust implementation defects
and documentation problems. Use the public IICP specification repository for
protocol or cross-component proposals, the IICP forum for open-ended
discussion, and GitHub's private security-advisory form for vulnerabilities.
Do not include credentials, production topology, task payloads, operator
records or personal data in public issues.

Participation does not confer protocol authority. Decisions and objections on
public proposals are recorded in their public issue or pull request under the
current founder-led governance process.

Before opening a pull request, run:

```bash
cargo fmt --check
cargo test --locked
```

Release, coverage, conformance and operator-evidence scripts use isolated Cargo
targets with incremental compilation disabled. They remove only their own
successful run output. Set `IICP_KEEP_FAILED_CARGO_TARGET=1` to preserve a
failed run for diagnosis. Interactive Cargo commands continue to use `target/`.

Run the cross-directory parity gates from the IICP integration workspace when
changing public fields, lifecycle behavior, persistence or migrations. Do not
include production configuration or real operator data.
