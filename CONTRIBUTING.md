# Contributing

Changes must preserve the control-plane boundary and the versioned PHP/Rust
parity contract. Protocol changes require a corresponding proposal in the IICP
specification repository.

Before opening a pull request, run:

```bash
cargo fmt --check
cargo test --locked
```

Run the cross-directory parity gates from the IICP integration workspace when
changing public fields, lifecycle behavior, persistence or migrations. Do not
include production configuration or real operator data.
