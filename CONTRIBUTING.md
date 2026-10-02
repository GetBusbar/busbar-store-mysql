# Contributing to busbar-store-mysql

Thanks for your interest in improving `busbar-store-mysql`.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [MIT](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Layout

Every busbar plugin repo has the same skeleton. This one is a two-crate Cargo workspace: `store-mysql/` holds the plugin's logic and `store-mysql-plugin/` is the thin `cdylib` that packages it as a droppable `kind: store` plugin. busbar itself is a git dependency
pinned to the commit in `.busbar-ref`. The CI, release, dependency and lint configuration
are rendered by `busbar-release plugin sync` from the fleet template (GetBusbar/busbar-release
`template/`), [busbar's plugin registry](https://github.com/GetBusbar/busbar/blob/main/plugins.yaml)
and busbar's dependency policy (`.github/fleet/deps.toml` and the root `[workspace.dependencies]`
at the pin); change them there, not here.

## This repo tests itself against busbar

CI runs the fleet's one harness, busbar's reusable `plugin-ci.yml`, at the busbar commit in
`.busbar-ref`: fmt, clippy -D warnings, the whole test suite, `cargo deny`, the dependency wall
(busbar-contract plus third-party only), the socket/TLS ban (no plugin opens its own socket, dials,
binds or does TLS), the C-dependency allow-list, `Cargo.lock` parity with busbar's lock at the pin,
the both-ways conformance and the busbar conformance kit for this kind. The tests are this repo's:
`store-mysql-plugin/tests/conformance.rs` loads the LINKED door and the BUILT cdylib through busbar's
plugin loader and requires one transcript (a test named `the_linked_and_the_dropped_in_*`), and keeps
at least one RED arm (any other test in that target) that proves the comparison can fail.

## Before you open a pull request

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The README's Tests section names any live backend the full suite needs. Add or update
tests for any behavior change, and update the README when you change behavior or
config. Keep commits focused and describe what changed, why, and how it was verified.
