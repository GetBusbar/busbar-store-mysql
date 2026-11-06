# Contributing to busbar-store-mysql

Thanks for your interest in improving `busbar-store-mysql`.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Layout

Every busbar plugin repo has the same skeleton. This one is a two-crate Cargo workspace: `store-mysql/` holds the plugin's logic and `store-mysql-plugin/` is the thin `cdylib` that packages it as a droppable `kind: store` plugin. busbar itself is a git dependency
pinned to the commit in `.busbar-ref`. The CI, release, dependency and lint configuration
are rendered by `busbar-release plugin heal` from the fleet template (GetBusbar/busbar-release
`template/`), [busbar's plugin registry](https://github.com/GetBusbar/busbar/blob/main/plugins.yaml)
and busbar's dependency policy (`fleet/deps.toml` and the root `[workspace.dependencies]`
at the pin); change them there, not here.

## This repo tests itself against busbar

Internal CI tests against the commit in `.busbar-ref`. It runs formatting,
strict Clippy, dependency checks and this repository's ordinary Rust tests. The tests load the
actual linked door and the freshly built library through the public plugin loader. CI exports the
absolute library path as `BUSBAR_PLUGIN_CDYLIB`; a missing library fails the tests.

Keep product assertions in this repository. Exercise both actual loading paths and retain negative
cases that distinguish a refused input or failed operation from success. There is no shared kind
script or generated host adapter. Configure any real service backends and existing test-only
features in this repository's registry entry; test-image features do not change production builds.

The plugin keeps its own `Cargo.lock`. Heal seeds its resolution from busbar's lock at the pin;
this does not make the two complete dependency graphs or every resolved version identical.

## Before you open a pull request

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked -p busbar-store-mysql-plugin --lib
BUSBAR_PLUGIN_CDYLIB="$PWD/target/release/libbusbar_store_mysql_plugin.so" cargo test --release --workspace --locked
```

The README's Tests section names any live backend the full suite needs. Add or update
tests for any behavior change, and update the README when you change behavior or
config. Keep commits focused and describe what changed, why, and how it was verified.
