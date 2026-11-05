# mysql_common 0.35.5 source custody

Official crates.io release, archive SHA256 `fbb9f371618ce723f095c61fbcdc36e8936956d2b62832f9c7648689b338e052`. Upstream: https://github.com/blackbeam/rust_mysql_common. Original MIT and Apache-2.0 license files retained. Original source hashes are recorded in `BUSBAR-UPSTREAM-FILES.json`; registry normalization files remain untouched except Cargo.toml adds zeroize.

Local patch: wipe consumed protocol input before advancing; preserve live data while wiping codec buffers before allocation replacement; wipe both private codec buffers on drop and the output staging on failed encoding; use initialized wiping compression/decompression staging. No change to wire format, negotiated compression, packet bounds or sequence checks.

This maintained dependency patch is specific to codec buffer custody. It does not claim to wipe flate2/miniz internal allocations or all third-party scratch. Official serde_json remains unchanged.

The standalone codec regression harness in `testing/mysql-codec` imports this exact module and official constants. It avoids enabling upstream's unrelated C++ decimal test feature. Its lock is seeded from the production workspace lock and resolved normally. The vendored lock is also generated normally for standalone tooling; the upstream `.gitignore` exception preserves it in this repository.
