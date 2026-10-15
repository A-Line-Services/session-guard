# Contributing

Thanks for helping out. Issues and pull requests are welcome.

## Test-driven development

All changes are test-driven: write a failing test first, then make it pass,
then refactor. Bug fixes start with a test that reproduces the bug.

## Tooling

Recipes live in the [`justfile`](justfile) (run `just` to list them):

| Recipe          | What it does                                                        |
| --------------- | ------------------------------------------------------------------- |
| `just test`     | Unit, property, doc and in-memory store tests (no Docker).          |
| `just test-all` | Everything, including Postgres/Valkey stores and e2e. Needs Docker (testcontainers). |
| `just test-postgres` / `just test-valkey` / `just test-valkey-cluster` / `just e2e` | One store suite or the end-to-end HTTP tests. Need Docker. |
| `just test-clean` | Removes the Docker containers the store and e2e tests share. |
| `just lint`     | `rustfmt --check` and clippy on all and no features.                |
| `just hack`     | `cargo hack` over every pair of features.                           |
| `just fuzz`     | Fuzz a target, e.g. `just fuzz cookie 60` (nightly + `cargo-fuzz`). |
| `just deny` / `just audit` | Supply chain checks.                                     |
| `just doc-stable` / `just examples` / `just msrv` | Rustdoc with `-D warnings`, build the examples, check on Rust 1.94. |
| `just llms`     | Regenerates `llms-full.txt` after editing `llms.txt`, the README or the examples (CI checks it). |
| `just ci`       | Roughly what CI runs: lint, test, docs, feature pairs and the `llms-full.txt` check. |

### Docker for store tests

The Postgres, Valkey and e2e tests start their servers with testcontainers, so
Docker must be running. All tests share one container per image (labelled
`session-guard.test`) and reuse it across runs; `just test-clean` removes them.
Set `DATABASE_URL`, `VALKEY_URL` and `VALKEY_CLUSTER_URL` to use servers you
already run instead (this is what CI does).

The cluster tests start a single cluster-enabled node that owns every slot
(host networking, port 7391). That catches every `CROSSSLOT` error, which the
server raises per slot, but not redirects between nodes. CI therefore runs the
same tests against a three-node cluster; to do that locally, start one and
point `VALKEY_CLUSTER_URL` at it.

### MSRV

The minimum supported Rust version is 1.94 (`rust-version` in `Cargo.toml`),
checked in CI with `cargo check --all-features --all-targets`. Raising it is a
breaking-ish change: do it only when needed, note it in `CHANGELOG.md` and
bump the minor version.

### MaxMind databases

The `maxmind` unit tests build tiny MMDB files in memory. To also smoke-test
against real databases, point these at local copies (the test is skipped when
unset):

```sh
SESSION_GUARD_MAXMIND_TEST_DB=/var/lib/GeoIP/GeoLite2-City.mmdb \
SESSION_GUARD_MAXMIND_TEST_ASN_DB=/var/lib/GeoIP/GeoLite2-ASN.mmdb \
  cargo test --lib --features maxmind real_database_from_env
```

### Benchmarks and fuzzing

`just bench` runs the criterion benches in `benches/`. Fuzz targets live in
`fuzz/` (`cookie`, `xff`, `user_agent`) with seed inputs in `fuzz/seeds/`;
`just fuzz xff 60` runs one for a minute.

Code must be formatted with `rustfmt` and pass clippy (`pedantic`) with
`-D warnings`. Public items need docs.

## Pull requests

Releases are automated with
[release-pilot](https://github.com/A-Line-Services/release-pilot) and run
weekly when there are changes. Label each PR with one of:

- `release:major`, `release:minor`, `release:patch` (default when unlabelled)
- `release:skip` (docs, CI, refactors with no user-facing change)

`CHANGELOG.md` is generated from merged PR titles at release time, so give PRs
a [Conventional Commits](https://www.conventionalcommits.org/) title.

## Commits

Use brief [Conventional Commits](https://www.conventionalcommits.org/), e.g.
`fix(valkey): retry rotation on script reload` or `feat: shadow mode metrics`.

## License

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the Apache-2.0
license, shall be dual licensed under the MIT and Apache-2.0 licenses,
without any additional terms or conditions.
