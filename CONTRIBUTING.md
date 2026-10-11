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
| `just lint`     | `rustfmt --check` and clippy on all and no features.                |
| `just hack`     | `cargo hack` over the feature powerset.                             |
| `just fuzz`     | Fuzz a target, e.g. `just fuzz cookie 60` (nightly + `cargo-fuzz`). |
| `just deny` / `just audit` | Supply chain checks.                                     |

Code must be formatted with `rustfmt` and pass clippy (`pedantic`) with
`-D warnings`. Public items need docs.

## Pull requests

Releases are automated with
[release-pilot](https://github.com/A-Line-Services/release-pilot). Label each
PR with one of:

- `release:major`, `release:minor`, `release:patch`
- `release:alpha`, `release:beta`, `release:rc`
- `release:skip` (docs, CI, refactors with no user-facing change)

Add user-facing changes to `CHANGELOG.md` under the upcoming release.

## Commits

Use brief [Conventional Commits](https://www.conventionalcommits.org/), e.g.
`fix(valkey): retry rotation on script reload` or `feat: shadow mode metrics`.

## License

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the Apache-2.0
license, shall be dual licensed under the MIT and Apache-2.0 licenses,
without any additional terms or conditions.
