# session-guard task runner. `just` lists recipes.

set dotenv-load := true

default:
    @just --list

# Unit, property, doc and in-memory store tests (no Docker needed).
test:
    cargo nextest run --features axum,maxmind,metrics,testing
    cargo nextest run -p examples
    cargo test --doc --all-features

# Everything, including Postgres/Valkey stores and e2e via testcontainers (needs Docker).
test-all:
    cargo nextest run --all-features
    cargo test --doc --all-features

# Store tests against real Postgres (testcontainers).
test-postgres:
    cargo nextest run --features postgres,testing --test postgres

# Store tests against real Valkey (testcontainers).
test-valkey:
    cargo nextest run --features valkey,testing --test valkey

# End-to-end HTTP tests (axum + Postgres + Valkey, testcontainers).
e2e:
    cargo nextest run --all-features --test e2e

# Remove the Docker containers the store and e2e tests share across runs.
test-clean:
    docker ps -aq --filter label=session-guard.test | xargs -r docker rm -f

# Build every feature combination.
hack:
    cargo hack check --feature-powerset --depth 2 --no-dev-deps

fmt:
    cargo fmt --all

lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo clippy --all-targets --no-default-features -- -D warnings

doc:
    RUSTDOCFLAGS="-D warnings --cfg docsrs" cargo +nightly doc --all-features --no-deps

# Rustdoc without nightly (no docsrs cfg).
doc-stable:
    RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

bench:
    cargo bench --features testing

# Fuzz one target for a while: just fuzz cookie 60
fuzz target="cookie" seconds="60":
    cd fuzz && cargo +nightly fuzz run {{target}} -- -max_total_time={{seconds}}

coverage:
    cargo llvm-cov nextest --all-features --lcov --output-path lcov.info

# Supply chain checks.
deny:
    cargo deny check

audit:
    cargo audit

# Dependencies with newer (including semver-incompatible) releases.
outdated:
    cargo upgrade --dry-run --incompatible

msrv:
    cargo +1.94 check --workspace --all-features --all-targets

semver:
    cargo semver-checks

# What CI runs.
ci: lint test doc-stable hack

examples:
    cargo build -p examples
