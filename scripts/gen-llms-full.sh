#!/bin/bash
# Generate llms-full.txt from llms.txt, the README and the examples.
# Run with --check to fail if the committed file is out of date.
set -euo pipefail

cd "$(dirname "$0")/.."

OUT="llms-full.txt"
EXAMPLES=(
    examples/axum_simple.rs
    examples/core_only.rs
    examples/axum_memory.rs
    examples/app/mod.rs
    examples/app/config.rs
    examples/app/state.rs
    examples/app/models.rs
    examples/app/users.rs
    examples/app/routes.rs
    examples/app/handlers/auth.rs
    examples/app/handlers/account.rs
    examples/app/handlers/transfer.rs
    examples/app/handlers/api.rs
    examples/app/errors.rs
)

generate() {
    cat llms.txt
    printf '\n---\n\n# README\n\n'
    # Skip the title and badges before the first paragraph, and the
    # contributor-only sections from `## Contributing` onwards
    awk '
        !body && /^\[!\[|^# / { next }
        !body && /^$/ { next }
        { body = 1 }
        /^## Contributing$/ { exit }
        body
    ' README.md
    for example in "${EXAMPLES[@]}"; do
        printf '\n---\n\n# %s\n\n```rust\n' "$example"
        cat "$example"
        printf '```\n'
    done
}

if [ "${1:-}" = "--check" ]; then
    if ! diff -u "$OUT" <(generate) >/dev/null; then
        echo "error: $OUT is out of date, run 'just llms' to regenerate it" >&2
        exit 1
    fi
else
    generate >"$OUT"
    echo "Wrote $OUT"
fi
