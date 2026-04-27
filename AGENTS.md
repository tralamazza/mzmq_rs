Run `brew list --formula`

# Guidelines

## Dev environment tips
- Verify code changes with `cargo clippy --all-targets --all-features`.
- Use `scripts/coverage-table.sh` for unit test coverage report.
- Use `scripts/measure_size.sh` for a binary size report.
- Find the CI plans in the .github/workflows folder.
- Use `ast-grep` for code exploration and manipulation.
- Use `rg` instead of grep.
- Use `gh` for github operations.

## Conventions
- Don't hide confusion.
- Surface tradeoffs.
- State your assumptions.
- Avoid unnecessary abstractions.
- Write the minimum amount of code to complete the task.
- Treat warnings as errors.
