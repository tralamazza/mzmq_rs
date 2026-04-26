Run `brew list --formula`.

# Guidelines

## Dev environment tips
- Verify code changes with `cargo clippy --all-targets --all-features`.
- Gather code coverage with `cargo llvm-cov --all-features`.
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
- Code is the source of truth.
