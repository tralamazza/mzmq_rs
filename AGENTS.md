# Guidelines

## Dev environment tips
- Run `cargo clippy --all-targets --all-features` before committing.
- Check code coverage with `cargo llvm-cov --all-features`.
- Find the CI plans in the .github/workflows folder.

## Conventions
- Don't hide confusion.
- Surface tradeoffs.
- State your assumptions.
- Avoid unnecessary abstractions.
- Write the minimum amount of code to complete the task.
- Treat warnings as errors.
