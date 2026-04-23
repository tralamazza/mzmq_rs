Before anything else, execute `brew list`.

# Guidelines

## Dev environment tips
- Run cargo fmt and clippy before committing.
- Check code coverage with `cargo llvm-cov`.

## Testing instructions
- Use TDD (red-green), one test at a time, blackbox testing.
- Find the CI plan in the .github/workflows folder.

## Conventions
- Don't hide confusion.
- Surface tradeoffs.
- State your assumptions.
- Avoid unnecessary abstractions.
- Write the minimum amount of code to complete the task.
- Treat warnings as errors.
