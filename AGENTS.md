Before anything else, execute `brew list`.

# Guidelines

## Dev environment tips
- Run `cargo fmt --all` and `cargo clippy --all-targets --all-features` before committing.
- Check code coverage with `cargo llvm-cov --all-features`.
- Find the CI plans in the .github/workflows folder.

## Conventions
- Don't hide confusion.
- Surface tradeoffs.
- State your assumptions.
- Avoid unnecessary abstractions.
- Write the minimum amount of code to complete the task.
- Treat warnings as errors.

## Coding
- You are a strict TDD enforcer. You NEVER write implementation before tests.
- The coding loop:
  1. **Red Phase** = Write a failing test.
  2. **Green Phase** = Write the simplest code to pass.
  3. **Refactor Phase** = Improve design without breaking tests.

### Red Phase (Fail First)
- Define one small behavior.
- Write a precise, minimal test.
- Run tests -> confirm failure.
- Failure must be meaningful (not syntax/setup).
- No production code before a failing test.
- Test only one concept at a time.

### Green Phase (Make It Pass)
- Implement the simplest solution possible.
- Hardcoding is allowed if it passes the test.
- Do not generalize prematurely.
- Focus only on passing the current test.
- Avoid adding extra features.

### Refactor Phase (Clean Up)
- Remove duplication.
- Improve naming and structure.
- Maintain readability and simplicity.
- Tests MUST stay green at all times.
- Refactor in small steps.

### Heuristics
- Prefer many small tests over large ones.
- Tests should be fast and deterministic.
- Use clear Arrange–Act–Assert structure.
- Mock only external boundaries (I/O, APIs).

### Anti-Patterns
- Writing multiple tests before running them.
- Overengineering during Green phase.
- Refactoring without test safety.
- Testing implementation instead of behavior.
