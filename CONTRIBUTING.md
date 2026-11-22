# Contributing to Staffet

Thanks for your interest in improving Staffet. Contributions of all sizes are welcome: bug reports, documentation, new detection rules, scanners, and code.

## Getting started

1. Fork the repository and clone your fork.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the test suite:
   ```bash
   npm test
   ```
4. Create a branch for your change:
   ```bash
   git checkout -b feat/short-description
   ```

Requirements: Node.js 20.18.1 or newer.

## Making changes

- Keep each pull request focused on one change.
- Add or update tests in `test/` for any behaviour change.
- Do not commit secrets, real API keys, request logs or anything from `data/`. These paths are already in `.gitignore`; check `git status` before committing.
- Do not add organisation-specific names, domains or patterns to shared rules. Put local rules in `rules/custom/`, which is ignored.
- Keep dependencies minimal. Open an issue before adding a new one.

## Commit messages

Use short, imperative messages, for example:

```
Add domain allowlist check for tool calls
Fix redaction of multi-line tokens
```

## Pull requests

In your pull request, describe:

- what changed and why,
- how you tested it,
- any follow-up work or known limitations.

All checks must pass before review.

## Reporting bugs and requesting features

Open an issue with:

- the Staffet version and Node.js version,
- steps to reproduce,
- expected and actual behaviour,
- relevant logs with secrets removed.

For security vulnerabilities, do not open a public issue. Report them privately to the maintainers.

## Code of conduct

Be respectful and constructive. Reviews critique code, not people.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
