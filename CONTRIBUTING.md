# Contributing

Thanks for helping improve ConduitGuard. Keep changes focused and explain any changes to the policy model or its documented semantics.

## Development

1. Follow the clean-install commands in [README.md](README.md).
2. Add or update tests for behavior changes. Simulator expected results should be independently specified in tests.
3. Run `python -m pytest`, `ruff check backend`, and `pnpm lint` from `frontend/` before opening a pull request.
4. Update the schema, API documentation, and limitations when behavior changes.

## Pull requests

Describe the security impact, compatibility impact, and how you verified the change. Never include credentials, private network configurations, or production secrets in examples or test fixtures. Do not add functionality that applies changes to a real firewall or probes an external target.
