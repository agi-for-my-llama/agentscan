# DepKit

DepKit is an open-source dependency lifecycle planner for small teams.

Renovate and Dependabot tell you what changed. DepKit tells you how to survive the upgrade.

## What it does

- Scans dependency files across an app, not just package manifests.
- Finds coupled upgrades across runtimes, package managers, Docker bases, and CI images.
- Flags upgrade risk before a team opens a messy PR.
- Produces staged plans grouped by likely blast radius.

## Supported inputs

- `package.json`
- `requirements.txt`
- `pyproject.toml`
- `go.mod`
- `Dockerfile`
- GitHub Actions workflow files

## Quick start

```bash
pip install -e .
depkit scan .
depkit risk .
depkit plan .
```

## Example

```bash
depkit plan examples/polyglot-app
```

```text
Stage 1: Tooling and CI
- actions/setup-node: 3 -> 4
- actions/setup-python: 4 -> 5

Stage 2: Runtime foundations
- node: 18 -> 20
- python: 3.10 -> 3.12

Stage 3: Application packages
- react: 17.0.2
- fastapi: 0.95.0
```

## Status

This is an MVP. It uses local heuristics to produce a practical upgrade plan without contacting registries. Registry-backed latest-version checks are a natural next step.
