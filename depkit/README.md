# DepKit

DepKit helps small teams plan dependency upgrades before they turn into a week-long branch.

Renovate and Dependabot are good at opening update PRs. DepKit is for the step before that: looking at the repo, spotting the coupled pieces, and deciding what should move first.

## What it does

- Scans the dependency files that usually move together.
- Spots runtimes, framework packages, Docker bases, and CI actions.
- Calls out risky upgrade work before it lands in one giant PR.
- Groups the work into stages a maintainer can actually follow.

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
Upgrade plan for 17 dependencies
High-risk items: 8

Stage 1: Tooling and CI
- actions/setup-node: v3 [medium; CI workflow dependency]
- actions/setup-python: v4 [medium; CI workflow dependency]

Stage 2: Runtime foundations
- node: 18-alpine [high; runtime foundation]
- python: 3.10-slim [high; runtime foundation]

Stage 3: Frameworks and platform packages
- next: 13.4.0 [high; application framework]
- fastapi: 0.95.0 [high; application framework, pre-1.0 package]
```

## Status

This is early. Right now DepKit works locally and uses heuristics instead of registry lookups. That keeps the first version simple and useful offline. Registry-backed latest-version checks are the obvious next step.
