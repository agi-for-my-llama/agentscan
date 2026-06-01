# AgentScan

Local security preflight for AI-agent-era repositories.

AgentScan is a local-first CLI that checks repositories for risks introduced by AI coding agents and MCP tools before code is published or wired into automation.

It focuses on practical launch blockers:

- leaked secrets in source, docs, and config files
- risky MCP server commands and overbroad filesystem access
- hostile or suspicious agent instructions in files like `AGENTS.md`, `CLAUDE.md`, and `.cursor/rules`
- dangerous install hooks in `package.json`
- missing open-source launch basics like a license

## Install

```bash
python -m pip install .
```

For local development:

```bash
python -m pip install -e .
```

## Use

Scan the current repository:

```bash
agentscan .
```

Create a starter config:

```bash
agentscan --init-config
```

Use it as a GitHub Action:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: your-org/agentscan@v1
    with:
      fail-on: high
```

Return JSON for CI or automation:

```bash
agentscan . --format json
```

Generate SARIF for GitHub code scanning:

```bash
agentscan . --format sarif > agentscan.sarif
```

Fail only on high-severity findings:

```bash
agentscan . --fail-on high
```

Ignore generated or vendored paths:

```bash
agentscan . --exclude dist --exclude vendor
```

## Config

AgentScan automatically reads `.agentscan.json` or `agentscan.json` from the repository root.

```json
{
  "fail_on": "high",
  "exclude": ["dist", "vendor"],
  "ignore_rules": ["oss.license-missing"],
  "ignore_paths": ["docs/generated"]
}
```

CLI flags override config where both are provided.

## Exit Codes

- `0`: no findings at or above the configured `--fail-on` level
- `1`: findings at or above the configured `--fail-on` level
- `2`: CLI usage or scan error

## What It Detects

AgentScan is intentionally conservative. It prefers specific, explainable checks over noisy guesses.

| Rule | Severity | What it looks for |
| --- | --- | --- |
| `secret.*` | high/critical | common API keys, private keys, token assignments |
| `mcp.command.*` | medium/high | shell pipelines, remote installers, privileged Docker, writable broad paths |
| `agent.instructions.*` | medium/high | instructions that ask agents to ignore rules, reveal secrets, exfiltrate data, or disable safety checks |
| `github.workflow.*` | medium/high | `pull_request_target`, `write-all` token permissions |
| `package.install-script` | medium/high | install hooks that run networked shell commands or broad filesystem changes |
| `oss.license-missing` | medium | missing repository license |

## CI Example

```yaml
name: agentscan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install .
      - run: agentscan . --fail-on high
```

For GitHub code scanning:

```yaml
name: agentscan-sarif

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install .
      - run: agentscan . --format sarif --fail-on critical > agentscan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentscan.sarif
```

## Scope

This is not a replacement for full SAST, dependency scanning, or secret scanning platforms. It is a fast preflight scanner for the new layer many repos now have: agent instructions, local tool permissions, and MCP server definitions.

## Development

```bash
python -m unittest discover -s tests
```

## Roadmap

- more MCP client config formats
- optional baseline files for existing findings
- package manager lockfile risk hints
- pre-commit hook packaging
- richer GitHub code scanning metadata

## License

MIT
