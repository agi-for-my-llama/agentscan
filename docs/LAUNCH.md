# Launch Checklist

Use this when publishing AgentScan as a public GitHub repository.

## Repository

- Create the repo as `agentscan` or `agentscan-dev/agentscan`.
- Set the description to: `Local security preflight for AI-agent-era repositories.`
- Add topics: `mcp`, `ai-agents`, `security`, `secrets`, `github-actions`, `cli`, `devsecops`.
- Enable private vulnerability reporting.
- Enable GitHub Actions.

## First Release

- Tag `v0.1.0`.
- Include the CLI, GitHub Action, SARIF output, and config support in release notes.
- Keep the release explicit that the scanner is conservative and local-first.

## Launch Copy

AgentScan scans repos for the new layer of risk introduced by AI coding agents and MCP servers: inline secrets, risky MCP commands, hostile agent instructions, dangerous install hooks, and overbroad GitHub workflow permissions.

It runs locally, has no runtime dependencies, emits SARIF, and ships as both a CLI and GitHub Action.
