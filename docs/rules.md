# Rules

AgentScan rules are intentionally narrow. Each finding should explain what was detected, why it matters, and how to fix it.

## `secret.*`

Detects private keys, common cloud tokens, AI provider keys, package registry tokens, SaaS tokens, database URLs, and high-confidence secret assignments.

Current provider-specific patterns include AWS, GitHub, OpenAI, Anthropic, Google API keys, Hugging Face, npm, PyPI, Slack, Discord, Stripe, Supabase, Vercel, and Postgres URLs.

Why it matters: AI coding tools and MCP servers often need credentials. Hardcoding those credentials in source or config files makes them easy to leak when repos are shared, forked, or published.

Fix: remove the value, rotate it if it was committed, and load it from the runtime environment or a secret manager.

## `mcp.command.*`

Detects risky MCP server commands such as shell pipelines, privileged containers, Docker socket mounts, and broad filesystem access.

Why it matters: MCP servers turn local tools into agent-callable capabilities. A risky command can give an agent or compromised server wider access than intended.

Fix: pin explicit commands, avoid remote shell installers, remove privileged container flags, avoid Docker socket mounts, and restrict file access to project-specific directories.

## `mcp.env.inline-secret`

Detects likely secrets stored directly in MCP server `env` blocks.

Why it matters: MCP examples often place tokens in config. Those files are easy to sync or commit by accident.

Fix: use environment references like `$API_TOKEN` instead of literal values.

## `agent.instructions.*`

Detects suspicious agent instructions that ask tools to ignore rules, reveal secrets, exfiltrate credentials, or disable safeguards.

Why it matters: Agent instruction files are trusted context for coding agents. Hostile instructions can change how an agent behaves when a repo is opened.

Fix: keep instruction files limited to project workflow, style, test, and architecture guidance.

## `github.workflow.*`

Detects risky GitHub workflow patterns such as `pull_request_target` and `permissions: write-all`.

Why it matters: repository automation is a high-value target. Overbroad token permissions or unsafe PR triggers can turn a code contribution path into a write path.

Fix: use `pull_request` where possible and grant only the permissions a workflow needs.

## `package.install-script`

Detects risky package install lifecycle scripts that pipe network responses into shells or run broad filesystem deletion.

Why it matters: install hooks run during dependency installation and can execute before developers inspect the package.

Fix: avoid networked shell installers and destructive filesystem operations in install hooks.

## `oss.license-missing`

Detects repositories without a license file.

Why it matters: public repositories without a license are harder for people and companies to use.

Fix: add an OSI-approved license file such as MIT, Apache-2.0, or BSD-3-Clause.
