# Demo

AgentScan includes an intentionally unsafe fixture.

```bash
agentscan examples/unsafe-repo --fail-on critical
```

Expected finding categories:

- committed secrets
- risky MCP shell command
- privileged Docker MCP server
- inline MCP secret
- hostile agent instructions
- risky GitHub workflow permissions
- package install hook
- missing license
