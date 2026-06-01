from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, Iterator

from .findings import Finding


SECRET_PATTERNS = [
    (
        "secret.private-key",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Remove the private key, rotate it, and load it from a secret manager.",
    ),
    (
        "secret.aws-access-key",
        "critical",
        re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b"),
        "Remove the AWS key, rotate it, and use IAM roles or environment injection.",
    ),
    (
        "secret.github-token",
        "high",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
        "Remove the GitHub token, revoke it, and use scoped CI secrets.",
    ),
    (
        "secret.openai-key",
        "high",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
        "Remove the API key, rotate it, and read it from runtime secrets.",
    ),
    (
        "secret.generic-assignment",
        "high",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{20,}['\"]?"
        ),
        "Move the value to an environment variable or secret store, then rotate it if committed.",
    ),
]

AGENT_INSTRUCTION_FILES = {
    "agents.md",
    "claude.md",
    "gemini.md",
    "copilot-instructions.md",
    ".cursorrules",
}

AGENT_INSTRUCTION_PATTERNS = [
    (
        "agent.instructions.ignore-rules",
        "high",
        re.compile(r"(?i)\bignore (?:all |any |previous |prior |system |developer ).{0,40}(?:instructions|rules|policies)\b"),
        "Remove instructions that try to override agent or repository safety rules.",
    ),
    (
        "agent.instructions.secret-exfiltration",
        "high",
        re.compile(r"(?i)\b(?:reveal|print|dump|exfiltrate|send).{0,40}\b(?:secrets?|tokens?|api keys?|credentials?)\b"),
        "Remove instructions that ask agents to reveal or move secrets.",
    ),
    (
        "agent.instructions.safety-disable",
        "medium",
        re.compile(r"(?i)\b(?:disable|bypass|turn off).{0,40}\b(?:safety|guardrails?|permissions?|approval)\b"),
        "Keep agent guidance focused on project workflows, not disabling safeguards.",
    ),
]

PACKAGE_INSTALL_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}
NETWORK_SHELL_PATTERN = re.compile(r"(?i)(curl|wget|iwr|irm)\b.+\|\s*(bash|sh|powershell|pwsh)")
DESTRUCTIVE_PATTERN = re.compile(r"(?i)\b(rm\s+-rf\s+[/~*]|Remove-Item\s+.*-Recurse|del\s+/s)\b")
WORKFLOW_PERMISSION_PATTERN = re.compile(r"^\s*permissions\s*:\s*(write-all|read-all)\s*$", re.IGNORECASE)
PULL_REQUEST_TARGET_PATTERN = re.compile(r"^\s*pull_request_target\s*:", re.IGNORECASE)
DOCKER_SOCKET_PATTERN = re.compile(r"(?i)(/var/run/docker\.sock|//var/run/docker\.sock)")


def scan_text(path: Path, display_path: str, text: str) -> Iterator[Finding]:
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule_id, severity, pattern, remediation in SECRET_PATTERNS:
            if pattern.search(line):
                yield Finding(
                    rule_id=rule_id,
                    severity=severity,
                    path=display_path,
                    line=line_number,
                    message="Potential secret committed to the repository.",
                    remediation=remediation,
                    evidence=_redact(line.strip()),
                )

        if _is_agent_instruction_path(path):
            for rule_id, severity, pattern, remediation in AGENT_INSTRUCTION_PATTERNS:
                if pattern.search(line):
                    yield Finding(
                        rule_id=rule_id,
                        severity=severity,
                        path=display_path,
                        line=line_number,
                        message="Suspicious agent instruction detected.",
                        remediation=remediation,
                        evidence=line.strip(),
                    )

        if _is_github_workflow_path(path):
            if PULL_REQUEST_TARGET_PATTERN.search(line):
                yield Finding(
                    rule_id="github.workflow.pull-request-target",
                    severity="high",
                    path=display_path,
                    line=line_number,
                    message="Workflow uses pull_request_target.",
                    remediation="Use pull_request unless this workflow is tightly scoped and avoids checking out untrusted code.",
                    evidence=line.strip(),
                )
            permission_match = WORKFLOW_PERMISSION_PATTERN.search(line)
            if permission_match and permission_match.group(1).lower() == "write-all":
                yield Finding(
                    rule_id="github.workflow.write-all",
                    severity="medium",
                    path=display_path,
                    line=line_number,
                    message="Workflow grants write-all permissions.",
                    remediation="Grant only the minimum GitHub token permissions needed by the workflow.",
                    evidence=line.strip(),
                )


def scan_json(path: Path, display_path: str, text: str) -> Iterator[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return

    if path.name.lower() == "package.json":
        yield from _scan_package_json(display_path, data)

    if _looks_like_mcp_config(path, data):
        yield from _scan_mcp_config(display_path, data)


def scan_repo_metadata(root: Path) -> Iterable[Finding]:
    license_files = ["LICENSE", "LICENSE.md", "COPYING", "COPYING.md"]
    if not any((root / name).exists() for name in license_files):
        yield Finding(
            rule_id="oss.license-missing",
            severity="medium",
            path=".",
            line=1,
            message="No repository license file found.",
            remediation="Add an OSI-approved license before publishing the repository.",
        )


def _scan_package_json(display_path: str, data: object) -> Iterator[Finding]:
    if not isinstance(data, dict):
        return
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return

    for script_name in sorted(PACKAGE_INSTALL_SCRIPTS.intersection(scripts)):
        command = str(scripts[script_name])
        severity = "high" if NETWORK_SHELL_PATTERN.search(command) else "medium"
        if NETWORK_SHELL_PATTERN.search(command) or DESTRUCTIVE_PATTERN.search(command):
            yield Finding(
                rule_id="package.install-script",
                severity=severity,
                path=display_path,
                line=1,
                message=f"Install lifecycle script `{script_name}` runs a risky command.",
                remediation="Avoid networked shell installers and broad deletion in install hooks.",
                evidence=command,
            )


def _scan_mcp_config(display_path: str, data: object) -> Iterator[Finding]:
    servers = _extract_mcp_servers(data)
    for server_name, server in servers:
        if not isinstance(server, dict):
            continue

        command = str(server.get("command", ""))
        args = [str(arg) for arg in server.get("args", []) if arg is not None]
        env = server.get("env", {})
        combined = " ".join([command, *args])

        if _contains_shell_pipeline(combined):
            yield Finding(
                rule_id="mcp.command.shell-pipeline",
                severity="high",
                path=display_path,
                line=1,
                message=f"MCP server `{server_name}` uses shell piping or chained commands.",
                remediation="Pin and run explicit commands instead of shell pipelines.",
                evidence=combined,
            )

        if re.search(r"(?i)\bdocker\b", combined) and re.search(r"(?i)(--privileged|-v\s+/:|--volume\s+/:)", combined):
            yield Finding(
                rule_id="mcp.command.privileged-container",
                severity="high",
                path=display_path,
                line=1,
                message=f"MCP server `{server_name}` appears to run a privileged container.",
                remediation="Remove privileged mode and mount only the directories the server needs.",
                evidence=combined,
            )

        if DOCKER_SOCKET_PATTERN.search(combined):
            yield Finding(
                rule_id="mcp.command.docker-socket",
                severity="high",
                path=display_path,
                line=1,
                message=f"MCP server `{server_name}` mounts the Docker socket.",
                remediation="Avoid exposing the Docker socket to MCP servers; use a narrow sandbox or dedicated API instead.",
                evidence=combined,
            )

        if re.search(r"(?i)(--allow-dir|--allowed-directory|--filesystem|--root)", combined):
            if re.search(r"(?i)(\s/(\s|$)|[A-Za-z]:\\\\|~|%USERPROFILE%|\$HOME)", combined):
                yield Finding(
                    rule_id="mcp.permission.broad-filesystem",
                    severity="high",
                    path=display_path,
                    line=1,
                    message=f"MCP server `{server_name}` may expose a broad filesystem path.",
                    remediation="Limit filesystem access to the smallest project-specific directory.",
                    evidence=combined,
                )

        if isinstance(env, dict):
            for key, value in env.items():
                if (
                    re.search(r"(?i)(secret|token|password|api[_-]?key)", str(key))
                    and value not in ("", None)
                    and not _is_env_reference(str(value))
                ):
                    yield Finding(
                        rule_id="mcp.env.inline-secret",
                        severity="high",
                        path=display_path,
                        line=1,
                        message=f"MCP server `{server_name}` defines a likely secret inline.",
                        remediation="Reference secrets from the runtime environment instead of storing values in config.",
                        evidence=f"{key}={_redact(str(value))}",
                    )


def _extract_mcp_servers(data: object) -> list[tuple[str, object]]:
    if not isinstance(data, dict):
        return []
    raw_servers = data.get("mcpServers") or data.get("servers")
    if isinstance(raw_servers, dict):
        return [(str(name), server) for name, server in raw_servers.items()]
    return []


def _looks_like_mcp_config(path: Path, data: object) -> bool:
    name = path.name.lower()
    if name in {".mcp.json", "mcp.json", "claude_desktop_config.json"}:
        return True
    return isinstance(data, dict) and ("mcpServers" in data or "servers" in data)


def _is_agent_instruction_path(path: Path) -> bool:
    lowered = [part.lower() for part in path.parts]
    if path.name.lower() in AGENT_INSTRUCTION_FILES:
        return True
    return ".cursor" in lowered and any(part in {"rules", "rules.md"} for part in lowered)


def _is_github_workflow_path(path: Path) -> bool:
    lowered = [part.lower() for part in path.parts]
    return len(lowered) >= 3 and lowered[0] == ".github" and lowered[1] == "workflows"


def _contains_shell_pipeline(command: str) -> bool:
    return bool(
        re.search(r"(?i)(curl|wget|iwr|irm)\b.+\|\s*(bash|sh|powershell|pwsh)", command)
        or re.search(r"(?i)(bash|sh|powershell|pwsh)\s+-c", command)
        or re.search(r"&&|\|\|", command)
    )


def _is_env_reference(value: str) -> bool:
    return bool(re.fullmatch(r"(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\{env:[A-Za-z_][A-Za-z0-9_]*\})", value))


def _redact(value: str) -> str:
    if len(value) <= 12:
        return "[redacted]"
    return f"{value[:6]}...[redacted]...{value[-4:]}"
