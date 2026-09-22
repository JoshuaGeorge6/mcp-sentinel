# MCP Sentinel
<img width="1901" height="374" alt="image" src="https://github.com/user-attachments/assets/45ddcc92-884d-4a00-a50d-51ab2ef3afb5" />

MCP Sentinel is a security scanner for AI agents that use Model Context Protocol (MCP) servers.

It helps developers spot risky MCP tools before an AI agent trusts them.

## What it checks

- **Tool descriptions:** hidden instructions, data-exfiltration attempts, tool shadowing, and hidden text.
- **Python MCP server code:** command injection, unsafe `eval`, path traversal, SSRF, and unsafe deserialization patterns.
- **Tool responses:** suspicious instructions returned at runtime before they enter an AI agent's context.

MCP Sentinel works as a terminal tool and as an MCP server that an MCP-compatible AI client can call.

## Quick start

```bash
git clone https://github.com/JoshuaGeorge6/mcp-sentinel.git
cd mcp-sentinel

python3 -m venv .venv
.venv/bin/pip install -e .
