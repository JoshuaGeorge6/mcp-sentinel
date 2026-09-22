# MCP Sentinel

![MCP Sentinel terminal UI](https://github.com/user-attachments/assets/45ddcc92-884d-4a00-a50d-51ab2ef3afb5)

MCP Sentinel is a security scanner for AI agents that use Model Context Protocol (MCP) servers. It helps developers spot risky MCP tools before an AI agent trusts them.

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
```

Run the interactive terminal tool:

```bash
.venv/bin/sentinel
```

Or run scans directly:

```bash
.venv/bin/sentinel scan-manifest benchmark/malicious/manifest_1.json
.venv/bin/sentinel scan-code benchmark/malicious/server_vulnerable.py
.venv/bin/sentinel scan-response benchmark/malicious/runtime_response_1.json search_documents
.venv/bin/sentinel benchmark
```

## Optional Gemini semantic check

The scanner works without an API key using deterministic checks. Optionally, add a Google AI Studio Gemini API key to help identify paraphrased tool-poisoning attacks that simple patterns might miss:

```bash
export GEMINI_API_KEY="your-google-ai-studio-key"
.venv/bin/sentinel benchmark
```

The default model is `gemini-3.6-flash`. To choose another available model:

```bash
export GEMINI_MODEL="your-model-id"
```

Do not commit API keys. Keep them in your terminal environment or a local `.env` file, which is ignored by Git.

## Use as an MCP server

Start the MCP server over stdio:

```bash
.venv/bin/sentinel-mcp
```

It provides tools to scan MCP manifests, Python source code, and captured tool responses. The connected client receives structured findings and a `should_block` recommendation.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Notes

- The included benchmark is small and synthetic. It is useful for regression testing, not for claiming real-world perfect accuracy.
- The optional Gemini check sends scanned descriptions to Google's API. Leave it disabled for confidential content unless that data sharing is acceptable.
