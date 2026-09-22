# MCP Sentinel

A security scanner + agent for the Model Context Protocol (MCP) ecosystem.
Detects two real, documented attack classes against MCP servers:

1. **Tool description poisoning** — hidden instructions embedded in a tool's
   description/metadata, which get injected straight into an LLM's context
   and treated as trusted input (OWASP MCP Top 10 #3).
2. **Server-side code vulnerabilities** — command injection, path traversal,
   and SSRF patterns in the actual tool implementation code.

## Project layout

```
mcp_sentinel/
  description_scanner.py   # regex + heuristic detection of poisoned tool text
  code_scanner.py           # AST-based detection of dangerous code patterns
  ui.py                     # rich-based terminal UI (banner, live trace, table)
  cli.py                    # ties everything together, the entry point

benchmark/
  malicious/                # known-bad example manifests + server code
  clean/                    # known-good example manifests + server code
```

## How to run it

**Option A — install `sentinel` as a real terminal command (recommended):**
```bash
cd mcp-sentinel
pip install -e . --break-system-packages   # reads pyproject.toml, installs deps + the `sentinel` command

sentinel                                    # launches the interactive menu (banner + choices)
```
Once installed, just typing `sentinel` anywhere drops you into the banner UI, where you
pick a numbered option and it asks for the file path — no need to remember flags or
module paths.

**Option B — run without installing, for scripting/CI:**
```bash
cd mcp-sentinel
pip install rich pyfiglet --break-system-packages

# One-shot commands (skip the interactive menu, useful in scripts):
PYTHONPATH=. python3 -m mcp_sentinel.cli scan-manifest benchmark/malicious/manifest_1.json
PYTHONPATH=. python3 -m mcp_sentinel.cli scan-code benchmark/malicious/server_vulnerable.py
PYTHONPATH=. python3 -m mcp_sentinel.cli scan-response path/to/captured_tool_result.json get_customer
PYTHONPATH=. python3 -m mcp_sentinel.cli benchmark
```

## Optional semantic pass

Set `GEMINI_API_KEY` to enable an opt-in Gemini semantic check during a
manifest scan or benchmark. Google AI Studio keys also work when supplied as
`GOOGLE_API_KEY`. The default model is `gemini-3.6-flash`; override it
with `GEMINI_MODEL` when your account uses a different supported model.

```bash
export GEMINI_API_KEY="..."
export GEMINI_MODEL="gemini-3.6-flash"  # optional override
PYTHONPATH=. python3 -m mcp_sentinel.cli benchmark
```

The semantic pass catches paraphrased attacks that evade static signatures. It
treats each tool description as untrusted evidence, clearly delimits it from
the auditing instructions, and accepts only a validated JSON response. This is
defense in depth, not a guarantee that an auditor LLM is immune to prompt
injection. Findings should remain subject to human review.

## Use MCP Sentinel as an MCP server

MCP Sentinel also runs as a local stdio MCP server, so any **MCP-compatible
client** can call its scanners. It is not tied to a specific LLM provider; the
client supplies the content to scan and receives structured findings plus a
deterministic `should_block` field.

Install the project in an isolated environment, then configure your client to
start `sentinel-mcp` (or `python -m mcp_sentinel.mcp_server`):

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

Example generic MCP client configuration:

```json
{
  "mcpServers": {
    "mcp-sentinel": {
      "command": "/absolute/path/to/mcp-sentinel/.venv/bin/sentinel-mcp"
    }
  }
}
```

The server exposes four tools:

- `scan_tool_manifest`: checks client-supplied `tools/list` metadata for tool poisoning.
- `scan_python_source`: checks client-supplied Python server source for risky patterns.
- `scan_tool_response`: checks a captured text or JSON tool response before it enters model context.
- `get_security_policy`: returns default enforcement guidance and limits.

The MCP server intentionally does **not** accept arbitrary host file paths or
execute tools. A client must apply `should_block` itself; an LLM may explain a
finding but should never decide enforcement.

## Benchmarking

`sentinel benchmark` runs the labeled local fixtures and reports precision,
recall, and F1 for the regex-only scanner, the optional regex-plus-Gemini scanner,
and the Python source scanner. The bundled fixtures are deliberately small and
synthetic; their scores are regression checks, not claims of real-world
performance. Run the LLM comparison with your own API key and record the model
identifier, date, cost, latency, and exact fixture revision when publishing
results.

## Known limitations and next step

- **Runtime response guard** — `scan-response` inspects a captured plain-text
  or JSON MCP tool result before it is placed in model context. Its
  transport-agnostic `scan_tool_response` function can be embedded in a client
  or proxy. A full transparent streaming MCP proxy remains future work.
- **Known limitation:** the code scanner does lightweight intra-function
  variable tracking (e.g. resolving `cmd = [...]` before `subprocess.run(cmd)`)
  but is not full data-flow/taint analysis — it can still miss cases where a
  variable is reassigned conditionally or passed through helper functions.
  A production version would use a proper CFG or a tool like Semgrep.
