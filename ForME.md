# MCP Sentinel - Project Handoff and Interview Notes

## One-sentence description

**MCP Sentinel is a security scanner for Model Context Protocol (MCP) servers that detects tool poisoning in MCP metadata and responses, plus risky patterns in Python server code.**

## What problem it solves

MCP lets AI agents connect to external servers that expose tools such as file access, search, databases, and APIs. Those tools become part of the agent's operational surface. A malicious or compromised MCP server can:

- Hide instructions in a tool description or parameter description that try to manipulate the AI agent.
- Return malicious instructions at runtime after appearing safe during discovery.
- Contain server-side implementation flaws, such as command injection, path traversal, SSRF, unsafe evaluation, or unsafe deserialization.

MCP Sentinel gives developers a way to inspect that surface before an agent trusts it and to return structured evidence that a client can use for deterministic policy enforcement.

## What it does

| Component | Input | Detection approach | Output |
|---|---|---|---|
| Description scanner | MCP `tools/list` manifests and parameter descriptions | Regex/heuristic signals plus optional Gemini semantic reasoning | CLEAN / SUSPICIOUS / MALICIOUS verdict, score, evidence |
| Code scanner | Python MCP server source supplied by the user/client | AST-based static analysis with lightweight intra-function variable tracking | Vulnerability findings, lines, risk score |
| Runtime response guard | Captured plain text or JSON MCP tool result | Detects model-directed instructions, exfiltration signals, shadowing, invisible content | Verdict, score, findings, block recommendation |
| MCP server adapter | Client-supplied metadata, source, or responses | Exposes the scanners as MCP tools over stdio | Structured JSON including `should_block` |

## Detection details

### Tool poisoning / metadata scanning

The description scanner combines independent signals:

1. Imperative model-directed language such as "ignore previous instructions," "first call," or attempts to hide actions from the user.
2. Data-exfiltration indicators such as URLs, credential references, environment variables, `.env`, or sensitive file paths.
3. Tool-shadowing language that attempts to override another tool's behavior.
4. Structural anomalies such as zero-width Unicode characters, HTML comments, and unusually long descriptions.
5. Optional Gemini semantic classification to catch paraphrased attacks that regex misses.

Signals use weighted scoring and are capped at 1.0. Scores at least 0.70 are `MALICIOUS`; scores from 0.35 to 0.69 are `SUSPICIOUS`; lower scores are `CLEAN`.

### Python code scanning

The AST scanner flags dynamically constructed calls to:

- `os.system`, `subprocess.*` with raw/dynamic commands or `shell=True` - command injection.
- `eval` or `exec` - unsafe evaluation.
- `pickle.load(s)` and `yaml.load` - unsafe deserialization.
- `requests` / `httpx` / `urlopen` with dynamic URLs and no visible allow-list signal - SSRF.
- `open`, `Path`, and path joins with dynamic paths and no visible normalization/allow-list signal - path traversal.

It avoids one important false positive: `subprocess.run(cmd)` is not flagged when `cmd` was assigned a list literal earlier in the same function and `shell=True` is absent. This is deliberately lightweight data-flow tracking, not full taint analysis.

### Runtime response guard

The runtime guard accepts captured tool-result text or common JSON-RPC/MCP response shapes. It should run before untrusted output is inserted into an LLM's context. It detects the same poisoning indicators but labels them as runtime findings.

The current implementation is a reusable inspection component and CLI command, not yet a transparent streaming proxy that sits between every client and server.

## Gemini semantic pass

The semantic pass is optional and uses a Google AI Studio key through `GEMINI_API_KEY` or `GOOGLE_API_KEY`.

- Default model: `gemini-3.6-flash`.
- Override: `GEMINI_MODEL`.
- The scanner batches all descriptions in one manifest into one Gemini call, preventing free-tier request-limit problems.
- The model is asked to return JSON only. The implementation validates required fields and clamps confidence values.
- Tool metadata is explicitly marked as **untrusted evidence**, not instructions. This reduces the chance that the auditing model follows a malicious description, but it does not make LLM prompt injection impossible.
- The Gemini result is an additional signal only. The client must enforce `should_block` deterministically; an LLM must never be the enforcement authority.

Privacy note: enabling Gemini sends the descriptions being scanned to Google's API. Keep the semantic pass off for confidential manifests unless that external processing is permitted.

## MCP integration

Run the project as an MCP server with:

```bash
sentinel-mcp
```

It exposes these tools to any **MCP-compatible client**:

- `scan_tool_manifest(manifest, enable_semantic_llm=False)`
- `scan_python_source(source, filename="server.py")`
- `scan_tool_response(tool_name, response)`
- `get_security_policy()`

The MCP server intentionally accepts content supplied by the client instead of arbitrary host file paths. It does not execute tools and does not expose arbitrary local-file reads. This keeps the security tool from becoming an escalation path itself.

## Architecture

```text
MCP client / AI agent
        |
        | client supplies manifest, Python source, or captured tool response
        v
MCP Sentinel CLI or MCP server
        |
        +--> Description scanner ----> deterministic signals
        |                              + optional Gemini semantic signal
        +--> Python AST scanner ------> code findings
        +--> Runtime response guard --> runtime findings
        |
        v
Structured verdict + evidence + should_block
        |
        v
Client policy layer blocks, warns, or allows (not the LLM)
```

## Verified benchmark results

The included benchmark is a small, labeled, synthetic regression suite: 13 tool descriptions (8 malicious, 5 clean) and 2 Python fixtures (1 vulnerable, 1 clean).

| Scanner | Precision | Recall | F1 |
|---|---:|---:|---:|
| Regex-only description scanner | 100.0% | 62.5% | 76.9% |
| Regex + Gemini semantic pass | 100.0% | 100.0% | 100.0% |
| Python code scanner | 100.0% | 100.0% | 100.0% |

Correct way to state this:

> On the current small, synthetic 13-tool fixture suite, Gemini recovered all three paraphrased poisoning cases missed by regex, improving recall from 62.5% to 100% without false positives.

Incorrect claim:

> "MCP Sentinel is 100% accurate in the real world."

The benchmark should be expanded with real, independently sourced, adversarial, and clean fixtures before making broad accuracy claims.

## Commands

Create and use the local environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

Run the CLI:

```bash
.venv/bin/sentinel
.venv/bin/sentinel scan-manifest benchmark/malicious/manifest_1.json
.venv/bin/sentinel scan-code benchmark/malicious/server_vulnerable.py
.venv/bin/sentinel scan-response benchmark/malicious/runtime_response_1.json search_documents
.venv/bin/sentinel benchmark
```

Enable Gemini only when appropriate:

```bash
export GEMINI_API_KEY="your-key"
export GEMINI_MODEL="gemini-3.6-flash"  # optional; this is the default
.venv/bin/sentinel benchmark
```

Run regression tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Technology stack

- Python 3.10+
- Standard-library `ast` for static analysis
- `re` and Unicode analysis for text heuristics
- Google Gemini REST API for optional semantic classification
- MCP Python SDK v2 for the stdio MCP server
- Rich and pyfiglet for the terminal interface
- `unittest` for regression tests

## Resume paragraph

Built **MCP Sentinel**, an MCP-native security scanner and policy service for AI agents. Developed multi-signal detection for tool-description poisoning and runtime prompt injection, AST-based analysis for Python MCP-server vulnerabilities, and an optional Gemini semantic pass hardened by treating scanned metadata as untrusted evidence. Packaged the system as a CLI and MCP server with structured, deterministic `should_block` outputs, labeled regression benchmarks, and precision/recall/F1 evaluation.

## Resume bullet options

Choose two or three depending on available space:

- Built MCP Sentinel, a Python CLI and MCP-native security service that scans AI-agent tool metadata, Python server code, and runtime tool responses for prompt injection and implementation risks.
- Designed a multi-signal tool-poisoning detector combining imperative-language, data-exfiltration, tool-shadowing, and hidden-content signals with an opt-in Gemini semantic classifier.
- Improved poisoning-detection recall from **62.5% to 100%** on a 13-tool labeled synthetic regression suite while preserving **100% precision**; report scope is limited to the bundled benchmark.
- Implemented AST-based checks for command injection, unsafe evaluation, path traversal, SSRF, and unsafe deserialization, including lightweight intra-function tracking to reduce false positives.
- Exposed deterministic, evidence-based scan results through an MCP server so MCP-compatible clients can enforce `should_block` policies without delegating security decisions to an LLM.

## Short portfolio/GitHub description

MCP Sentinel is a security scanner for AI agents that use Model Context Protocol servers. It detects poisoned tool descriptions, suspicious runtime tool responses, and risky Python server patterns, then returns structured evidence that an MCP-compatible client can use to block or review unsafe tools.

## Likely interview questions and strong answers

### What is tool poisoning?

Tool poisoning is an indirect prompt-injection attack. An MCP server places instructions in metadata or output that is later shown to an LLM. The text may tell the model to call another tool, hide its action, leak data, or override instructions. The model can treat this content as trusted context even though it came from an untrusted external server.

### Why use both regex and an LLM?

Regex is cheap, deterministic, fast, and easy to audit, but it misses paraphrases. An LLM can reason about intent and catch novel wording, but it is slower, costs money, can fail, and can itself be influenced by untrusted text. Combining them gives high-confidence deterministic signals plus an optional semantic signal. The system remains useful offline.

### How did you protect the auditor LLM from prompt injection?

I explicitly framed descriptions as untrusted evidence, separated them from audit instructions with a structured boundary, requested structured JSON, validated the returned fields, and kept final enforcement outside the LLM. These are defense-in-depth measures, not proof that prompt injection is solved.

### Why should the LLM not decide whether to block something?

Security enforcement needs predictable, auditable behavior. An LLM can be inconsistent, vulnerable to adversarial inputs, and difficult to reproduce. Sentinel returns deterministic scores and evidence; a client-side policy decides whether to block, warn, or allow.

### What are the code scanner's limitations?

It is static pattern analysis with small intra-function tracking, not full taint analysis. It can miss conditional reassignment, cross-function propagation, aliasing, framework-specific sinks, and non-Python code. It can also produce false positives because an allow-list check is inferred heuristically. A production version could integrate Semgrep, CodeQL, or a real control-flow/taint engine.

### Why does the benchmark not prove 100% real-world accuracy?

The fixtures are small and synthetic. They are valuable as repeatable regression tests but do not represent the diversity of production MCP servers, evasions, clean edge cases, model versions, or adversarial behavior. I would expand it before making general claims.

### What would you build next?

1. A transparent MCP streaming proxy that intercepts `tools/list` and `tools/call` responses automatically.
2. A larger benchmark with independently sourced real-world examples and blind test splits.
3. Per-signal explanations, configurable policy thresholds, SARIF/JSON export, and CI integration.
4. Better code analysis using control-flow and taint tracking, plus support for TypeScript and other MCP-server languages.
5. Telemetry and versioned security baselines for monitoring behavior changes over time.

## GitHub safety checklist

Before committing, confirm that `.venv/`, `.env`, and generated `*.egg-info/` files are absent from `git status`. The project `.gitignore` is set up to exclude them.

Never commit an API key. If a real key was ever pasted into a public location or committed, create a new key, update your local environment, and disable/delete the old key in Google AI Studio or Google Cloud Console.
