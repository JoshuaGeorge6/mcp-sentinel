"""
Static scanner for MCP *server implementation* source code.

Independent field assessments in 2025-2026 found these vulnerability classes
extremely common across real MCP servers:
  - Command injection   (~43% of tested servers — Equixly offensive-security
                          assessment)
  - Path traversal       (~82% of file-operation-using servers across 2,614
                          implementations — Endor Labs)
  - SSRF                 (~30-37% of servers — Equixly / BlueRock Security)

This module does lightweight AST + regex analysis (no execution) over Python
MCP server source to flag these patterns. It intentionally favors recall over
precision (it's a scanner meant to flag things for human review, not a
compiler) — see README for the precision/recall tradeoff discussion.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum


class VulnClass(str, Enum):
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    UNSAFE_EVAL = "unsafe_eval"


@dataclass
class CodeFinding:
    vuln_class: VulnClass
    line: int
    snippet: str
    detail: str


@dataclass
class CodeScanResult:
    filepath: str
    findings: list[CodeFinding] = field(default_factory=list)

    @property
    def risk_score(self) -> float:
        weights = {
            VulnClass.COMMAND_INJECTION: 0.35,
            VulnClass.UNSAFE_EVAL: 0.35,
            VulnClass.PATH_TRAVERSAL: 0.2,
            VulnClass.SSRF: 0.25,
            VulnClass.UNSAFE_DESERIALIZATION: 0.3,
        }
        score = sum(weights.get(f.vuln_class, 0.1) for f in self.findings)
        return min(score, 1.0)


# Call patterns that are almost always attacker-controllable if fed
# user/tool-argument input without sanitization.
DANGEROUS_CALLS = {
    "os.system": VulnClass.COMMAND_INJECTION,
    "subprocess.call": VulnClass.COMMAND_INJECTION,
    "subprocess.run": VulnClass.COMMAND_INJECTION,
    "subprocess.Popen": VulnClass.COMMAND_INJECTION,
    "eval": VulnClass.UNSAFE_EVAL,
    "exec": VulnClass.UNSAFE_EVAL,
    "pickle.loads": VulnClass.UNSAFE_DESERIALIZATION,
    "pickle.load": VulnClass.UNSAFE_DESERIALIZATION,
    "yaml.load": VulnClass.UNSAFE_DESERIALIZATION,
}

# Requests/httpx calls whose URL argument traces back to a function parameter
# (rather than a hardcoded string) are a classic SSRF shape.
NETWORK_CALLS = {"requests.get", "requests.post", "httpx.get", "httpx.post", "urlopen"}

PATH_FUNCS = {"open", "os.path.join", "Path"}


def _dotted_name(node: ast.AST) -> str | None:
    """Resolve `os.system(...)` style calls to a dotted string."""
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _arg_is_dynamic(arg: ast.AST) -> bool:
    """True if the argument is NOT a hardcoded string literal — i.e. it's
    built from a variable, f-string, or concatenation, which means it could
    carry attacker-controlled tool-call input straight into a dangerous sink."""
    if isinstance(arg, ast.Constant):
        return False
    return True


def _resolve_to_list_literal(
    name_node: ast.Name, func_node: ast.FunctionDef, call_line: int
) -> bool:
    """
    Minimal intra-function data-flow: if `name_node` is a bare variable name,
    walk the enclosing function for the most recent prior assignment to that
    name and check whether it was a list literal (the safe subprocess arg
    shape). This is NOT full data-flow analysis — it won't follow the value
    across function boundaries, conditionals, or reassignment after the call —
    but it resolves the common "cmd = [...]" pattern seen in most real MCP
    servers, without the false-positive rate of ignoring variables entirely.
    Documented limitation: a genuine taint-tracking pass (e.g. via a tool
    like Semgrep with custom rules, or a full CFG) would be needed for
    complete coverage; that's out of scope for this static pass.
    """
    if not isinstance(name_node, ast.Name):
        return False
    latest_assignment: ast.AST | None = None
    for stmt in ast.walk(func_node):
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and getattr(stmt, "lineno", 0) < call_line:
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id == name_node.id:
                    if latest_assignment is None or stmt.lineno > latest_assignment.lineno:
                        latest_assignment = stmt
    return bool(latest_assignment and isinstance(latest_assignment.value, ast.List))


def scan_source(filepath: str, source: str) -> CodeScanResult:
    result = CodeScanResult(filepath=filepath)
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        result.findings.append(CodeFinding(
            vuln_class=VulnClass.UNSAFE_EVAL,
            line=e.lineno or 0,
            snippet="<parse error>",
            detail=f"Could not parse file for AST analysis: {e}",
        ))
        return result

    lines = source.splitlines()

    parent_functions: dict[ast.AST, ast.FunctionDef] = {}
    for function in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        for child in ast.walk(function):
            parent_functions.setdefault(child, function)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted_name(node.func)
        if not name:
            continue

        snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""

        if name in DANGEROUS_CALLS:
            vclass = DANGEROUS_CALLS[name]
            dynamic_arg = any(_arg_is_dynamic(a) for a in node.args)
            shell_true = name in ("subprocess.run", "subprocess.call", "subprocess.Popen") and _has_shell_true(node)

            # subprocess with a *list* first argument and no shell=True is the
            # safe pattern (no shell metacharacter interpretation) — only flag
            # subprocess calls when shell=True or the command is a raw/dynamic
            # string rather than an argument list. os.system/eval/exec have no
            # safe form, so any dynamic argument there is still flagged.
            is_subprocess = name.startswith("subprocess.")
            first_arg_is_list = bool(node.args) and isinstance(node.args[0], ast.List)
            enclosing_function = parent_functions.get(node)
            first_arg_is_safe_variable = bool(
                node.args
                and isinstance(node.args[0], ast.Name)
                and enclosing_function
                and _resolve_to_list_literal(node.args[0], enclosing_function, node.lineno)
            )
            if is_subprocess and (first_arg_is_list or first_arg_is_safe_variable) and not shell_true:
                continue

            if dynamic_arg or shell_true:
                detail = (
                    f"`{name}` called with a non-literal argument"
                    + (" and shell=True" if shell_true else "")
                    + " — if this argument traces back to a tool-call parameter, "
                      "this is exploitable command injection / unsafe eval."
                )
                result.findings.append(CodeFinding(
                    vuln_class=vclass, line=node.lineno, snippet=snippet, detail=detail,
                ))

        if name in NETWORK_CALLS:
            dynamic_arg = any(_arg_is_dynamic(a) for a in node.args)
            # Crude proxy for "this file appears to allow-list hosts somewhere":
            # look for common allow-list identifier patterns anywhere in the
            # source. A real implementation would check the enclosing
            # function's control flow for a guard before this call; this
            # whole-file heuristic is a documented limitation (see README).
            has_allowlist_guard = bool(re.search(
                r"ALLOWED_HOSTS|allow[_-]?list|allowed_domains|whitelist", source, re.IGNORECASE
            ))
            if dynamic_arg and not has_allowlist_guard:
                result.findings.append(CodeFinding(
                    vuln_class=VulnClass.SSRF,
                    line=node.lineno,
                    snippet=snippet,
                    detail=f"`{name}` called with a dynamic URL argument and no "
                           f"visible allow-list check nearby — classic SSRF shape "
                           f"if the URL originates from tool-call input.",
                ))

        if name in PATH_FUNCS or (name and name.endswith("open")):
            dynamic_arg = any(_arg_is_dynamic(a) for a in node.args)
            has_traversal_guard = bool(re.search(
                r"resolve\(\)|realpath|os\.path\.abspath|\.startswith\(", "\n".join(lines)
            ))
            if dynamic_arg and not has_traversal_guard:
                result.findings.append(CodeFinding(
                    vuln_class=VulnClass.PATH_TRAVERSAL,
                    line=node.lineno,
                    snippet=snippet,
                    detail=f"`{name}` called with a dynamic path and no path-"
                           f"normalization/allow-list guard found in the file — "
                           f"a '../../' payload in a tool argument could escape "
                           f"the intended directory.",
                ))

    return result
