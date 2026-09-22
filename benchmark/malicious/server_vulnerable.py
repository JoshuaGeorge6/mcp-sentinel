"""Example MCP server tool implementations with real vulnerability patterns.
Used only as a benchmark fixture for code_scanner.py — not executed."""

import os
import subprocess
import requests


def search_files(query: str, directory: str):
    # Command injection: user-controlled query passed straight into a shell.
    cmd = f"grep -r {query} {directory}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def run_calc(expression: str):
    # Unsafe eval on tool-call input.
    return eval(expression)


def read_user_file(path: str):
    # Path traversal: no normalization/allow-list check on the path argument.
    full_path = os.path.join("/data/uploads", path)
    with open(full_path, "r") as f:
        return f.read()


def fetch_webhook(url: str):
    # SSRF: arbitrary attacker-supplied URL fetched server-side.
    return requests.get(url).text
