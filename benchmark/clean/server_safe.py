"""Example MCP server tool implementations written defensively.
Used only as a benchmark fixture for code_scanner.py — not executed."""

import os
import subprocess
import requests

ALLOWED_HOSTS = {"api.internal.example"}
BASE_DIR = os.path.abspath("/data/uploads")


def search_files(query: str, directory: str):
    # No shell=True, arguments passed as a list so nothing gets interpreted
    # by a shell; ripgrep itself treats query as a literal pattern.
    cmd = ["grep", "-r", query, directory]
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def compute(a: float, b: float, op: str):
    # No eval — explicit whitelist of allowed operations.
    ops = {"add": lambda: a + b, "sub": lambda: a - b, "mul": lambda: a * b}
    if op not in ops:
        raise ValueError("unsupported operation")
    return ops[op]()


def read_user_file(path: str):
    # Path normalized and checked against the intended base directory.
    full_path = os.path.abspath(os.path.join(BASE_DIR, path))
    if not full_path.startswith(BASE_DIR):
        raise ValueError("path traversal detected")
    with open(full_path, "r") as f:
        return f.read()


def fetch_internal_status(host: str):
    # Host checked against an allow-list before any network call.
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(f"https://{host}/status").text
