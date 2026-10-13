"""
A small sample app with several common security mistakes, built in on
purpose for CodeAlpha Task 3 (Secure Coding Review).

This is a mock "user login and notes" app. Do not use any of this
code's patterns in a real project.
"""

import os
import sqlite3
import hashlib
import subprocess

# --- Issue 1: FIXED - credentials now loaded from environment variables ---
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
API_KEY = os.environ.get("API_KEY", "")


def connect_db():
    conn = sqlite3.connect("app.db")
    return conn


def create_user_table():
    conn = connect_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()


def get_user(username):
    conn = connect_db()
    # FIXED - parameterized query, username is passed separately, never
    # inserted into the SQL text itself
    query = "SELECT * FROM users WHERE username = ?"
    cursor = conn.execute(query, (username,))
    return cursor.fetchone()


# --- Issue 3: weak password hashing ---
def hash_password(password):
    # FIXED - scrypt is a slow, salted hash designed for passwords.
    # A random salt means the same password produces a different hash
    # every time, which stops attackers using precomputed lookup tables.
    salt = os.urandom(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return salt.hex() + ":" + hashed.hex()


# --- Issue 4: command injection ---
import re

def ping_host(hostname):
    # FIXED - reject anything that isn't a plausible hostname/IP before
    # it ever reaches a command, and run without invoking a shell.
    if not re.match(r"^[a-zA-Z0-9.\-]+$", hostname):
        return "Invalid hostname"
    result = subprocess.run(
        [r"C:\Windows\System32\PING.EXE", "-n", "1", hostname],
        capture_output=True, text=True, shell=False
    )  # nosec B603 -- hostname is validated above with a regex allowlist, shell=False
    return result.stdout


# --- Issue 5: unsafe eval of user input ---
import ast
import operator

_ALLOWED_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg,
}

def _safe_eval(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("Unsupported expression")

def calculate(expression):
    # FIXED - only numbers and + - * / are allowed, parsed as a syntax
    # tree rather than executed as Python code. Anything else (imports,
    # function calls, attribute access) raises an error instead of running.
    tree = ast.parse(expression, mode="eval")
    return _safe_eval(tree.body)


# --- Issue 6: insecure deserialization-style shortcut ---
# A fixed allowlist of commands this function is permitted to run.
# Nothing outside this dictionary can ever be executed, no matter
# what text is passed in.
_ALLOWED_COMMANDS = {
    "check_disk_space": ["wmic", "logicaldisk", "get", "size,freespace,caption"],
    "list_processes": ["tasklist"],
}

def run_saved_command(command_name):
    # FIXED - no longer runs arbitrary text as a shell command. Only
    # names in _ALLOWED_COMMANDS can run, and each maps to a fixed,
    # pre-written command list, never user-supplied text.
    if command_name not in _ALLOWED_COMMANDS:
        return f"Unknown command: {command_name}"
    result = subprocess.run(
        _ALLOWED_COMMANDS[command_name],
        capture_output=True, text=True, shell=False
    )  # nosec B603 -- command_name is checked against a fixed allowlist above, never arbitrary text
    return result.stdout


if __name__ == "__main__":
    create_user_table()
    print("Ping test:", ping_host("127.0.0.1"))
    print("Calc test:", calculate("2 + 2"))
    print("Command test:", run_saved_command("list_processes"))
    