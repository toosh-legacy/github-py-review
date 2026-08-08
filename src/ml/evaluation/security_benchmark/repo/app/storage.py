"""Data access for the benchmark fixture app.

BENCHMARK FIXTURE — the unsafe patterns below are planted deliberately.
"""
import hashlib
import json
import pickle
import sqlite3
import subprocess

import yaml


# --- planted: must be detected -------------------------------------------- #
def find_order(conn: sqlite3.Connection, order_id: str):
    query = "SELECT * FROM orders WHERE id = " + order_id
    return conn.execute(query).fetchall()


def restore_session(blob: bytes):
    return pickle.loads(blob)


def load_config(text: str):
    return yaml.load(text)


def compute(expression: str):
    return eval(expression)


def checksum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def archive(path: str):
    subprocess.call("tar -czf backup.tgz " + path, shell=True)


# --- decoys: must NOT be detected ------------------------------------------ #
def find_order_safely(conn: sqlite3.Connection, order_id: str):
    """Parameter binding — the value can never be parsed as SQL."""
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchall()


def restore_session_safely(blob: bytes):
    """JSON cannot carry executable constructors."""
    return json.loads(blob)


def load_config_safely(text: str):
    return yaml.safe_load(text)


def content_digest(data: bytes) -> str:
    """SHA-256 for integrity — not a broken hash."""
    return hashlib.sha256(data).hexdigest()


def archive_safely(path: str):
    """Argument list, no shell: the path cannot inject a second command."""
    subprocess.run(["tar", "-czf", "backup.tgz", path], check=True)


def describe_eval():
    """The word `eval` in a docstring and a string is not a call site."""
    return "this function does not call eval(x) at all"
