# Test fixture: code that must produce no findings.
import hashlib
import logging
import subprocess

log = logging.getLogger(__name__)


def find_user(cur, name):
    cur.execute("SELECT id, name FROM users WHERE name = %s", (name,))
    return cur.fetchone()


def list_dir(path):
    return subprocess.run(["ls", "-l", path], check=True, capture_output=True).stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(value, default=None):
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        log.warning("not a number: %r", value)
        return default
