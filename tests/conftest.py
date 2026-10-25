import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_tmp = tempfile.mkdtemp()
os.environ["DATABASE"] = os.path.join(_tmp, "test.db")
os.environ["AUTH_LOG"] = os.path.join(_tmp, "auth.log")

from app import app as flask_app          # noqa: E402
from extensions import limiter            # noqa: E402
import db                                 # noqa: E402

BASE = "https://localhost:5000"           # https so the test client sends Secure cookies


@pytest.fixture(autouse=True)
def clean():
    import sqlite3
    con = sqlite3.connect(os.environ["DATABASE"])
    for t in ("sessions", "tokens", "backup_codes", "passkeys", "outbox", "events", "users"):
        con.execute(f"DELETE FROM {t}")
    con.commit(); con.close()
    limiter.reset()
    yield


@pytest.fixture
def app():
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()
