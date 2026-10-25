import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_tmp = tempfile.mkdtemp()
os.environ["DATABASE"] = os.path.join(_tmp, "test.db")
os.environ["AUTH_LOG"] = os.path.join(_tmp, "auth.log")

import mailer
from app import app as flask_app
from extensions import limiter

SENT = []
mailer.deliver = lambda to, subject, body: SENT.append((to, subject, body))

BASE = "https://localhost:5000"


@pytest.fixture(autouse=True)
def clean():
    import sqlite3
    con = sqlite3.connect(os.environ["DATABASE"])
    for t in ("sessions", "tokens", "backup_codes", "passkeys", "events", "users"):
        con.execute(f"DELETE FROM {t}")
    con.commit(); con.close()
    limiter.reset()
    SENT.clear()
    yield


@pytest.fixture
def app():
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()
