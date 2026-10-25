"""SQLite storage. One connection per request, schema created on first start."""
import os
import sqlite3
import time

from flask import g

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    display_name  TEXT NOT NULL,
    user_handle   BLOB UNIQUE NOT NULL,          -- random WebAuthn user.id, never the e-mail
    grp           TEXT NOT NULL DEFAULT 'students',
    role          TEXT NOT NULL DEFAULT 'user',  -- user | admin
    status        TEXT NOT NULL DEFAULT 'active',-- active | disabled
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB UNIQUE NOT NULL,
    public_key    BLOB NOT NULL,                 -- only the public key is stored
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT,
    backed_up     INTEGER NOT NULL DEFAULT 0,    -- 1 = synced passkey
    name          TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);
CREATE TABLE IF NOT EXISTS backup_codes (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash     TEXT NOT NULL,                 -- Argon2id
    created_at    INTEGER NOT NULL,
    used_at       INTEGER
);
CREATE TABLE IF NOT EXISTS tokens (
    id            INTEGER PRIMARY KEY,
    token_hash    TEXT UNIQUE NOT NULL,          -- SHA-256 of the link token
    purpose       TEXT NOT NULL,                 -- signup | login | reset | enroll
    email         TEXT NOT NULL,
    payload       TEXT,
    bind_hash     TEXT,                          -- SHA-256 of the requesting browser's bind cookie
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    used_at       INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash       TEXT PRIMARY KEY,              -- SHA-256 of the cookie value
    user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
    data          TEXT NOT NULL DEFAULT '{}',
    auth_method   TEXT,
    auth_at       INTEGER,
    created_at    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    ip            TEXT,
    user_agent    TEXT
);
CREATE TABLE IF NOT EXISTS outbox (
    id            INTEGER PRIMARY KEY,
    to_email      TEXT NOT NULL,
    subject       TEXT NOT NULL,
    body          TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    event         TEXT NOT NULL,
    outcome       TEXT NOT NULL,
    user_id       INTEGER,
    email         TEXT,
    ip            TEXT,
    detail        TEXT
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(config.DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(config.DATABASE), exist_ok=True)
    con = sqlite3.connect(config.DATABASE)
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def now():
    return int(time.time())


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur
