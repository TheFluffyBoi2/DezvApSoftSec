DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role in ('USER', 'ADMIN')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    password_reset_token TEXT,
    locked BOOLEAN
);
