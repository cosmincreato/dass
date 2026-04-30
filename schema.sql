DROP TABLE IF EXISTS users;

DROP TABLE IF EXISTS tickets;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER' CHECK (role IN ('USER', 'MANAGER')),
    created_at TEXT NOT NULL,
    locked INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT DEFAULT NULL,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    password_reset_token TEXT DEFAULT NULL
);

CREATE TABLE tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (
        severity IN ('LOW', 'MED', 'HIGH')
    ),
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (
        status IN (
            'OPEN',
            'IN_PROGRESS',
            'RESOLVED'
        )
    ),
    owner_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users (id)
);