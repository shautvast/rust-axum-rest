-- Add migration script here
CREATE TABLE users
(
    id       SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email    TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    created_at TIMESTAMP DEFAULT NOW()
)