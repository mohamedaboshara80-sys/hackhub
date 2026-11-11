CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('host','participant','admin')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hackathons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    domains TEXT NOT NULL,          -- comma-separated, e.g. "AI, Web Dev"
    duration TEXT NOT NULL,         -- e.g. "48 hours"
    start_date TEXT NOT NULL,       -- YYYY-MM-DD
    terms TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hackathon_id INTEGER NOT NULL REFERENCES hackathons(id) ON DELETE CASCADE,
    applicant_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    participant_username TEXT NOT NULL,
    team_members TEXT NOT NULL,     -- comma-separated usernames
    institutions TEXT NOT NULL,
    team_name TEXT NOT NULL,
    team_leader TEXT NOT NULL,
    project_name TEXT NOT NULL,
    domain TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (hackathon_id, applicant_id)
);
