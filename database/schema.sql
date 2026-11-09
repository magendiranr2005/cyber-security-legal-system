CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT,
    username TEXT UNIQUE,
    password_hash TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_ref TEXT UNIQUE,
    complaint TEXT NOT NULL,
    detected_category TEXT,
    related_category TEXT,
    confidence INTEGER DEFAULT 0,
    urgency TEXT DEFAULT 'LOW',
    indicators TEXT,
    follow_up_answers TEXT,
    legal_guidance TEXT,
    evidence TEXT,
    next_steps TEXT,
    assessment_json TEXT,
    session_id TEXT,
    status TEXT DEFAULT 'Saved',
    user_id INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS report_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER,
    sender TEXT CHECK(sender IN ('user', 'assistant')),
    message TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(report_id) REFERENCES reports(id)
);
