-- session-guard 0.2

-- What the guard knew about the client: country, city, network, anonymizer, browser, OS.
ALTER TABLE session_guard_events ADD COLUMN client jsonb NOT NULL DEFAULT '{}';
