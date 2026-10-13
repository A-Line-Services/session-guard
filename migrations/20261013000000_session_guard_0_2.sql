-- session-guard 0.2

-- What the guard knew about the client: country, city, network, anonymizer, browser, OS.
ALTER TABLE session_guard_events ADD COLUMN client jsonb NOT NULL DEFAULT '{}';

CREATE TABLE session_guard_subject_claims (
    subject text NOT NULL,
    kind text NOT NULL,
    claimed_at timestamptz NOT NULL,
    PRIMARY KEY (subject, kind)
);

CREATE INDEX session_guard_subject_claims_claimed_at_idx ON session_guard_subject_claims (claimed_at);

-- Where the session started; NULL for sessions created before 0.2.
ALTER TABLE session_guard_sessions ADD COLUMN origin jsonb NULL;
