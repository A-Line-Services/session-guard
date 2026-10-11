-- session-guard schema. Tracked in its own `_session_guard_migrations` table.

CREATE TABLE session_guard_sessions (
    id uuid PRIMARY KEY,
    subject text NOT NULL,
    created_at timestamptz NOT NULL,
    authenticated_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    step_up_required boolean NOT NULL DEFAULT false,
    baseline jsonb NOT NULL
);

CREATE INDEX session_guard_sessions_subject_idx ON session_guard_sessions (subject);
CREATE INDEX session_guard_sessions_expires_at_idx ON session_guard_sessions (expires_at);
CREATE INDEX session_guard_sessions_last_seen_at_idx ON session_guard_sessions (last_seen_at);

CREATE TABLE session_guard_tokens (
    hash bytea PRIMARY KEY CHECK (octet_length(hash) = 32),
    session_id uuid NOT NULL REFERENCES session_guard_sessions (id) ON DELETE CASCADE,
    -- Issue order within a session; `issued_at` can tie.
    seq bigint GENERATED ALWAYS AS IDENTITY,
    issued_at timestamptz NOT NULL,
    first_used_at timestamptz,
    superseded_at timestamptz
);

-- At most one current token per session.
CREATE UNIQUE INDEX session_guard_tokens_current_idx
    ON session_guard_tokens (session_id) WHERE superseded_at IS NULL;
CREATE INDEX session_guard_tokens_session_idx ON session_guard_tokens (session_id, seq);

CREATE TABLE session_guard_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- No foreign key: events outlive their sessions.
    session_id uuid NOT NULL,
    subject text NOT NULL,
    kind text NOT NULL,
    enforced boolean NOT NULL,
    score bigint,
    signals text[] NOT NULL DEFAULT '{}',
    ip inet NOT NULL,
    user_agent text,
    created_at timestamptz NOT NULL
);

CREATE INDEX session_guard_events_created_at_idx ON session_guard_events (created_at);
CREATE INDEX session_guard_events_session_id_idx ON session_guard_events (session_id);
CREATE INDEX session_guard_events_subject_idx ON session_guard_events (subject);

CREATE TABLE session_guard_event_claims (
    session_id uuid NOT NULL,
    kind text NOT NULL,
    claimed_at timestamptz NOT NULL,
    PRIMARY KEY (session_id, kind)
);

CREATE INDEX session_guard_event_claims_claimed_at_idx ON session_guard_event_claims (claimed_at);
