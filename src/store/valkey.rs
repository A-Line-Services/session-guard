//! Valkey / Redis store.

use std::{fmt, net::IpAddr, sync::LazyLock};

use chrono::{DateTime, TimeDelta, Utc};
use redis::{
    RedisFuture, Script, Value,
    aio::{ConnectionLike, ConnectionManager},
    cluster_async::ClusterConnection,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    ClaimScope, SessionRecord, SessionStore, SessionUpdate, Supersede, TokenLookup, TokenRecord, session_bucket,
    token_bucket,
};
use crate::{
    checks::Check,
    error::StoreError,
    event::{ClientSummary, EventKind, SessionEvent, SessionOrigin},
    fingerprint::Baseline,
    token::TokenHash,
};

/// How many sessions one `delete_expired` script invocation removes at most.
const PURGE_BATCH: usize = 500;

/// How many session ids one `SREM` removes at most.
const SREM_BATCH: usize = 1000;

/// Lua helpers shared by several scripts. `P` is always a bucket prefix (`prefix{bb}:`), so every
/// key a script builds shares the hash slot of the keys it was called with.
macro_rules! lua_helpers {
    () => {
        r"
local function read_session(P, sid)
  local v = redis.call('HMGET', P .. 's:' .. sid,
    'subject', 'created', 'auth', 'seen', 'expires', 'step_up', 'baseline', 'origin')
  if not v[1] then return nil end
  return {sid, v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8] or ''}
end

-- Deletes a session and its tokens; returns its subject, or false if it did not exist.
local function del_session(P, sid)
  local s = P .. 's:' .. sid
  local k = P .. 'k:' .. sid
  local subject = redis.call('HGET', s, 'subject')
  for _, hex in ipairs(redis.call('ZRANGE', k, 0, -1)) do
    redis.call('DEL', P .. 't:' .. hex)
  end
  redis.call('DEL', k)
  redis.call('ZREM', P .. 'x', sid)
  redis.call('ZREM', P .. 'i', sid)
  if subject then
    redis.call('DEL', s)
    return subject
  end
  return false
end
"
    };
}

/// KEYS: session, token, token set, expiry index. ARGV: bucket prefix, sid, token hex, subject,
/// created, auth, seen, expires, `step_up`, baseline, `exp_ms`, origin or `''`.
static INSERT: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local P = ARGV[1]
if redis.call('EXISTS', KEYS[1]) == 1 or redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'subject', ARGV[4], 'created', ARGV[5], 'auth', ARGV[6],
  'seen', ARGV[7], 'expires', ARGV[8], 'step_up', ARGV[9], 'baseline', ARGV[10],
  'exp_ms', ARGV[11], 'cur', ARGV[3], 'seq', 1)
if ARGV[12] ~= '' then redis.call('HSET', KEYS[1], 'origin', ARGV[12]) end
redis.call('HSET', KEYS[2], 'sid', ARGV[2], 'seq', 1, 'issued', ARGV[5])
redis.call('ZADD', KEYS[3], 1, ARGV[3])
redis.call('ZADD', KEYS[4], ARGV[8], ARGV[2])
redis.call('ZADD', P .. 'i', ARGV[7], ARGV[2])
redis.call('PEXPIREAT', KEYS[1], ARGV[11])
redis.call('PEXPIREAT', KEYS[2], ARGV[11])
redis.call('PEXPIREAT', KEYS[3], ARGV[11])
return 1
",
    )
});

/// KEYS: subject set. ARGV: sid, `exp_ms`. Adds a session to the set and keeps the set alive
/// until the latest member expires.
static INDEX_ADD: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
redis.call('SADD', KEYS[1], ARGV[1])
local pt = redis.call('PEXPIRETIME', KEYS[1])
if pt == -1 or pt < tonumber(ARGV[2]) then redis.call('PEXPIREAT', KEYS[1], ARGV[2]) end
return 1
",
    )
});

/// KEYS: subject set, revoking set. Moves every member of the subject set into the revoking set
/// (keeping the later expiry) and returns the revoking set's members, which includes any a
/// crashed revoke left behind.
static INDEX_MOVE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local pt = redis.call('PEXPIRETIME', KEYS[1])
if pt ~= -2 then
  local cur = redis.call('PEXPIRETIME', KEYS[2])
  redis.call('SUNIONSTORE', KEYS[2], KEYS[2], KEYS[1])
  local at = math.max(pt, cur)
  if at > 0 then redis.call('PEXPIREAT', KEYS[2], at) end
  redis.call('DEL', KEYS[1])
end
return redis.call('SMEMBERS', KEYS[2])
",
    )
});

/// KEYS: token. ARGV: bucket prefix.
static FIND: LazyLock<Script> = LazyLock::new(|| {
    Script::new(concat!(
        lua_helpers!(),
        r"
local P = ARGV[1]
local t = redis.call('HMGET', KEYS[1], 'sid', 'seq', 'issued', 'used', 'sup')
if not t[1] then return false end
local rec = read_session(P, t[1])
if not rec then return false end
local newer = 0
for _, hex in ipairs(redis.call('ZRANGEBYSCORE', P .. 'k:' .. t[1], '(' .. t[2], '+inf')) do
  if redis.call('HEXISTS', P .. 't:' .. hex, 'used') == 1 then
    newer = 1
    break
  end
end
rec[10] = t[3]
rec[11] = t[4] or ''
rec[12] = t[5] or ''
rec[13] = tostring(newer)
return rec
",
    ))
});

/// KEYS: session. ARGV: bucket prefix, sid.
static READ: LazyLock<Script> = LazyLock::new(|| {
    Script::new(concat!(
        lua_helpers!(),
        "return read_session(ARGV[1], ARGV[2]) or false\n"
    ))
});

/// KEYS: session. ARGV: bucket prefix, sid, now, supersede mode (`''` for no rotation), mode argument, new token hex,
/// prune cutoff, `mark_used` hex or `''`, baseline or `''`, `step_up` or `''`, auth or `''`.
static APPLY: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local s = KEYS[1]
if redis.call('EXISTS', s) == 0 then return 0 end
local P, sid, now, mode = ARGV[1], ARGV[2], ARGV[3], ARGV[4]
local rotated = 0
if mode ~= '' then
  local cur = redis.call('HGET', s, 'cur')
  if cur then
    local ck = P .. 't:' .. cur
    local holds = false
    if mode == 'exact' then
      holds = cur == ARGV[5]
    elseif mode == 'before' then
      local issued = tonumber(redis.call('HGET', ck, 'issued'))
      holds = issued ~= nil and issued < tonumber(ARGV[5])
    elseif mode == 'current' then
      holds = redis.call('EXISTS', ck) == 1
    end
    local nk = P .. 't:' .. ARGV[6]
    if holds and redis.call('EXISTS', nk) == 0 then
      local k = P .. 'k:' .. sid
      redis.call('HSET', ck, 'sup', now)
      local seq = redis.call('HINCRBY', s, 'seq', 1)
      redis.call('HSET', nk, 'sid', sid, 'seq', seq, 'issued', now)
      local exp = redis.call('HGET', s, 'exp_ms')
      if exp then redis.call('PEXPIREAT', nk, exp) end
      redis.call('ZADD', k, seq, ARGV[6])
      redis.call('HSET', s, 'cur', ARGV[6])
      local cutoff = tonumber(ARGV[7])
      for _, hex in ipairs(redis.call('ZRANGE', k, 0, -1)) do
        local sup = tonumber(redis.call('HGET', P .. 't:' .. hex, 'sup'))
        if sup ~= nil and sup < cutoff then
          redis.call('DEL', P .. 't:' .. hex)
          redis.call('ZREM', k, hex)
        end
      end
      rotated = 1
    end
  end
end
if ARGV[8] ~= '' then
  local mk = P .. 't:' .. ARGV[8]
  if redis.call('HGET', mk, 'sid') == sid and redis.call('HEXISTS', mk, 'used') == 0 then
    redis.call('HSET', mk, 'used', now)
  end
end
redis.call('HSET', s, 'seen', now)
redis.call('ZADD', P .. 'i', now, sid)
if ARGV[9] ~= '' then redis.call('HSET', s, 'baseline', ARGV[9]) end
if ARGV[10] ~= '' then redis.call('HSET', s, 'step_up', ARGV[10]) end
if ARGV[11] ~= '' then redis.call('HSET', s, 'auth', ARGV[11]) end
return rotated
",
    )
});

/// KEYS: session. ARGV: bucket prefix, sid, expected subject (optional). Returns the deleted
/// session's subject, or nothing when it did not exist or belongs to another subject.
static DELETE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(concat!(
        lua_helpers!(),
        r"
if ARGV[3] and redis.call('HGET', KEYS[1], 'subject') ~= ARGV[3] then return false end
return del_session(ARGV[1], ARGV[2])
",
    ))
});

/// KEYS: expiry index. ARGV: bucket prefix, now, idle cutoff, batch size.
static DELETE_EXPIRED: LazyLock<Script> = LazyLock::new(|| {
    Script::new(concat!(
        lua_helpers!(),
        r"
local P = ARGV[1]
local found, n = 0, 0
for _, idx in ipairs({{'x', ARGV[2]}, {'i', ARGV[3]}}) do
  local ids = redis.call('ZRANGEBYSCORE', P .. idx[1], '-inf', idx[2], 'LIMIT', 0, ARGV[4])
  found = found + #ids
  for _, sid in ipairs(ids) do
    if del_session(P, sid) then n = n + 1 end
  end
end
return {n, found}
",
    ))
});

/// KEYS: events, claim index. ARGV: bucket prefix, cutoff.
static DELETE_EVENTS: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local bound = '(' .. ARGV[2]
local n = redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', bound)
for _, m in ipairs(redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', bound)) do
  redis.call('DEL', ARGV[1] .. 'c:' .. m)
end
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', bound)
return n
",
    )
});

/// KEYS: claim, claim index. ARGV: now, window (µs), window (ms), claim index member.
static CLAIM: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local at = tonumber(redis.call('GET', KEYS[1]))
if at ~= nil and tonumber(ARGV[1]) - at < tonumber(ARGV[2]) then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[1], ARGV[4])
return 1
",
    )
});

/// Standalone or cluster connection behind one type, so the store has a single code path.
#[derive(Clone)]
enum Conn {
    Standalone(ConnectionManager),
    Cluster(ClusterConnection),
}

impl ConnectionLike for Conn {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a redis::Cmd) -> RedisFuture<'a, Value> {
        match self {
            Self::Standalone(conn) => conn.req_packed_command(cmd),
            Self::Cluster(conn) => conn.req_packed_command(cmd),
        }
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        pipeline: &'a redis::Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        match self {
            Self::Standalone(conn) => conn.req_packed_commands(pipeline, offset, count),
            Self::Cluster(conn) => conn.req_packed_commands(pipeline, offset, count),
        }
    }

    fn get_db(&self) -> i64 {
        match self {
            Self::Standalone(conn) => conn.get_db(),
            Self::Cluster(conn) => conn.get_db(),
        }
    }
}

/// A [`SessionStore`] on Valkey or Redis, standalone or Cluster.
///
/// Every write that touches more than one key runs as a Lua script, so it is atomic across any
/// number of processes sharing the server. Requires Valkey 7.2+ or Redis 7.0+.
///
/// # Cluster
///
/// Connect with [`connect_cluster`](Self::connect_cluster) or
/// [`from_cluster`](Self::from_cluster). Keys are split into 256 fixed buckets, and every key
/// carries its bucket as a hash tag (`{bb}`), so a session, its tokens and its indexes always
/// live in one hash slot and each script runs on one node. The bucket is the last byte of the
/// session id, the first byte of a token's hash, or the first byte of the SHA-256 of a subject.
/// [`Guard`](crate::Guard) mines tokens so that a session's tokens share its bucket; the store
/// rejects writes where they do not.
///
/// The subject index is the one structure that spans buckets: a session id sits in its subject's
/// set while the session lives in its own bucket, so subject-wide operations are eventually
/// consistent. [`delete_subject_sessions`](SessionStore::delete_subject_sessions) moves the set
/// aside, deletes each session in its bucket and then drops the moved ids. If the caller
/// crashes in between, the leftover ids stay pending and the next revoke for the subject
/// finishes them. A session created while a revoke runs is either revoked or its creator gets an
/// error and the session is removed. [`list_subject_sessions`](SessionStore::list_subject_sessions)
/// includes sessions that are mid-revoke.
///
/// [`delete_expired`](SessionStore::delete_expired) and
/// [`delete_events_before`](SessionStore::delete_events_before) visit all 256 buckets.
///
/// # Data layout
///
/// All keys start with the [key prefix](Self::key_prefix) followed by the bucket tag, written
/// `B` here (for example `sg:{0a}:`). Timestamps are microseconds since the Unix epoch as
/// decimal integers.
///
/// | Key | Type | Contents |
/// |-----|------|----------|
/// | `B s:{session id}` | hash | `subject`, `created`, `auth`, `seen`, `expires`, `step_up`, `baseline` (JSON), `origin` (JSON, absent before 0.2), `cur` (current token), `seq` (token counter), `exp_ms` |
/// | `B t:{token hash hex}` | hash | `sid`, `seq` (issue order), `issued`, `used`, `sup` (superseded) |
/// | `B k:{session id}` | sorted set | the session's token hashes, scored by `seq` |
/// | `B u:{subject}` | set | session ids of a subject (in the subject's bucket) |
/// | `B ur:{subject}` | set | ids of a subject being revoked (in the subject's bucket) |
/// | `B x` | sorted set | session ids scored by `expires_at` |
/// | `B i` | sorted set | session ids scored by `last_seen_at` |
/// | `B e` | sorted set | events as JSON, scored by `at` |
/// | `B c:{session id}:{kind}` | string | time of the last session event claim |
/// | `B c:s:{subject}:{kind}` | string | time of the last subject alert claim (subject's bucket) |
/// | `B cz` | sorted set | `{session id}:{kind}` and `s:{subject}:{kind}` claims scored by claim time |
///
/// Session, token and per-session token-set keys expire at the session's absolute expiry and
/// subject sets at their last session's expiry, so Valkey cleans up even if
/// [`delete_expired`](SessionStore::delete_expired) never runs. Because those TTLs follow the
/// server's wall clock, sessions whose `expires_at` is already in the past vanish immediately.
/// Claim keys expire after their window.
///
/// Subjects are passed to scripts as data, never as code.
///
/// Cheap to clone; clones share the connection.
#[derive(Clone)]
pub struct ValkeyStore {
    conn: Conn,
    prefix: String,
}

impl fmt::Debug for ValkeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValkeyStore")
            .field("key_prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl ValkeyStore {
    /// A store on an existing connection, with the default key prefix `sg:`.
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn: Conn::Standalone(conn),
            prefix: "sg:".to_owned(),
        }
    }

    /// A store on an existing Cluster connection, with the default key prefix `sg:`.
    pub fn from_cluster(conn: ClusterConnection) -> Self {
        Self {
            conn: Conn::Cluster(conn),
            prefix: "sg:".to_owned(),
        }
    }

    /// Connects to a Valkey or Redis Cluster through any of its nodes (`redis://`, `rediss://`
    /// or `valkey://` URLs), with the default key prefix `sg:`.
    ///
    /// # Errors
    ///
    /// If a URL is invalid or no node is reachable.
    pub async fn connect_cluster<T: redis::IntoConnectionInfo>(
        nodes: impl IntoIterator<Item = T>,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::cluster::ClusterClient::new(nodes)?;
        Ok(Self::from_cluster(client.get_async_connection().await?))
    }

    /// Connects to `url` (`redis://`, `rediss://` or `valkey://`), with the default key prefix
    /// `sg:`.
    ///
    /// # Errors
    ///
    /// If the URL is invalid or the server is unreachable.
    pub async fn connect(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        Ok(Self::new(ConnectionManager::new(client).await?))
    }

    /// Prefixes every key with `prefix`, so several apps can share one server. Defaults to
    /// `sg:`.
    ///
    /// # Panics
    ///
    /// If `prefix` contains `{` or `}`: the store puts its own hash tag after the prefix, and a
    /// brace in the prefix would change which slot keys land in.
    #[must_use]
    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        let prefix = prefix.into();
        assert!(
            !prefix.contains(['{', '}']),
            "ValkeyStore key prefix must not contain '{{' or '}}'"
        );
        self.prefix = prefix;
        self
    }

    /// `prefix{bb}:`, the start of every key in `bucket`.
    fn bucket_prefix(&self, bucket: u8) -> String {
        format!("{}{{{bucket:02x}}}:", self.prefix)
    }

    /// A key `kind:id` in `bucket`.
    fn key(&self, bucket: u8, kind: &str, id: &str) -> String {
        format!("{}{kind}:{id}", self.bucket_prefix(bucket))
    }

    /// A singleton key `kind` in `bucket`.
    fn plain_key(&self, bucket: u8, kind: &str) -> String {
        format!("{}{kind}", self.bucket_prefix(bucket))
    }

    fn conn(&self) -> Conn {
        self.conn.clone()
    }

    /// Removes `session_id` from its subject's sets. Best effort: the sets also expire, and
    /// readers tolerate ids of sessions that are gone.
    async fn unindex(&self, subject: &str, session_id: Uuid) {
        let bucket = subject_bucket(subject);
        for kind in ["u", "ur"] {
            let _removed: Result<i64, _> = redis::cmd("SREM")
                .arg(self.key(bucket, kind, subject))
                .arg(session_id.to_string())
                .query_async(&mut self.conn())
                .await;
        }
    }
}

/// The bucket of a subject's index sets: the first byte of the SHA-256 of its canonical JSON.
fn subject_bucket(subject: &str) -> u8 {
    Sha256::digest(subject.as_bytes())[0]
}

fn ensure_aligned(session_id: Uuid, token: &TokenHash) -> Result<(), StoreError> {
    if session_bucket(session_id) == token_bucket(token) {
        Ok(())
    } else {
        Err("valkey store: token and session id are in different buckets".into())
    }
}

fn micros(at: DateTime<Utc>) -> String {
    at.timestamp_micros().to_string()
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StoreError> {
    value
        .parse::<i64>()
        .ok()
        .and_then(DateTime::from_timestamp_micros)
        .ok_or_else(|| "valkey store: malformed timestamp".into())
}

fn parse_optional_time(value: &str) -> Result<Option<DateTime<Utc>>, StoreError> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_time(value).map(Some)
    }
}

/// Parses the nine fields `read_session` returns.
fn parse_session(fields: &[String]) -> Result<SessionRecord, StoreError> {
    let [id, subject, created, auth, seen, expires, step_up, baseline, origin] = fields else {
        return Err("valkey store: malformed session".into());
    };
    let baseline: Baseline = serde_json::from_str(baseline)?;
    let origin: Option<SessionOrigin> = if origin.is_empty() {
        None
    } else {
        Some(serde_json::from_str(origin)?)
    };
    Ok(SessionRecord {
        id: Uuid::parse_str(id)?,
        subject: subject.clone(),
        created_at: parse_time(created)?,
        authenticated_at: parse_time(auth)?,
        last_seen_at: parse_time(seen)?,
        expires_at: parse_time(expires)?,
        step_up_required: step_up == "1",
        baseline,
        origin,
    })
}

#[derive(Serialize)]
struct EventRow<'a> {
    /// Keeps identical events distinct in the sorted set.
    id: Uuid,
    session_id: Uuid,
    subject: &'a str,
    kind: EventKind,
    enforced: bool,
    score: Option<u32>,
    signals: &'a [Check],
    ip: IpAddr,
    user_agent: Option<&'a str>,
    client: &'a ClientSummary,
    at: DateTime<Utc>,
}

impl SessionStore for ValkeyStore {
    fn sharded(&self) -> bool {
        true
    }

    async fn insert_session(&self, session: &SessionRecord, token: &TokenHash) -> Result<(), StoreError> {
        ensure_aligned(session.id, token)?;
        let bucket = session_bucket(session.id);
        let sid = session.id.to_string();
        let hex = token.to_hex();
        let exp_ms = session
            .expires_at
            .timestamp_micros()
            .saturating_add(999)
            .div_euclid(1000);
        // Index first: a concurrent revoke then either sees the id or makes the check below fail.
        let sbucket = subject_bucket(&session.subject);
        let _: i64 = INDEX_ADD
            .key(self.key(sbucket, "u", &session.subject))
            .arg(&sid)
            .arg(exp_ms)
            .invoke_async(&mut self.conn())
            .await?;
        let inserted: i64 = INSERT
            .key(self.key(bucket, "s", &sid))
            .key(self.key(bucket, "t", &hex))
            .key(self.key(bucket, "k", &sid))
            .key(self.plain_key(bucket, "x"))
            .arg(self.bucket_prefix(bucket))
            .arg(&sid)
            .arg(&hex)
            .arg(&session.subject)
            .arg(micros(session.created_at))
            .arg(micros(session.authenticated_at))
            .arg(micros(session.last_seen_at))
            .arg(micros(session.expires_at))
            .arg(if session.step_up_required { "1" } else { "0" })
            .arg(serde_json::to_string(&session.baseline)?)
            .arg(exp_ms)
            .arg(match &session.origin {
                Some(origin) => serde_json::to_string(origin)?,
                None => String::new(),
            })
            .invoke_async(&mut self.conn())
            .await?;
        if inserted != 1 {
            return Err("duplicate session id or token".into());
        }
        let indexed: bool = redis::cmd("SISMEMBER")
            .arg(self.key(sbucket, "u", &session.subject))
            .arg(&sid)
            .query_async(&mut self.conn())
            .await?;
        if !indexed {
            let exists: bool = redis::cmd("EXISTS")
                .arg(self.key(bucket, "s", &sid))
                .query_async(&mut self.conn())
                .await?;
            if exists {
                // A revoke moved the index entry between our two writes; do not leave a session
                // the revoke can no longer find.
                self.delete_session(session.id).await?;
                return Err("valkey store: subject was revoked while the session was created".into());
            }
        }
        Ok(())
    }

    async fn find_by_token(&self, token: &TokenHash) -> Result<Option<TokenLookup>, StoreError> {
        let bucket = token_bucket(token);
        let fields: Option<Vec<String>> = FIND
            .key(self.key(bucket, "t", &token.to_hex()))
            .arg(self.bucket_prefix(bucket))
            .invoke_async(&mut self.conn())
            .await?;
        let Some(fields) = fields else {
            return Ok(None);
        };
        let [session @ .., issued, used, superseded, newer] = fields.as_slice() else {
            return Err("valkey store: malformed token lookup".into());
        };
        Ok(Some(TokenLookup {
            session: parse_session(session)?,
            token: TokenRecord {
                hash: *token,
                issued_at: parse_time(issued)?,
                first_used_at: parse_optional_time(used)?,
                superseded_at: parse_optional_time(superseded)?,
            },
            newer_token_used: newer == "1",
        }))
    }

    async fn apply(&self, update: &SessionUpdate) -> Result<bool, StoreError> {
        if let Some(rotation) = &update.rotation {
            ensure_aligned(update.session_id, &rotation.new_token)?;
        }
        if let Some(used) = &update.mark_used {
            ensure_aligned(update.session_id, used)?;
        }
        let bucket = session_bucket(update.session_id);
        let sid = update.session_id.to_string();
        let (mode, mode_arg, new_token, prune) = match &update.rotation {
            None => ("", String::new(), String::new(), String::new()),
            Some(rotation) => {
                let (mode, arg) = match rotation.supersede {
                    Supersede::Exact(hash) => ("exact", hash.to_hex()),
                    Supersede::CurrentIssuedBefore(at) => ("before", micros(at)),
                    Supersede::Current => ("current", String::new()),
                };
                (
                    mode,
                    arg,
                    rotation.new_token.to_hex(),
                    micros(rotation.prune_superseded_before),
                )
            }
        };
        let baseline = match &update.baseline {
            Some(baseline) => serde_json::to_string(baseline)?,
            None => String::new(),
        };
        let step_up = match update.step_up_required {
            Some(true) => "1",
            Some(false) => "0",
            None => "",
        };
        let rotated: i64 = APPLY
            .key(self.key(bucket, "s", &sid))
            .arg(self.bucket_prefix(bucket))
            .arg(&sid)
            .arg(micros(update.now))
            .arg(mode)
            .arg(mode_arg)
            .arg(new_token)
            .arg(prune)
            .arg(update.mark_used.map(|h| h.to_hex()).unwrap_or_default())
            .arg(baseline)
            .arg(step_up)
            .arg(update.authenticated_at.map(micros).unwrap_or_default())
            .invoke_async(&mut self.conn())
            .await?;
        Ok(rotated == 1)
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<bool, StoreError> {
        let bucket = session_bucket(session_id);
        let sid = session_id.to_string();
        let subject: Option<String> = DELETE
            .key(self.key(bucket, "s", &sid))
            .arg(self.bucket_prefix(bucket))
            .arg(&sid)
            .invoke_async(&mut self.conn())
            .await?;
        let Some(subject) = subject else {
            return Ok(false);
        };
        self.unindex(&subject, session_id).await;
        Ok(true)
    }

    async fn delete_subject_sessions(&self, subject: &str) -> Result<Vec<Uuid>, StoreError> {
        let sbucket = subject_bucket(subject);
        let revoking = self.key(sbucket, "ur", subject);
        let members: Vec<String> = INDEX_MOVE
            .key(self.key(sbucket, "u", subject))
            .key(&revoking)
            .invoke_async(&mut self.conn())
            .await?;
        let mut deleted = Vec::new();
        for member in &members {
            // A malformed member can't name a session; the SREM below clears it.
            let Ok(id) = Uuid::parse_str(member) else { continue };
            let bucket = session_bucket(id);
            let removed: Option<String> = DELETE
                .key(self.key(bucket, "s", member))
                .arg(self.bucket_prefix(bucket))
                .arg(member)
                .arg(subject)
                .invoke_async(&mut self.conn())
                .await?;
            if removed.is_some() {
                deleted.push(id);
            }
        }
        // Only now are the ids done; a failure above leaves them pending for the next revoke.
        for chunk in members.chunks(SREM_BATCH) {
            let _removed: i64 = redis::cmd("SREM")
                .arg(&revoking)
                .arg(chunk)
                .query_async(&mut self.conn())
                .await?;
        }
        Ok(deleted)
    }

    async fn list_subject_sessions(&self, subject: &str) -> Result<Vec<SessionRecord>, StoreError> {
        let sbucket = subject_bucket(subject);
        let members: Vec<String> = redis::cmd("SUNION")
            .arg(self.key(sbucket, "u", subject))
            .arg(self.key(sbucket, "ur", subject))
            .query_async(&mut self.conn())
            .await?;
        let mut sessions = Vec::with_capacity(members.len());
        let mut stale = Vec::new();
        for member in &members {
            let Ok(id) = Uuid::parse_str(member) else {
                stale.push(member);
                continue;
            };
            let bucket = session_bucket(id);
            let fields: Option<Vec<String>> = READ
                .key(self.key(bucket, "s", member))
                .arg(self.bucket_prefix(bucket))
                .arg(member)
                .invoke_async(&mut self.conn())
                .await?;
            match fields.map(|fields| parse_session(&fields)).transpose()? {
                Some(record) if record.subject == subject => sessions.push(record),
                _ => stale.push(member),
            }
        }
        // Expired sessions leave their ids behind. Dropping one that a creator has added but
        // not yet inserted is safe: the creator's membership check then fails the login.
        for chunk in stale.chunks(SREM_BATCH) {
            for kind in ["u", "ur"] {
                let _removed: Result<i64, _> = redis::cmd("SREM")
                    .arg(self.key(sbucket, kind, subject))
                    .arg(chunk)
                    .query_async(&mut self.conn())
                    .await;
            }
        }
        Ok(sessions)
    }

    async fn delete_expired(&self, now: DateTime<Utc>, idle_cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        let mut total = 0;
        for bucket in 0..=u8::MAX {
            loop {
                let (deleted, found): (u64, u64) = DELETE_EXPIRED
                    .key(self.plain_key(bucket, "x"))
                    .arg(self.bucket_prefix(bucket))
                    .arg(micros(now))
                    .arg(micros(idle_cutoff))
                    .arg(PURGE_BATCH)
                    .invoke_async(&mut self.conn())
                    .await?;
                total += deleted;
                if found == 0 {
                    break;
                }
            }
        }
        Ok(total)
    }

    async fn record_event(&self, event: &SessionEvent) -> Result<(), StoreError> {
        let row = EventRow {
            id: Uuid::new_v4(),
            session_id: event.session_id,
            subject: &event.subject,
            kind: event.kind,
            enforced: event.enforced,
            score: event.score,
            signals: &event.signals,
            ip: event.ip,
            user_agent: event.user_agent.as_deref(),
            client: &event.client,
            at: event.at,
        };
        let _added: i64 = redis::cmd("ZADD")
            .arg(self.plain_key(session_bucket(event.session_id), "e"))
            .arg(event.at.timestamp_micros())
            .arg(serde_json::to_string(&row)?)
            .query_async(&mut self.conn())
            .await?;
        Ok(())
    }

    async fn delete_events_before(&self, cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        let mut total = 0;
        for bucket in 0..=u8::MAX {
            let deleted: u64 = DELETE_EVENTS
                .key(self.plain_key(bucket, "e"))
                .key(self.plain_key(bucket, "cz"))
                .arg(self.bucket_prefix(bucket))
                .arg(micros(cutoff))
                .invoke_async(&mut self.conn())
                .await?;
            total += deleted;
        }
        Ok(total)
    }

    async fn claim_event(
        &self,
        scope: ClaimScope<'_>,
        kind: EventKind,
        now: DateTime<Utc>,
        window: TimeDelta,
    ) -> Result<bool, StoreError> {
        // A session id never starts with `s:`, and no kind contains `:`, so members are unique.
        let (bucket, member) = match scope {
            ClaimScope::Session(session_id) => (session_bucket(session_id), format!("{session_id}:{kind}")),
            ClaimScope::Subject(subject) => (subject_bucket(subject), format!("s:{subject}:{kind}")),
        };
        let micros_window = window.num_microseconds().unwrap_or(i64::MAX);
        let millis_window = window.num_milliseconds().max(1);
        let claimed: i64 = CLAIM
            .key(self.key(bucket, "c", &member))
            .key(self.plain_key(bucket, "cz"))
            .arg(micros(now))
            .arg(micros_window)
            .arg(millis_window)
            .arg(&member)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(claimed == 1)
    }
}
