//! Valkey / Redis store.

use std::{fmt, net::IpAddr, sync::LazyLock};

use chrono::{DateTime, TimeDelta, Utc};
use redis::{Script, aio::ConnectionManager};
use serde::Serialize;
use uuid::Uuid;

use super::{SessionRecord, SessionStore, SessionUpdate, Supersede, TokenLookup, TokenRecord};
use crate::{
    checks::Check,
    error::StoreError,
    event::{ClientSummary, EventKind, SessionEvent},
    fingerprint::Baseline,
    token::TokenHash,
};

/// How many sessions one `delete_expired` script invocation removes at most.
const PURGE_BATCH: usize = 500;

/// Lua helpers shared by several scripts.
macro_rules! lua_helpers {
    () => {
        r"
local function read_session(P, sid)
  local v = redis.call('HMGET', P .. 's:' .. sid,
    'subject', 'created', 'auth', 'seen', 'expires', 'step_up', 'baseline')
  if not v[1] then return nil end
  return {sid, v[1], v[2], v[3], v[4], v[5], v[6], v[7]}
end

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
    redis.call('SREM', P .. 'u:' .. subject, sid)
    redis.call('DEL', s)
    return 1
  end
  return 0
end
"
    };
}

/// KEYS: session, token, token set, subject set.
/// ARGV: prefix, sid, token hex, subject, created, auth, seen, expires, `step_up`, baseline,
/// `exp_ms`.
static INSERT: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        r"
local P = ARGV[1]
if redis.call('EXISTS', KEYS[1]) == 1 or redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'subject', ARGV[4], 'created', ARGV[5], 'auth', ARGV[6],
  'seen', ARGV[7], 'expires', ARGV[8], 'step_up', ARGV[9], 'baseline', ARGV[10],
  'exp_ms', ARGV[11], 'cur', ARGV[3], 'seq', 1)
redis.call('HSET', KEYS[2], 'sid', ARGV[2], 'seq', 1, 'issued', ARGV[5])
redis.call('ZADD', KEYS[3], 1, ARGV[3])
redis.call('SADD', KEYS[4], ARGV[2])
redis.call('ZADD', P .. 'x', ARGV[8], ARGV[2])
redis.call('ZADD', P .. 'i', ARGV[7], ARGV[2])
redis.call('PEXPIREAT', KEYS[1], ARGV[11])
redis.call('PEXPIREAT', KEYS[2], ARGV[11])
redis.call('PEXPIREAT', KEYS[3], ARGV[11])
local pt = redis.call('PEXPIRETIME', KEYS[4])
if pt == -1 or pt < tonumber(ARGV[11]) then redis.call('PEXPIREAT', KEYS[4], ARGV[11]) end
return 1
",
    )
});

/// KEYS: token. ARGV: prefix.
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
rec[9] = t[3]
rec[10] = t[4] or ''
rec[11] = t[5] or ''
rec[12] = tostring(newer)
return rec
",
    ))
});

/// KEYS: session.
/// ARGV: prefix, sid, now, supersede mode (`''` for no rotation), mode argument, new token hex,
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

/// ARGV: prefix, sid.
static DELETE: LazyLock<Script> =
    LazyLock::new(|| Script::new(concat!(lua_helpers!(), "return del_session(ARGV[1], ARGV[2])\n")));

/// KEYS: subject set. ARGV: prefix.
static DELETE_SUBJECT: LazyLock<Script> = LazyLock::new(|| {
    Script::new(concat!(
        lua_helpers!(),
        r"
local n = 0
for _, sid in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  n = n + del_session(ARGV[1], sid)
end
redis.call('DEL', KEYS[1])
return n
",
    ))
});

/// KEYS: subject set. ARGV: prefix.
static LIST_SUBJECT: LazyLock<Script> = LazyLock::new(|| {
    Script::new(concat!(
        lua_helpers!(),
        r"
local out = {}
for _, sid in ipairs(redis.call('SMEMBERS', KEYS[1])) do
  local rec = read_session(ARGV[1], sid)
  if rec then
    out[#out + 1] = rec
  else
    redis.call('SREM', KEYS[1], sid)
  end
end
return out
",
    ))
});

/// ARGV: prefix, now, idle cutoff, batch size.
static DELETE_EXPIRED: LazyLock<Script> = LazyLock::new(|| {
    Script::new(concat!(
        lua_helpers!(),
        r"
local P = ARGV[1]
local found, n = 0, 0
for _, idx in ipairs({{'x', ARGV[2]}, {'i', ARGV[3]}}) do
  local ids = redis.call('ZRANGEBYSCORE', P .. idx[1], '-inf', idx[2], 'LIMIT', 0, ARGV[4])
  found = found + #ids
  for _, sid in ipairs(ids) do n = n + del_session(P, sid) end
end
return {n, found}
",
    ))
});

/// KEYS: events, claim index. ARGV: prefix, cutoff.
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

/// A [`SessionStore`] on Valkey or Redis.
///
/// Every write that touches more than one key runs as a Lua script, so it is atomic across any
/// number of processes sharing the server. Requires Valkey 7.2+ or Redis 7.0+ in standalone or
/// primary/replica mode; Cluster is not supported because the scripts derive key names from
/// stored data.
///
/// # Data layout
///
/// All keys start with the [key prefix](Self::key_prefix) (`P`, default `sg:`).
/// Timestamps are microseconds since the Unix epoch as decimal integers.
///
/// | Key | Type | Contents |
/// |-----|------|----------|
/// | `P s:{session id}` | hash | `subject`, `created`, `auth`, `seen`, `expires`, `step_up`, `baseline` (JSON), `cur` (current token), `seq` (token counter), `exp_ms` |
/// | `P t:{token hash hex}` | hash | `sid`, `seq` (issue order), `issued`, `used`, `sup` (superseded) |
/// | `P k:{session id}` | sorted set | the session's token hashes, scored by `seq` |
/// | `P u:{subject}` | set | session ids of a subject |
/// | `P x` | sorted set | session ids scored by `expires_at` |
/// | `P i` | sorted set | session ids scored by `last_seen_at` |
/// | `P e` | sorted set | events as JSON, scored by `at` |
/// | `P c:{session id}:{kind}` | string | time of the last event claim |
/// | `P cz` | sorted set | `{session id}:{kind}` claims scored by claim time |
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
    conn: ConnectionManager,
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
            conn,
            prefix: "sg:".to_owned(),
        }
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
    #[must_use]
    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn key(&self, kind: &str, id: &str) -> String {
        format!("{}{kind}:{id}", self.prefix)
    }

    fn conn(&self) -> ConnectionManager {
        self.conn.clone()
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

/// Parses the eight fields `read_session` returns.
fn parse_session(fields: &[String]) -> Result<SessionRecord, StoreError> {
    let [id, subject, created, auth, seen, expires, step_up, baseline] = fields else {
        return Err("valkey store: malformed session".into());
    };
    let baseline: Baseline = serde_json::from_str(baseline)?;
    Ok(SessionRecord {
        id: Uuid::parse_str(id)?,
        subject: subject.clone(),
        created_at: parse_time(created)?,
        authenticated_at: parse_time(auth)?,
        last_seen_at: parse_time(seen)?,
        expires_at: parse_time(expires)?,
        step_up_required: step_up == "1",
        baseline,
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
    async fn insert_session(&self, session: &SessionRecord, token: &TokenHash) -> Result<(), StoreError> {
        let sid = session.id.to_string();
        let hex = token.to_hex();
        let exp_ms = session
            .expires_at
            .timestamp_micros()
            .saturating_add(999)
            .div_euclid(1000);
        let inserted: i64 = INSERT
            .key(self.key("s", &sid))
            .key(self.key("t", &hex))
            .key(self.key("k", &sid))
            .key(self.key("u", &session.subject))
            .arg(&self.prefix)
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
            .invoke_async(&mut self.conn())
            .await?;
        if inserted == 1 {
            Ok(())
        } else {
            Err("duplicate session id or token".into())
        }
    }

    async fn find_by_token(&self, token: &TokenHash) -> Result<Option<TokenLookup>, StoreError> {
        let fields: Option<Vec<String>> = FIND
            .key(self.key("t", &token.to_hex()))
            .arg(&self.prefix)
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
            .key(self.key("s", &sid))
            .arg(&self.prefix)
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
        let deleted: i64 = DELETE
            .arg(&self.prefix)
            .arg(session_id.to_string())
            .invoke_async(&mut self.conn())
            .await?;
        Ok(deleted == 1)
    }

    async fn delete_subject_sessions(&self, subject: &str) -> Result<u64, StoreError> {
        let deleted: u64 = DELETE_SUBJECT
            .key(self.key("u", subject))
            .arg(&self.prefix)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(deleted)
    }

    async fn list_subject_sessions(&self, subject: &str) -> Result<Vec<SessionRecord>, StoreError> {
        let rows: Vec<Vec<String>> = LIST_SUBJECT
            .key(self.key("u", subject))
            .arg(&self.prefix)
            .invoke_async(&mut self.conn())
            .await?;
        rows.iter().map(|row| parse_session(row)).collect()
    }

    async fn delete_expired(&self, now: DateTime<Utc>, idle_cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        let mut total = 0;
        loop {
            let (deleted, found): (u64, u64) = DELETE_EXPIRED
                .arg(&self.prefix)
                .arg(micros(now))
                .arg(micros(idle_cutoff))
                .arg(PURGE_BATCH)
                .invoke_async(&mut self.conn())
                .await?;
            total += deleted;
            if found == 0 {
                return Ok(total);
            }
        }
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
            .arg(format!("{}e", self.prefix))
            .arg(event.at.timestamp_micros())
            .arg(serde_json::to_string(&row)?)
            .query_async(&mut self.conn())
            .await?;
        Ok(())
    }

    async fn delete_events_before(&self, cutoff: DateTime<Utc>) -> Result<u64, StoreError> {
        let deleted: u64 = DELETE_EVENTS
            .key(format!("{}e", self.prefix))
            .key(format!("{}cz", self.prefix))
            .arg(&self.prefix)
            .arg(micros(cutoff))
            .invoke_async(&mut self.conn())
            .await?;
        Ok(deleted)
    }

    async fn claim_event(
        &self,
        session_id: Uuid,
        kind: EventKind,
        now: DateTime<Utc>,
        window: TimeDelta,
    ) -> Result<bool, StoreError> {
        let member = format!("{session_id}:{kind}");
        let micros_window = window.num_microseconds().unwrap_or(i64::MAX);
        let millis_window = window.num_milliseconds().max(1);
        let claimed: i64 = CLAIM
            .key(self.key("c", &member))
            .key(format!("{}cz", self.prefix))
            .arg(micros(now))
            .arg(micros_window)
            .arg(millis_window)
            .arg(&member)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(claimed == 1)
    }
}
