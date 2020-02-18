use crate::agents::*;
use crate::config::LimitConfig;
use crate::crypto::SigningAlgorithm;
use crate::utils::{agent::*, unix_timestamp};
use ::rusqlite::{Connection, Error as SqlError, OptionalExtension, ToSql, NO_PARAMS};
use std::time::Duration;
use tokio::task::spawn_blocking;
use url::Url;

macro_rules! params {
    ($($list:expr),*) => (
        std::convert::identity::<&[&dyn ToSql]>(&[$($list),*])
    );
}

/// SQLite `application_id` value. 'Prtr' in hex.
const APP_ID: u32 = 0x5072_7472;

/// Message sent at an interval to collect garbage.
struct Gc;
impl Message for Gc {
    type Reply = ();
}

/// Message used internally to save a cache entry.
struct SaveCache {
    url: Url,
    data: String,
    expires: i64,
}
impl Message for SaveCache {
    type Reply = Result<(), SqlError>;
}

/// Message used internally to save a key set.
struct SaveKeys(KeySet);
impl Message for SaveKeys {
    type Reply = Result<(), SqlError>;
}

/// Store implementation using memory.
pub struct RusqliteStore {
    /// TTL of session keys
    expire_sessions: Duration,
    /// TTL of cache keys
    expire_cache: Duration,
    /// Configuration for per-email rate limiting.
    limit_per_email_config: LimitConfig,
    /// SQLite connection.
    conn: Connection,
    /// The agent used for fetching on cache miss.
    fetcher: Addr<FetchAgent>,
    /// Key manager if rotating keys are enabled.
    key_manager: Option<Addr<RotatingKeys>>,
}

impl RusqliteStore {
    pub async fn new(
        sqlite_db: String,
        expire_sessions: Duration,
        expire_cache: Duration,
        limit_per_email_config: LimitConfig,
        fetcher: Addr<FetchAgent>,
    ) -> Result<Self, SqlError> {
        spawn_blocking(move || {
            let conn = Connection::open(&sqlite_db)?;
            conn.busy_timeout(Duration::from_millis(500))?;
            Self::verify_app_id(&conn)?;
            Self::verify_schema(&conn)?;
            log::warn!("Storing sessions in SQLite at: {}", sqlite_db);
            log::warn!("Please always double check this directory has secure permissions!");
            log::warn!("(This warning can't be fixed; it's a friendly reminder.)");
            Ok(RusqliteStore {
                expire_sessions,
                expire_cache,
                limit_per_email_config,
                conn,
                fetcher,
                key_manager: None,
            })
        })
        .await
        .unwrap()
    }

    fn verify_app_id(conn: &Connection) -> Result<(), SqlError> {
        // If this is 0, assume the file was just now created.
        let schema_version: u32 =
            conn.query_row("SELECT * FROM pragma_schema_version()", NO_PARAMS, |row| {
                row.get(0)
            })?;
        if schema_version == 0 {
            // Note: can't use parameter binding in pragma.
            conn.execute(&format!("PRAGMA application_id = {}", APP_ID), NO_PARAMS)?;
            return Ok(());
        }
        let app_id: u32 =
            conn.query_row("SELECT * FROM pragma_application_id()", NO_PARAMS, |row| {
                row.get(0)
            })?;
        if app_id != APP_ID {
            panic!(
                "The SQLite database has an invalid application ID: {}",
                app_id
            );
        }
        Ok(())
    }

    fn verify_schema(conn: &Connection) -> Result<(), SqlError> {
        let user_version: u32 =
            conn.query_row("SELECT * FROM pragma_user_version()", NO_PARAMS, |row| {
                row.get(0)
            })?;
        match user_version {
            0 => Self::init_schema(conn),
            1 => Ok(()),
            _ => panic!(
                "The SQLite database has an unknown version: {}",
                user_version
            ),
        }
    }

    fn init_schema(conn: &Connection) -> Result<(), SqlError> {
        conn.execute_batch(
            "
            BEGIN;

            CREATE TABLE sessions (
                id TEXT NOT NULL PRIMARY KEY,
                data TEXT NOT NULL,
                expires INTEGER NOT NULL
            );
            CREATE INDEX sessions_expires ON sessions (expires);

            CREATE TABLE cache_entries (
                url TEXT NOT NULL PRIMARY KEY,
                data TEXT NOT NULL,
                expires INTEGER NOT NULL
            );
            CREATE INDEX cache_entries_expires ON cache_entries (expires);

            CREATE TABLE rate_limits (
                id TEXT NOT NULL PRIMARY KEY,
                value INTEGER NOT NULL,
                expires INTEGER NOT NULL
            );
            CREATE INDEX rate_limits_expires ON rate_limits (expires);

            CREATE TABLE key_sets (
                signing_alg TEXT NOT NULL PRIMARY KEY,
                key_set TEXT NOT NULL
            );

            PRAGMA user_version = 1;
            COMMIT;
            ",
        )?;
        Ok(())
    }

    fn get_key_set(&mut self, signing_alg: SigningAlgorithm) -> KeySet {
        self.conn
            .query_row(
                "SELECT key_set FROM key_sets WHERE signing_alg = ?1 LIMIT 1",
                params![&signing_alg.as_str()],
                |row| row.get(0),
            )
            .optional()
            .expect("Could not fetch keys from SQLite")
            .map(|data: String| {
                serde_json::from_str(&data).expect("Invalid key set JSON in SQLite")
            })
            .unwrap_or_else(|| KeySet::empty(signing_alg))
    }
}

impl Agent for RusqliteStore {
    fn started(addr: &Addr<Self>) {
        // Start the garbage collection loop.
        let addr = addr.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                addr.send(Gc).await;
            }
        });
    }
}

impl Handler<Gc> for RusqliteStore {
    fn handle(&mut self, _message: Gc, cx: Context<Self, Gc>) {
        let now = unix_timestamp() as i64;
        self.conn
            .execute("DELETE FROM sessions WHERE expires <= ?1", &[now])
            .expect("session cleanup failed");
        self.conn
            .execute("DELETE FROM cache_entries WHERE expires <= ?1", &[now])
            .expect("cache cleanup failed");
        self.conn
            .execute("DELETE FROM rate_limits WHERE expires <= ?1", &[now])
            .expect("rate limits cleanup failed");
        cx.reply(())
    }
}

impl Handler<SaveSession> for RusqliteStore {
    fn handle(&mut self, message: SaveSession, cx: Context<Self, SaveSession>) {
        cx.reply_with(move || {
            let expires = (unix_timestamp() + self.expire_sessions.as_secs()) as i64;
            let data = serde_json::to_string(&message.data)?;
            self.conn.execute(
                "REPLACE INTO sessions (id, data, expires) VALUES (?1, ?2, ?3)",
                params![&message.session_id, &data, &expires],
            )?;
            Ok(())
        });
    }
}

impl Handler<GetSession> for RusqliteStore {
    fn handle(&mut self, message: GetSession, cx: Context<Self, GetSession>) {
        cx.reply_with(move || {
            let now = unix_timestamp() as i64;
            let data: Option<String> = self
                .conn
                .query_row(
                    "SELECT data FROM sessions WHERE id = ?1 AND expires > ?2 LIMIT 1",
                    params![&message.session_id, &now],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(data) = data {
                let data = serde_json::from_str(&data)?;
                Ok(Some(data))
            } else {
                Ok(None)
            }
        });
    }
}

impl Handler<DeleteSession> for RusqliteStore {
    fn handle(&mut self, message: DeleteSession, cx: Context<Self, DeleteSession>) {
        cx.reply_with(move || {
            self.conn
                .execute("DELETE FROM sessions WHERE id = ?1", &[&message.session_id])?;
            Ok(())
        });
    }
}

impl Handler<FetchUrlCached> for RusqliteStore {
    fn handle(&mut self, message: FetchUrlCached, cx: Context<Self, FetchUrlCached>) {
        let now = unix_timestamp() as i64;
        let data: Result<Option<String>, SqlError> = self
            .conn
            .query_row(
                "SELECT data FROM cache_entries WHERE url = ?1 AND expires > ?2 LIMIT 1",
                params![&message.url.as_str(), &now],
                |row| row.get(0),
            )
            .optional();
        match data {
            Err(e) => return cx.reply(Err(e.into())),
            Ok(Some(data)) => return cx.reply(Ok(data)),
            Ok(None) => {}
        }
        let me = cx.addr().clone();
        let fetcher = self.fetcher.clone();
        let expire_cache = self.expire_cache;
        cx.reply_later(async move {
            let result = fetcher
                .send(FetchUrl {
                    url: message.url.clone(),
                })
                .await?;
            let ttl = std::cmp::max(expire_cache, result.max_age);
            me.send(SaveCache {
                url: message.url,
                data: result.data.clone(),
                expires: (unix_timestamp() + ttl.as_secs()) as i64,
            })
            .await?;
            Ok(result.data)
        });
    }
}

impl Handler<SaveCache> for RusqliteStore {
    fn handle(&mut self, message: SaveCache, cx: Context<Self, SaveCache>) {
        cx.reply_with(move || {
            self.conn.execute(
                "REPLACE INTO cache_entries (url, data, expires) VALUES (?1, ?2, ?3)",
                params![&message.url.as_str(), &message.data, &message.expires],
            )?;
            Ok(())
        });
    }
}

impl Handler<IncrAndTestLimit> for RusqliteStore {
    fn handle(&mut self, message: IncrAndTestLimit, cx: Context<Self, IncrAndTestLimit>) {
        cx.reply_with(move || {
            let (id, config) = match message {
                IncrAndTestLimit::PerEmail { addr } => {
                    (format!("per-email:{}", addr), self.limit_per_email_config)
                }
            };
            let expires = (unix_timestamp() + config.duration.as_secs()) as i64;
            let tx = self.conn.transaction()?;
            tx.execute(
                "DELETE FROM rate_limits WHERE id = ?1 AND expires <= ?2",
                params![&id, &expires],
            )?;
            tx.execute(
                "INSERT INTO rate_limits (id, value, expires) VALUES (?1, 1, ?2)
                ON CONFLICT(id) DO UPDATE SET value = value + 1",
                params![&id, &expires],
            )?;
            let count: i64 = tx.query_row(
                "SELECT value FROM rate_limits WHERE id = ?1 LIMIT 1",
                params![&id],
                |row| row.get(0),
            )?;
            tx.commit()?;
            Ok(count as usize <= config.max_count)
        })
    }
}

impl Handler<EnableRotatingKeys> for RusqliteStore {
    fn handle(&mut self, message: EnableRotatingKeys, cx: Context<Self, EnableRotatingKeys>) {
        self.key_manager = Some(message.key_manager.clone());
        let mut update_msgs = Vec::with_capacity(message.signing_algs.len());
        for signing_alg in &message.signing_algs {
            let key_set = self.get_key_set(*signing_alg);
            update_msgs.push(UpdateKeys(key_set.clone()));
        }
        cx.reply_later(async move {
            for update_msg in update_msgs {
                message.key_manager.send(update_msg).await;
            }
        });
    }
}

impl Handler<RotateKeysLocked> for RusqliteStore {
    fn handle(&mut self, message: RotateKeysLocked, cx: Context<Self, RotateKeysLocked>) {
        let me = cx.addr().clone();
        let key_set = self.get_key_set(message.0);
        let key_manager = self.key_manager.as_ref().unwrap().clone();
        cx.reply_later(async move {
            if let Some(key_set) = key_manager.send(RotateKeys(key_set)).await {
                me.send(SaveKeys(key_set.clone()))
                    .await
                    .expect("Could not save keys to SQLite");
                key_manager.send(UpdateKeys(key_set)).await;
            }
        });
    }
}

impl Handler<SaveKeys> for RusqliteStore {
    fn handle(&mut self, message: SaveKeys, cx: Context<Self, SaveKeys>) {
        let key_set = message.0;
        cx.reply_with(move || {
            let data = serde_json::to_string(&key_set).expect("Could not encode key set as JSON");
            self.conn.execute(
                "REPLACE INTO key_sets (signing_alg, key_set) VALUES (?1, ?2)",
                params![&key_set.signing_alg.as_str(), &data],
            )?;
            Ok(())
        });
    }
}

impl StoreSender for Addr<RusqliteStore> {}
