// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Thin abstraction over `sqlx::MySqlPool` / `sqlx::SqlitePool`. Used by the
//! schema, key-store, and resource-store layers so that callers can stay
//! driver-agnostic.
//!
//! sqlx 0.7's `Any` driver does not expose driver-kind discrimination
//! through stable feature flags (the `AnyKind::MySql` / `AnyKind::Sqlite`
//! variants are gated on private sqlx-core features that the umbrella
//! `sqlx` crate's `mysql` / `sqlite` features do not enable). Rather than
//! fight that, we keep typed pools and dispatch on a small enum.

use anyhow::{anyhow, bail, Context, Result};
use std::time::Duration;

use super::DatabaseConfig;

#[derive(Clone)]
pub enum DbPool {
    MySql(sqlx::MySqlPool),
    Sqlite(sqlx::SqlitePool),
}

impl DbPool {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
        match config.kind.to_ascii_lowercase().as_str() {
            "mysql" => {
                if config.dsn.is_empty() {
                    bail!("EncryptedDb: database.dsn is required when type=\"mysql\"");
                }
                let mut opts = sqlx::mysql::MySqlPoolOptions::new();
                if config.max_open_conns > 0 {
                    opts = opts.max_connections(config.max_open_conns);
                }
                if config.max_idle_conns > 0 {
                    // sqlx docs: min_connections is the warm-pool floor.
                    opts = opts.min_connections(config.max_idle_conns);
                }
                if !config.conn_max_lifetime.is_empty() {
                    let dur = parse_simple_duration(&config.conn_max_lifetime).map_err(|e| {
                        anyhow!(
                            "parse conn_max_lifetime `{}`: {e}",
                            config.conn_max_lifetime
                        )
                    })?;
                    opts = opts.max_lifetime(Some(dur));
                }
                let pool = opts
                    .connect(&config.dsn)
                    .await
                    .context("connect to MySQL DSN")?;
                Ok(DbPool::MySql(pool))
            }
            "sqlite" => {
                if config.path.is_empty() {
                    bail!("EncryptedDb: database.path is required when type=\"sqlite\"");
                }
                let url = if config.path == ":memory:" {
                    "sqlite::memory:".to_string()
                } else {
                    format!("sqlite://{}?mode=rwc", config.path)
                };
                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(1) // single-writer keeps tests deterministic
                    .acquire_timeout(Duration::from_secs(5))
                    .connect(&url)
                    .await
                    .context("connect to SQLite")?;
                Ok(DbPool::Sqlite(pool))
            }
            other => bail!("EncryptedDb: unsupported database.type `{other}`"),
        }
    }

    /// Connect to an in-memory SQLite (tests only).
    #[cfg(test)]
    pub async fn connect_sqlite_memory() -> Result<Self> {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        Ok(DbPool::Sqlite(pool))
    }
}

/// Tiny `humantime`-style parser supporting `Ns`, `Nm`, `Nh`, `Nd`, `Nw` (and
/// the bare `0` synonym). Avoids adding another dependency just to parse two
/// configuration knobs.
pub fn parse_simple_duration(s: &str) -> Result<Duration> {
    let trimmed = s.trim();
    if trimmed == "0" {
        return Ok(Duration::ZERO);
    }
    let (num_part, suffix) = match trimmed.find(|c: char| c.is_alphabetic()) {
        Some(i) => trimmed.split_at(i),
        None => bail!("missing unit suffix (s, m, h, d, w)"),
    };
    let n: u64 = num_part
        .trim()
        .parse()
        .map_err(|e| anyhow!("not a number: {e}"))?;
    let secs = match suffix {
        "s" | "sec" | "secs" => n,
        "m" | "min" | "mins" => n.saturating_mul(60),
        "h" | "hr" | "hrs" => n.saturating_mul(3600),
        "d" | "day" | "days" => n.saturating_mul(86_400),
        "w" | "wk" | "wks" | "week" | "weeks" => n.saturating_mul(7 * 86_400),
        other => bail!("unknown unit `{other}` (use s/m/h/d/w)"),
    };
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zero() {
        assert_eq!(parse_simple_duration("0").unwrap(), Duration::ZERO);
    }

    #[test]
    fn parse_units() {
        assert_eq!(
            parse_simple_duration("30s").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_simple_duration("5m").unwrap(),
            Duration::from_secs(300)
        );
        assert_eq!(
            parse_simple_duration("1h").unwrap(),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            parse_simple_duration("30d").unwrap(),
            Duration::from_secs(30 * 86_400)
        );
        assert_eq!(
            parse_simple_duration("2w").unwrap(),
            Duration::from_secs(14 * 86_400)
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_simple_duration("").is_err());
        assert!(parse_simple_duration("abc").is_err());
        assert!(parse_simple_duration("3").is_err());
        assert!(parse_simple_duration("3y").is_err());
    }
}
