// #################################################################
// /qompassai/volta/rewrite/crates/volta-core/src/store.rs
// Qompass AI Volta — Content-Addressed Store (SPEC 12.2/12.3)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

//! The state tier, single-node profile: content-addressed blobs on
//! disk (SHA-256 of the canonical served-form bytes) plus a SQLite
//! index. All derivation happens at ingest (SCALE-1); the read path
//! is index lookup -> blob fetch -> stream out. There is no symlink
//! tree and no regenerate step in normal operation (SCALE-2).
//! Every query is parameterized; every list is bounded.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::error::{VoltaError, VoltaResult};
use crate::model::{BindingStatus, CertificateMeta, StoredCertificate};

/// Hard cap on rows returned by any list operation.
pub const LIST_ROWS_MAX: usize = 200;

/// Counters for `op=stats` (SPEC 6.1.4). Counts only, never data.
#[derive(Clone, Copy, Debug, Default)]
pub struct StoreStats {
    /// Total stored certificates.
    pub certificates: i64,
    /// Published address bindings.
    pub published_addresses: i64,
    /// Certificates with a primary-key revocation on file.
    pub revoked_certificates: i64,
}

/// The store. Owns the SQLite connection and the blob directory.
pub struct Store {
    blob_dir: PathBuf,
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) a store rooted at `root`. Layout:
    /// `root/blobs/<sha256>` and `root/index.sqlite3`.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` when the layout cannot be created/opened.
    pub fn open(root: &Path) -> VoltaResult<Self> {
        let blob_dir = root.join("blobs");
        std::fs::create_dir_all(&blob_dir)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let conn = Connection::open(root.join("index.sqlite3"))
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS bindings (
                 address TEXT PRIMARY KEY,
                 fingerprint TEXT NOT NULL,
                 status TEXT NOT NULL,
                 verified_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS certificates (
                 armor TEXT NOT NULL,
                 content_sha256 TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 fingerprint TEXT PRIMARY KEY,
                 key_id TEXT NOT NULL,
                 meta_json TEXT NOT NULL,
                 modified_at INTEGER NOT NULL,
                 revision INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_certificates_key_id
                 ON certificates (key_id);
             CREATE TABLE IF NOT EXISTS subkey_index (
                 fingerprint TEXT NOT NULL,
                 key_id TEXT PRIMARY KEY
             );
             CREATE TABLE IF NOT EXISTS wkd_index (
                 fingerprint TEXT NOT NULL,
                 hash TEXT PRIMARY KEY,
                 address TEXT NOT NULL
             );",
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(Self { blob_dir, conn })
    }

    /// SHA-256 content address of a byte string, lowercase hex.
    #[must_use]
    pub fn content_address(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for byte in digest {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Delete a certificate, its bindings, and its index rows
    /// (DM-PUB-4). The blob stays (content-addressed storage may be
    /// shared); blob garbage collection is an operator concern.
    ///
    /// # Errors
    /// `E_KEY_NOT_FOUND` when the certificate is absent.
    pub fn delete_certificate(&mut self, fingerprint: &str) -> VoltaResult<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let removed = tx
            .execute(
                "DELETE FROM certificates WHERE fingerprint = ?1",
                params![fingerprint],
            )
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        if removed == 0 {
            return Err(VoltaError::KeyNotFound);
        }
        tx.execute(
            "DELETE FROM bindings WHERE fingerprint = ?1",
            params![fingerprint],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        tx.execute(
            "DELETE FROM subkey_index WHERE fingerprint = ?1",
            params![fingerprint],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        tx.execute(
            "DELETE FROM wkd_index WHERE fingerprint = ?1",
            params![fingerprint],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        tx.commit()
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(())
    }

    /// Fetch a certificate by content address for the read path.
    ///
    /// # Errors
    /// `E_KEY_NOT_FOUND` when no row names the address; a stored
    /// row whose blob fails its content address is an integrity
    /// failure surfaced as `E_KEY_MALFORMED` — never served.
    pub fn get_by_content_address(&self, content_sha256: &str) -> VoltaResult<StoredCertificate> {
        let fingerprint: String = self
            .conn
            .query_row(
                "SELECT fingerprint FROM certificates WHERE content_sha256 = ?1",
                params![content_sha256],
                |row| row.get(0),
            )
            .map_err(|_| VoltaError::KeyNotFound)?;
        self.get_by_fingerprint(&fingerprint)
    }

    /// Fetch a certificate by exact fingerprint (DM-PUB-2).
    ///
    /// # Errors
    /// `E_KEY_NOT_FOUND` when absent.
    pub fn get_by_fingerprint(&self, fingerprint: &str) -> VoltaResult<StoredCertificate> {
        self.load(fingerprint)
    }

    /// Fetch a certificate by long KeyID of the primary key or of
    /// any subkey (HKP-2). Returns the primary certificate (VKS-2).
    ///
    /// # Errors
    /// `E_KEY_NOT_FOUND` when absent.
    pub fn get_by_key_id(&self, key_id: &str) -> VoltaResult<StoredCertificate> {
        let fingerprint: Result<String, _> = self.conn.query_row(
            "SELECT fingerprint FROM certificates WHERE key_id = ?1",
            params![key_id],
            |row| row.get(0),
        );
        let fingerprint = match fingerprint {
            Ok(f) => f,
            Err(_) => self.conn.query_row(
                "SELECT fingerprint FROM subkey_index WHERE key_id = ?1",
                params![key_id],
                |row| row.get(0),
            ).map_err(|_| VoltaError::KeyNotFound)?,
        };
        self.load(&fingerprint)
    }

    /// Fetch the certificate an address is published for
    /// (DM-PUB-1). Unpublished bindings are indistinguishable from
    /// absent ones (VKS-1: no existence oracle).
    ///
    /// # Errors
    /// `E_KEY_NOT_FOUND` when the address is not published.
    pub fn get_by_email(&self, address: &str) -> VoltaResult<StoredCertificate> {
        let fingerprint: String = self
            .conn
            .query_row(
                "SELECT fingerprint FROM bindings
                 WHERE address = ?1 AND status = 'published'",
                params![address.to_lowercase()],
                |row| row.get(0),
            )
            .map_err(|_| VoltaError::KeyNotFound)?;
        self.load(&fingerprint)
    }

    /// Fetch a certificate by its WKD hash (WKD-2/WKD-3).
    ///
    /// # Errors
    /// `E_KEY_NOT_FOUND` when the hash is unknown.
    pub fn get_by_wkd_hash(&self, hash: &str) -> VoltaResult<StoredCertificate> {
        let fingerprint: String = self
            .conn
            .query_row(
                "SELECT fingerprint FROM wkd_index WHERE hash = ?1",
                params![hash],
                |row| row.get(0),
            )
            .map_err(|_| VoltaError::KeyNotFound)?;
        // Only published bindings resolve through WKD (DM-PUB-1).
        let status: String = self
            .conn
            .query_row(
                "SELECT status FROM bindings WHERE fingerprint = ?1
                 AND address = (SELECT address FROM wkd_index WHERE hash = ?2)",
                params![fingerprint, hash],
                |row| row.get(0),
            )
            .map_err(|_| VoltaError::KeyNotFound)?;
        if status != "published" {
            return Err(VoltaError::KeyNotFound);
        }
        self.load(&fingerprint)
    }

    /// The binding status of one address for one certificate.
    #[must_use]
    pub fn binding_status(&self, address: &str, fingerprint: &str) -> Option<BindingStatus> {
        let status: Result<String, _> = self.conn.query_row(
            "SELECT status FROM bindings WHERE address = ?1 AND fingerprint = ?2",
            params![address.to_lowercase(), fingerprint],
            |row| row.get(0),
        );
        status.ok().and_then(|s| BindingStatus::parse(&s))
    }

    /// All addresses bound to a certificate, with statuses.
    #[must_use]
    pub fn bindings_of(&self, fingerprint: &str) -> Vec<(String, BindingStatus)> {
        let mut stmt = match self.conn.prepare(
            "SELECT address, status FROM bindings WHERE fingerprint = ?1
             ORDER BY address LIMIT ?2",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![fingerprint, LIST_ROWS_MAX as i64], |row| {
            let address: String = row.get(0)?;
            let status: String = row.get(1)?;
            Ok((address, status))
        });
        match rows {
            Ok(iter) => iter
                .filter_map(Result::ok)
                .filter_map(|(a, s)| BindingStatus::parse(&s).map(|st| (a, st)))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Insert or replace a certificate and derive every index row
    /// (SCALE-1). Returns the stored record with its new revision.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failures.
    pub fn put_certificate(
        &mut self,
        mut meta: CertificateMeta,
        binary: &[u8],
        armor: &str,
        now_unix: i64,
    ) -> VoltaResult<StoredCertificate> {
        let content_sha256 = Self::content_address(binary);
        let blob_path = self.blob_dir.join(&content_sha256);
        if !blob_path.exists() {
            std::fs::write(&blob_path, binary)
                .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        }
        let existing: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT created_at, revision FROM certificates WHERE fingerprint = ?1",
                params![meta.fingerprint],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        let (created_at, revision) = match existing {
            Some((created, rev)) => (created, rev + 1),
            None => (now_unix, 1),
        };
        meta.created_at = created_at;
        meta.modified_at = now_unix;
        let verified: BTreeSet<String> = self
            .bindings_of(&meta.fingerprint)
            .into_iter()
            .filter(|(_, s)| *s == BindingStatus::Published)
            .map(|(a, _)| a)
            .collect();
        for uid in &mut meta.user_ids {
            if let Some(email) = &uid.email {
                uid.verified = verified.contains(email);
            }
        }
        let meta_json = serde_json::to_string(&meta)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let tx = self
            .conn
            .transaction()
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        tx.execute(
            "INSERT INTO certificates
                 (armor, content_sha256, created_at, fingerprint, key_id,
                  meta_json, modified_at, revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(fingerprint) DO UPDATE SET
                 armor = excluded.armor,
                 content_sha256 = excluded.content_sha256,
                 meta_json = excluded.meta_json,
                 modified_at = excluded.modified_at,
                 revision = excluded.revision",
            params![
                armor,
                content_sha256,
                created_at,
                meta.fingerprint,
                meta.key_id,
                meta_json,
                now_unix,
                revision
            ],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        tx.execute(
            "DELETE FROM subkey_index WHERE fingerprint = ?1",
            params![meta.fingerprint],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        for sub in &meta.subkeys {
            tx.execute(
                "INSERT OR REPLACE INTO subkey_index (fingerprint, key_id) VALUES (?1, ?2)",
                params![meta.fingerprint, sub.key_id],
            )
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        }
        for uid in &meta.user_ids {
            if let Some(email) = &uid.email {
                let (local, _domain) = crate::wkd::split_email(email)
                    .unwrap_or_else(|| (email.clone(), String::new()));
                let hash = crate::wkd::wkd_hash(&local);
                tx.execute(
                    "INSERT OR REPLACE INTO wkd_index (fingerprint, hash, address)
                     VALUES (?1, ?2, ?3)",
                    params![meta.fingerprint, hash, email],
                )
                .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
                tx.execute(
                    "INSERT OR IGNORE INTO bindings (address, fingerprint, status, verified_at)
                     VALUES (?1, ?2, 'unpublished', NULL)",
                    params![email, meta.fingerprint],
                )
                .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            }
        }
        tx.commit()
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(StoredCertificate {
            armor: armor.to_string(),
            binary: binary.to_vec(),
            content_sha256,
            meta,
            revision,
        })
    }

    /// Publish an address for a certificate: the address becomes
    /// searchable for this certificate and unpublished from any
    /// other (SPEC 5.2 invariant, DM-PUB-1).
    ///
    /// # Errors
    /// `E_KEY_NOT_FOUND` when the certificate is absent.
    pub fn publish_address(
        &mut self,
        address: &str,
        fingerprint: &str,
        now_unix: i64,
    ) -> VoltaResult<()> {
        let address = address.to_lowercase();
        let exists: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM certificates WHERE fingerprint = ?1",
                params![fingerprint],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false);
        if !exists {
            return Err(VoltaError::KeyNotFound);
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        tx.execute(
            "UPDATE bindings SET status = 'unpublished', verified_at = NULL
             WHERE address = ?1 AND fingerprint != ?2 AND status = 'published'",
            params![address, fingerprint],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        tx.execute(
            "INSERT INTO bindings (address, fingerprint, status, verified_at)
             VALUES (?1, ?2, 'published', ?3)
             ON CONFLICT(address) DO UPDATE SET
                 fingerprint = excluded.fingerprint,
                 status = 'published',
                 verified_at = excluded.verified_at",
            params![address, fingerprint, now_unix],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        tx.commit()
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(())
    }

    /// Set one binding's status without touching other bindings.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failures.
    pub fn set_binding_status(
        &mut self,
        address: &str,
        fingerprint: &str,
        status: BindingStatus,
        verified_at: Option<i64>,
    ) -> VoltaResult<()> {
        self.conn
            .execute(
                "INSERT INTO bindings (address, fingerprint, status, verified_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(address) DO UPDATE SET
                     fingerprint = excluded.fingerprint,
                     status = excluded.status,
                     verified_at = excluded.verified_at",
                params![address.to_lowercase(), fingerprint, status.as_str(), verified_at],
            )
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(())
    }

    /// Counters for `op=stats`.
    #[must_use]
    pub fn stats(&self) -> StoreStats {
        let count = |sql: &str| {
            self.conn
                .query_row(sql, [], |row| row.get::<_, i64>(0))
                .unwrap_or(0)
        };
        let revoked = {
            let mut n = 0i64;
            if let Ok(mut stmt) = self
                .conn
                .prepare("SELECT meta_json FROM certificates LIMIT 100000")
            {
                if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                    for meta_json in rows.flatten() {
                        if let Ok(meta) =
                            serde_json::from_str::<CertificateMeta>(&meta_json)
                        {
                            if meta.revoked {
                                n += 1;
                            }
                        }
                    }
                }
            }
            n
        };
        StoreStats {
            certificates: count("SELECT COUNT(*) FROM certificates"),
            published_addresses: count(
                "SELECT COUNT(*) FROM bindings WHERE status = 'published'",
            ),
            revoked_certificates: revoked,
        }
    }

    fn load(&self, fingerprint: &str) -> VoltaResult<StoredCertificate> {
        let (armor, content_sha256, meta_json, revision): (String, String, String, i64) =
            self.conn
                .query_row(
                    "SELECT armor, content_sha256, meta_json, revision
                     FROM certificates WHERE fingerprint = ?1",
                    params![fingerprint],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(|_| VoltaError::KeyNotFound)?;
        let blob_path = self.blob_dir.join(&content_sha256);
        let binary =
            std::fs::read(&blob_path).map_err(|_| VoltaError::KeyMalformed("missing blob".into()))?;
        if Self::content_address(&binary) != content_sha256 {
            return Err(VoltaError::KeyMalformed(
                "blob fails its content address".into(),
            ));
        }
        let meta: CertificateMeta =
            serde_json::from_str(&meta_json).map_err(|_| VoltaError::KeyNotFound)?;
        Ok(StoredCertificate {
            armor,
            binary,
            content_sha256,
            meta,
            revision,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CertificateMeta, UserIdMeta};

    fn meta(fingerprint: &str, email: &str) -> CertificateMeta {
        CertificateMeta {
            created_at: 0,
            fingerprint: fingerprint.to_string(),
            key_id: fingerprint[fingerprint.len() - 16..].to_string(),
            modified_at: 0,
            primary_algorithm: "ed25519".to_string(),
            primary_created_at: 1,
            primary_expires_at: None,
            revoked: false,
            subkeys: Vec::new(),
            user_ids: vec![UserIdMeta {
                email: Some(email.to_string()),
                raw: format!("Test <{email}>"),
                verified: false,
            }],
            warnings: Vec::new(),
        }
    }

    #[test]
    fn publish_then_lookup_round_trip() {
        let dir = std::env::temp_dir().join(format!("volta-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir).expect("open");
        let fpr = "A".repeat(40);
        store
            .put_certificate(meta(&fpr, "ada@example.org"), b"binary-key", "armor", 10)
            .expect("put");
        // Unpublished: by-email must not resolve (VKS-1).
        assert!(store.get_by_email("ada@example.org").is_err());
        assert!(store.get_by_fingerprint(&fpr).is_ok());
        store
            .publish_address("ada@example.org", &fpr, 20)
            .expect("publish");
        let found = store.get_by_email("ADA@example.org").expect("by email");
        assert_eq!(found.meta.fingerprint, fpr);
        let hash = crate::wkd::wkd_hash("ada");
        assert!(store.get_by_wkd_hash(&hash).is_ok());
        let stats = store.stats();
        assert_eq!(stats.certificates, 1);
        assert_eq!(stats.published_addresses, 1);
        store.delete_certificate(&fpr).expect("delete");
        assert!(store.get_by_fingerprint(&fpr).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn content_address_is_sha256() {
        assert_eq!(
            Store::content_address(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
