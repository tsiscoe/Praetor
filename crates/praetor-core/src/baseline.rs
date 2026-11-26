//! `BLAKE3` + `XChaCha20-Poly1305` Sealed Persistence Baselines & Rollback Store (`VEC-05`).
//!
//! Hardened under Wave-1 Security Audit (`[SEC-01b-1]`, `[SEC-01b-2]`):
//! - Parent-only key canonicalization (`normalize_key_path`) so replacing a protected file with a
//!   symlink cannot redirect SQLite primary-key lookup (`[SEC-01b-1]`).
//! - `symlink_metadata` inspection in `audit_all` & `restore_path` so planted symlinks, dangling
//!   links, or directory junctions are detected and unlinked cleanly without following links (`[SEC-01b-1]`).
//! - `OpenOptions::create_new(true)` (`CREATE_NEW` / `O_EXCL`) CSPRNG temp staging + Windows
//!   `FILE_ATTRIBUTE_READONLY` (`attrib +R`) clear-and-reapply preservation (`[SEC-01b-2]`).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::Utc;
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{PraetorError, PraetorResult};

const INVENTORY_MANIFEST_KEY: &str = "__praetor_inventory_manifest_v1__";

/// 256-bit symmetric sealing key protecting golden rollback snapshots in SQLite.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SnapshotSealKey([u8; 32]);

impl SnapshotSealKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex_str: &str) -> PraetorResult<Self> {
        let mut raw = hex::decode(hex_str.trim())
            .map_err(|e| PraetorError::KeyError(format!("invalid seal key hex: {e}")))?;
        if raw.len() != 32 {
            raw.zeroize();
            return Err(PraetorError::KeyError("seal key must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        raw.zeroize();
        Ok(Self(arr))
    }

    pub fn to_hex_zeroizing(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(hex::encode(self.0))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Outcome of scanning a protected persistence file against its sealed golden baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DriftStatus {
    Intact,
    Modified {
        expected_blake3: String,
        actual_blake3: String,
    },
    Deleted {
        expected_blake3: String,
    },
    UnauthorizedCreation {
        actual_blake3: String,
    },
}

/// Inspection record for a single protected file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineAuditItem {
    pub path: PathBuf,
    pub status: DriftStatus,
}

/// Compute domain-separated `BLAKE3` digest for a persistence file's raw bytes.
pub fn hash_protected_file_bytes(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("PRAETOR_PROTECTED_FILE_V1");
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hex::encode(hasher.finalize().as_bytes())
}

/// SQLite WAL store holding `BLAKE3` hashes and `XChaCha20-Poly1305`-encrypted rollback snapshots.
pub struct BaselineVault {
    conn: Connection,
}

impl BaselineVault {
    /// Open or initialize a WAL-mode baseline vault at `db_path` with owner-only ACLs.
    pub fn open(db_path: &Path) -> PraetorResult<Self> {
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let conn =
            Connection::open(db_path).map_err(|e| PraetorError::LedgerError(e.to_string()))?;
        let vault = Self::init_schema(conn)?;
        sextant_core::canonical::enforce_owner_only_acl(db_path, false)?;
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", db_path.to_string_lossy()));
            if sidecar.exists() {
                sextant_core::canonical::enforce_owner_only_acl(&sidecar, false)?;
            }
        }
        Ok(vault)
    }

    pub fn open_in_memory() -> PraetorResult<Self> {
        let conn =
            Connection::open_in_memory().map_err(|e| PraetorError::LedgerError(e.to_string()))?;
        Self::init_schema(conn)
    }

    fn init_schema(conn: Connection) -> PraetorResult<Self> {
        conn.execute_batch(
            "PRAGMA trusted_schema = OFF;
             PRAGMA busy_timeout = 5000;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS protected_baselines (
                 canonical_path TEXT PRIMARY KEY,
                 existed_at_seal INTEGER NOT NULL,
                 readonly_at_seal INTEGER NOT NULL DEFAULT 0,
                 blake3_hex TEXT NOT NULL,
                 nonce BLOB NOT NULL,
                 sealed_snapshot BLOB NOT NULL,
                 sealed_at_unix INTEGER NOT NULL
             );",
        )
        .map_err(|e| PraetorError::LedgerError(e.to_string()))?;
        // Migrate older v0.1.0 databases smoothly if `readonly_at_seal` column was absent
        let _ = conn.execute(
            "ALTER TABLE protected_baselines ADD COLUMN readonly_at_seal INTEGER NOT NULL DEFAULT 0",
            [],
        );
        Ok(Self { conn })
    }

    /// Seal the current state of `target_path` (whether existing regular file or absent watch-slot)
    /// into the vault using `XChaCha20-Poly1305` bound to `AAD`.
    pub fn seal_path(
        &mut self,
        target_path: &Path,
        seal_key: &SnapshotSealKey,
    ) -> PraetorResult<String> {
        let norm_key = normalize_key_path(target_path);
        let (existed, readonly_flag, raw_bytes, digest_hex) =
            match std::fs::symlink_metadata(target_path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() || meta.is_dir() {
                        return Err(PraetorError::BaselineTamper(format!(
                            "refusing to seal symlink or directory at '{}'",
                            target_path.display()
                        )));
                    }
                    let ro = i64::from(meta.permissions().readonly());
                    let data = std::fs::read(target_path)?;
                    let digest = hash_protected_file_bytes(&data);
                    (1i64, ro, data, digest)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    (0i64, 0i64, Vec::new(), "ABSENT".to_string())
                }
                Err(e) => return Err(PraetorError::Io(e)),
            };

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(seal_key.as_bytes()));
        let aad = format!("praetor-baseline-v2|{norm_key}|{existed}|{readonly_flag}|{digest_hex}");
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &raw_bytes,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| PraetorError::BaselineTamper("XChaCha20-Poly1305 seal failed".into()))?;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| PraetorError::LedgerError(e.to_string()))?;

        tx.execute(
            "INSERT INTO protected_baselines
                (canonical_path, existed_at_seal, readonly_at_seal, blake3_hex, nonce, sealed_snapshot, sealed_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(canonical_path) DO UPDATE SET
                existed_at_seal = excluded.existed_at_seal,
                readonly_at_seal = excluded.readonly_at_seal,
                blake3_hex = excluded.blake3_hex,
                nonce = excluded.nonce,
                sealed_snapshot = excluded.sealed_snapshot,
                sealed_at_unix = excluded.sealed_at_unix",
            params![
                norm_key,
                existed,
                readonly_flag,
                digest_hex,
                &nonce_bytes[..],
                ciphertext,
                Utc::now().timestamp()
            ],
        )
        .map_err(|e| PraetorError::LedgerError(e.to_string()))?;

        let mut sealed_paths = Vec::new();
        {
            let mut mstmt = tx
                .prepare(
                    "SELECT canonical_path FROM protected_baselines
                     WHERE canonical_path != ?1
                     ORDER BY canonical_path ASC",
                )
                .map_err(|e| PraetorError::LedgerError(e.to_string()))?;
            let mrows = mstmt
                .query_map(params![INVENTORY_MANIFEST_KEY], |r| r.get::<_, String>(0))
                .map_err(|e| PraetorError::LedgerError(e.to_string()))?;
            for r in mrows {
                sealed_paths.push(r.map_err(|e| PraetorError::LedgerError(e.to_string()))?);
            }
        }
        let manifest_json = serde_json::to_vec(&sealed_paths)?;
        let manifest_digest = hash_protected_file_bytes(&manifest_json);
        let mut manifest_nonce = [0u8; 24];
        OsRng.fill_bytes(&mut manifest_nonce);
        let manifest_aad = format!(
            "praetor-manifest-v1|{}|{manifest_digest}",
            sealed_paths.len()
        );
        let manifest_ct = cipher
            .encrypt(
                XNonce::from_slice(&manifest_nonce),
                Payload {
                    msg: &manifest_json,
                    aad: manifest_aad.as_bytes(),
                },
            )
            .map_err(|_| PraetorError::BaselineTamper("manifest seal failed".into()))?;

        tx.execute(
            "INSERT INTO protected_baselines
                (canonical_path, existed_at_seal, readonly_at_seal, blake3_hex, nonce, sealed_snapshot, sealed_at_unix)
             VALUES (?1, 1, 0, ?2, ?3, ?4, ?5)
             ON CONFLICT(canonical_path) DO UPDATE SET
                blake3_hex = excluded.blake3_hex,
                nonce = excluded.nonce,
                sealed_snapshot = excluded.sealed_snapshot,
                sealed_at_unix = excluded.sealed_at_unix",
            params![
                INVENTORY_MANIFEST_KEY,
                manifest_digest,
                &manifest_nonce[..],
                manifest_ct,
                Utc::now().timestamp()
            ],
        )
        .map_err(|e| PraetorError::LedgerError(e.to_string()))?;

        tx.commit()
            .map_err(|e| PraetorError::LedgerError(e.to_string()))?;

        Ok(digest_hex)
    }

    /// Cryptographically verify inventory manifest + every sealed row with `seal_key` (`[C1]`),
    /// then audit all protected paths for content, symlink/dir replacement, deletion, creation, or read-only drift.
    pub fn audit_all(&self, seal_key: &SnapshotSealKey) -> PraetorResult<Vec<BaselineAuditItem>> {
        type StoredAuditRow = (String, i64, i64, String, Vec<u8>, Vec<u8>);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT canonical_path, existed_at_seal, readonly_at_seal, blake3_hex, nonce, sealed_snapshot
                 FROM protected_baselines
                 ORDER BY canonical_path ASC",
            )
            .map_err(|e| PraetorError::LedgerError(e.to_string()))?;

        let raw_rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })
            .map_err(|e| PraetorError::LedgerError(e.to_string()))?;

        let mut manifest_row: Option<StoredAuditRow> = None;
        let mut file_rows: Vec<StoredAuditRow> = Vec::new();
        for row in raw_rows {
            let entry = row.map_err(|e| PraetorError::LedgerError(e.to_string()))?;
            if entry.0 == INVENTORY_MANIFEST_KEY {
                manifest_row = Some(entry);
            } else {
                file_rows.push(entry);
            }
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(seal_key.as_bytes()));
        if !file_rows.is_empty() || manifest_row.is_some() {
            let Some((_, _, _, m_digest, m_nonce_vec, m_ct)) = manifest_row else {
                return Err(PraetorError::BaselineTamper(
                    "baseline inventory manifest missing from vault".into(),
                ));
            };
            let m_nonce: [u8; 24] = m_nonce_vec.try_into().map_err(|_| {
                PraetorError::BaselineTamper("baseline manifest nonce invalid length".into())
            })?;
            let m_aad = format!("praetor-manifest-v1|{}|{m_digest}", file_rows.len());
            let m_pt = cipher
                .decrypt(
                    XNonce::from_slice(&m_nonce),
                    Payload {
                        msg: &m_ct,
                        aad: m_aad.as_bytes(),
                    },
                )
                .map_err(|_| {
                    PraetorError::BaselineTamper(
                        "baseline inventory manifest authentication failed (wrong key or tampered rows)"
                            .into(),
                    )
                })?;
            let expected_paths: Vec<String> = serde_json::from_slice(&m_pt).map_err(|e| {
                PraetorError::BaselineTamper(format!("invalid baseline manifest JSON: {e}"))
            })?;
            let actual_paths: Vec<String> = file_rows.iter().map(|r| r.0.clone()).collect();
            if expected_paths != actual_paths {
                return Err(PraetorError::BaselineTamper(
                    "baseline inventory mismatch (missing or injected rows)".into(),
                ));
            }
        }

        let mut results = Vec::with_capacity(file_rows.len());
        for (path_str, existed, readonly_flag, expected_hex, nonce_vec, ciphertext) in file_rows {
            let path = PathBuf::from(&path_str);
            let Ok((_pt, is_v2)) = decrypt_baseline_row(
                &cipher,
                &path_str,
                existed,
                readonly_flag,
                &expected_hex,
                &nonce_vec,
                &ciphertext,
            ) else {
                results.push(BaselineAuditItem {
                    path,
                    status: DriftStatus::Modified {
                        expected_blake3: expected_hex,
                        actual_blake3: "VAULT_ROW_AUTH_FAILED".into(),
                    },
                });
                continue;
            };

            let sym_meta = std::fs::symlink_metadata(&path);
            let status = match (existed != 0, sym_meta) {
                (true, Ok(meta)) => {
                    if meta.file_type().is_symlink() || meta.is_dir() {
                        DriftStatus::Modified {
                            expected_blake3: expected_hex,
                            actual_blake3: "SYMLINK_OR_DIR_SABOTAGE".into(),
                        }
                    } else {
                        match std::fs::read(&path) {
                            Ok(bytes) => {
                                let actual_hex = hash_protected_file_bytes(&bytes);
                                if actual_hex
                                    .as_bytes()
                                    .ct_eq(expected_hex.as_bytes())
                                    .unwrap_u8()
                                    != 1
                                {
                                    DriftStatus::Modified {
                                        expected_blake3: expected_hex,
                                        actual_blake3: actual_hex,
                                    }
                                } else if is_v2
                                    && meta.permissions().readonly() != (readonly_flag != 0)
                                {
                                    DriftStatus::Modified {
                                        expected_blake3: expected_hex,
                                        actual_blake3: "READONLY_ATTR_DRIFT".into(),
                                    }
                                } else {
                                    DriftStatus::Intact
                                }
                            }
                            Err(e) => DriftStatus::Modified {
                                expected_blake3: expected_hex,
                                actual_blake3: format!("READ_ERROR:{e}"),
                            },
                        }
                    }
                }
                (true, Err(_)) => DriftStatus::Deleted {
                    expected_blake3: expected_hex,
                },
                (false, Ok(meta)) => {
                    let actual_blake3 = if meta.file_type().is_symlink() || meta.is_dir() {
                        "SYMLINK_OR_DIR_PLANTED".into()
                    } else {
                        match std::fs::read(&path) {
                            Ok(bytes) => hash_protected_file_bytes(&bytes),
                            Err(e) => format!("READ_ERROR:{e}"),
                        }
                    };
                    DriftStatus::UnauthorizedCreation { actual_blake3 }
                }
                (false, Err(_)) => DriftStatus::Intact,
            };

            results.push(BaselineAuditItem { path, status });
        }
        Ok(results)
    }

    /// Atomically stage and verify plaintext BEFORE touching the live path, then replace cleanly (`[C2]`, `[C4]`).
    pub fn restore_path(
        &self,
        target_path: &Path,
        seal_key: &SnapshotSealKey,
    ) -> PraetorResult<()> {
        let norm_key = normalize_key_path(target_path);
        type StoredBaselineRow = (i64, i64, String, Vec<u8>, Vec<u8>);
        let row: Option<StoredBaselineRow> = self
            .conn
            .query_row(
                "SELECT existed_at_seal, readonly_at_seal, blake3_hex, nonce, sealed_snapshot
                 FROM protected_baselines WHERE canonical_path = ?1",
                params![norm_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()
            .map_err(|e| PraetorError::LedgerError(e.to_string()))?;

        let Some((existed, readonly_flag, expected_hex, nonce_vec, ciphertext)) = row else {
            return Err(PraetorError::BaselineTamper(format!(
                "no baseline registered for '{norm_key}'"
            )));
        };

        let cipher = XChaCha20Poly1305::new(Key::from_slice(seal_key.as_bytes()));
        let (plaintext, is_v2) = decrypt_baseline_row(
            &cipher,
            &norm_key,
            existed,
            readonly_flag,
            &expected_hex,
            &nonce_vec,
            &ciphertext,
        )?;
        // Never apply unauthenticated DB `readonly_at_seal` bits on legacy v1 rows (`[C4]`)
        let effective_readonly = is_v2 && readonly_flag != 0;

        if existed == 0 {
            remove_or_unlock_existing_target(target_path, true)?;
            if std::fs::symlink_metadata(target_path).is_ok() {
                return Err(PraetorError::BaselineTamper(format!(
                    "unauthorized entry still exists after removal attempt at '{}'",
                    target_path.display()
                )));
            }
            return Ok(());
        }

        // Stage & fsync replacement temp file BEFORE modifying the live target (`[C2]`)
        let parent = target_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;

        let tmp_name = format!(".praetor-restore-{}.tmp", Uuid::new_v4().simple());
        let tmp_path = parent.join(tmp_name);
        let stage_res = (|| -> PraetorResult<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            file.write_all(&plaintext)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(err) = stage_res {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }

        if let Err(err) = remove_or_unlock_existing_target(target_path, false) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
        if let Err(err) = std::fs::rename(&tmp_path, target_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(PraetorError::Io(err));
        }

        let post_meta = std::fs::symlink_metadata(target_path)?;
        if post_meta.file_type().is_symlink() || !post_meta.is_file() {
            return Err(PraetorError::BaselineTamper(format!(
                "restored target '{}' failed post-rename regular-file verification",
                target_path.display()
            )));
        }

        if effective_readonly {
            let mut perms = post_meta.permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(target_path, perms)?;
        }

        Ok(())
    }
}

fn decrypt_baseline_row(
    cipher: &XChaCha20Poly1305,
    norm_key: &str,
    existed: i64,
    readonly_flag: i64,
    expected_hex: &str,
    nonce_vec: &[u8],
    ciphertext: &[u8],
) -> PraetorResult<(Vec<u8>, bool)> {
    let nonce_arr: [u8; 24] = nonce_vec
        .try_into()
        .map_err(|_| PraetorError::BaselineTamper("stored nonce invalid length".into()))?;
    let aad_v2 = format!("praetor-baseline-v2|{norm_key}|{existed}|{readonly_flag}|{expected_hex}");
    let (plaintext, is_v2) = match cipher.decrypt(
        XNonce::from_slice(&nonce_arr),
        Payload {
            msg: ciphertext,
            aad: aad_v2.as_bytes(),
        },
    ) {
        Ok(pt) => (pt, true),
        Err(_) => {
            let aad_v1 = format!("praetor-baseline-v1|{norm_key}|{existed}|{expected_hex}");
            let pt = cipher
                .decrypt(
                    XNonce::from_slice(&nonce_arr),
                    Payload {
                        msg: ciphertext,
                        aad: aad_v1.as_bytes(),
                    },
                )
                .map_err(|_| {
                    PraetorError::BaselineTamper(
                        "snapshot authentication failed (wrong key or tampered DB)".into(),
                    )
                })?;
            (pt, false)
        }
    };

    if existed != 0 {
        let verify_hex = hash_protected_file_bytes(&plaintext);
        if verify_hex
            .as_bytes()
            .ct_eq(expected_hex.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(PraetorError::BaselineTamper(
                "decrypted snapshot failed BLAKE3 integrity check".into(),
            ));
        }
    }
    Ok((plaintext, is_v2))
}

fn remove_or_unlock_existing_target(
    target_path: &Path,
    delete_completely: bool,
) -> PraetorResult<()> {
    let Ok(meta) = std::fs::symlink_metadata(target_path) else {
        return Ok(());
    };
    if meta.file_type().is_symlink() {
        std::fs::remove_file(target_path).or_else(|_| std::fs::remove_dir(target_path))?;
        return Ok(());
    }
    if meta.is_dir() {
        std::fs::remove_dir_all(target_path)?;
        return Ok(());
    }
    if meta.permissions().readonly() {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(target_path, perms)?;
    }
    if delete_completely {
        std::fs::remove_file(target_path)?;
    }
    Ok(())
}

/// Canonicalize ONLY the parent directory, NEVER following a leaf symlink (`[SEC-01b-1]`).
fn normalize_key_path(path: &Path) -> String {
    let resolved = if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        let base_parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(canon_parent) = std::fs::canonicalize(base_parent) {
            canon_parent.join(name)
        } else {
            path.to_path_buf()
        }
    } else {
        path.to_path_buf()
    };

    let s = resolved.to_string_lossy();
    let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
    if cfg!(windows) {
        stripped.replace('/', "\\").to_ascii_lowercase()
    } else {
        stripped.to_string()
    }
}
