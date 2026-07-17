use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{
    Connection, MAIN_DB, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use super::{
    ActivationRequest, ActivationResponse, AuditAction, AuditEvent, LeaseClaims, LeaseRequest,
    OnlineEntitlement, OnlineError, OnlineErrorCode, OnlineHttpService, SignedLease,
    SignedTimeTicket, TimeTicketClaims, TimeTicketRequest,
    service::{
        DEFAULT_LEASE_SECONDS, DEFAULT_TIME_TICKET_SECONDS, idempotency_conflict, unknown_license,
        validate_audit_text, validate_entitlement,
    },
    token::{sign_lease, sign_time_ticket},
};

const SCHEMA_VERSION: i64 = 1;

/// Transactional SQLite implementation of the online License service.
///
/// The database uses WAL, foreign keys, immediate write transactions and a
/// stored KeyId/public-key identity. The signing private key is never stored.
#[derive(Clone)]
pub struct SqliteOnlineLicenseService {
    inner: Arc<SqliteInner>,
}

struct SqliteInner {
    key_id: String,
    signing_key: SigningKey,
    lease_seconds: i64,
    ticket_seconds: i64,
    connection: Mutex<Connection>,
}

struct EntitlementRow {
    features: BTreeSet<String>,
    max_activations: u32,
    max_concurrent_leases: u32,
    revocation_epoch: u64,
    revoked: bool,
}

impl SqliteOnlineLicenseService {
    /// Opens or creates a versioned SQLite service database.
    ///
    /// Existing databases must match the supplied KeyId and verifying key.
    pub fn open(
        path: impl AsRef<Path>,
        key_id: impl Into<String>,
        signing_key: SigningKey,
    ) -> Result<Self, OnlineError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        let mut connection = Connection::open(path).map_err(database_error)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(database_error)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(database_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(database_error)?;
        migrate(&mut connection)?;
        ensure_service_identity(&mut connection, &key_id, &signing_key.verifying_key())?;
        Ok(Self {
            inner: Arc::new(SqliteInner {
                key_id,
                signing_key,
                lease_seconds: DEFAULT_LEASE_SECONDS,
                ticket_seconds: DEFAULT_TIME_TICKET_SECONDS,
                connection: Mutex::new(connection),
            }),
        })
    }

    /// Returns the online token verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.signing_key.verifying_key()
    }

    /// Returns the online token KeyId.
    pub fn key_id(&self) -> &str {
        &self.inner.key_id
    }

    /// Registers an entitlement and audit event in one immediate transaction.
    pub fn register_entitlement(
        &self,
        entitlement: OnlineEntitlement,
        actor: &str,
        now: i64,
    ) -> Result<(), OnlineError> {
        validate_entitlement(&entitlement)?;
        validate_audit_text("actor", actor)?;
        let epoch = i64::try_from(entitlement.revocation_epoch).map_err(|_| {
            OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "SQLite 后端不支持超过 i64::MAX 的撤销代际",
            )
        })?;
        let features = json_encode(&entitlement.features)?;
        let mut connection = self.lock_connection()?;
        let transaction = immediate(&mut connection)?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO entitlements
                 (license_id, features_json, max_activations, max_concurrent_leases,
                  revocation_epoch, revoked)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![
                    entitlement.license_id.to_string(),
                    features,
                    i64::from(entitlement.max_activations),
                    i64::from(entitlement.max_concurrent_leases),
                    epoch,
                ],
            )
            .map_err(database_error)?;
        if inserted == 0 {
            return Err(OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "License entitlement 已存在",
            ));
        }
        insert_audit(
            &transaction,
            now,
            AuditAction::EntitlementRegistered,
            entitlement.license_id,
            None,
            actor,
            None,
        )?;
        transaction.commit().map_err(database_error)
    }

    /// Activates an installation transactionally with persistent idempotency.
    pub fn activate(
        &self,
        request: ActivationRequest,
        now: i64,
    ) -> Result<ActivationResponse, OnlineError> {
        let request_json = json_encode(&request)?;
        let mut connection = self.lock_connection()?;
        let transaction = immediate(&mut connection)?;
        if let Some(response) =
            find_idempotent(&transaction, "activate", request.request_id, &request_json)?
        {
            transaction.commit().map_err(database_error)?;
            return Ok(response);
        }
        let entitlement = active_entitlement(&transaction, request.license_id)?;
        let existing = transaction
            .query_row(
                "SELECT activation_id, activated_at, revocation_epoch
                 FROM activations WHERE license_id = ?1 AND installation_id = ?2",
                params![
                    request.license_id.to_string(),
                    request.installation_id.to_string()
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        let (response, action) = if let Some((activation_id, activated_at, epoch)) = existing {
            (
                ActivationResponse {
                    activation_id: parse_uuid(&activation_id)?,
                    license_id: request.license_id,
                    installation_id: request.installation_id,
                    activated_at,
                    revocation_epoch: parse_epoch(epoch)?,
                },
                AuditAction::ActivationReused,
            )
        } else {
            let count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM activations WHERE license_id = ?1",
                    [request.license_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if count >= i64::from(entitlement.max_activations) {
                return Err(OnlineError::new(
                    OnlineErrorCode::ActivationLimit,
                    "激活设备数量已达上限",
                ));
            }
            let response = ActivationResponse {
                activation_id: Uuid::new_v4(),
                license_id: request.license_id,
                installation_id: request.installation_id,
                activated_at: now,
                revocation_epoch: entitlement.revocation_epoch,
            };
            transaction
                .execute(
                    "INSERT INTO activations
                     (license_id, installation_id, activation_id, activated_at, revocation_epoch)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        request.license_id.to_string(),
                        request.installation_id.to_string(),
                        response.activation_id.to_string(),
                        now,
                        i64::try_from(response.revocation_epoch).map_err(|_| database_corrupt())?,
                    ],
                )
                .map_err(database_error)?;
            (response, AuditAction::Activated)
        };
        save_idempotent(
            &transaction,
            "activate",
            request.request_id,
            &request_json,
            &response,
            now,
        )?;
        insert_audit(
            &transaction,
            now,
            action,
            request.license_id,
            Some(request.installation_id),
            "installation",
            None,
        )?;
        transaction.commit().map_err(database_error)?;
        Ok(response)
    }

    /// Issues or renews a lease without exceeding the persistent seat quota.
    pub fn issue_lease(&self, request: LeaseRequest, now: i64) -> Result<SignedLease, OnlineError> {
        let request_json = json_encode(&request)?;
        let mut connection = self.lock_connection()?;
        let transaction = immediate(&mut connection)?;
        if let Some(response) =
            find_idempotent(&transaction, "lease", request.request_id, &request_json)?
        {
            transaction.commit().map_err(database_error)?;
            return Ok(response);
        }
        let entitlement = active_entitlement(&transaction, request.license_id)?;
        require_activation(&transaction, request.license_id, request.installation_id)?;
        if request.features.is_empty() || !request.features.is_subset(&entitlement.features) {
            return Err(OnlineError::new(
                OnlineErrorCode::FeatureDenied,
                "请求包含未授权功能或空功能集",
            ));
        }
        transaction
            .execute(
                "DELETE FROM leases WHERE license_id = ?1 AND expires_at <= ?2",
                params![request.license_id.to_string(), now],
            )
            .map_err(database_error)?;
        let renews_existing: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM leases WHERE license_id = ?1 AND installation_id = ?2
                 )",
                params![
                    request.license_id.to_string(),
                    request.installation_id.to_string()
                ],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let active_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM leases WHERE license_id = ?1",
                [request.license_id.to_string()],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !renews_existing && active_count >= i64::from(entitlement.max_concurrent_leases) {
            return Err(OnlineError::new(
                OnlineErrorCode::LeaseLimit,
                "浮动租约并发数已达上限",
            ));
        }
        let claims = LeaseClaims {
            lease_id: Uuid::new_v4(),
            license_id: request.license_id,
            installation_id: request.installation_id,
            features: request.features.clone(),
            issued_at: now,
            expires_at: now.saturating_add(self.inner.lease_seconds),
            server_nonce: Uuid::new_v4(),
            revocation_epoch: entitlement.revocation_epoch,
        };
        let response = SignedLease {
            token: BASE64.encode(sign_lease(
                &claims,
                &self.inner.key_id,
                &self.inner.signing_key,
            )?),
        };
        transaction
            .execute(
                "DELETE FROM leases WHERE license_id = ?1 AND installation_id = ?2",
                params![
                    request.license_id.to_string(),
                    request.installation_id.to_string()
                ],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO leases (lease_id, license_id, installation_id, expires_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    claims.lease_id.to_string(),
                    request.license_id.to_string(),
                    request.installation_id.to_string(),
                    claims.expires_at,
                ],
            )
            .map_err(database_error)?;
        save_idempotent(
            &transaction,
            "lease",
            request.request_id,
            &request_json,
            &response,
            now,
        )?;
        insert_audit(
            &transaction,
            now,
            AuditAction::LeaseIssued,
            request.license_id,
            Some(request.installation_id),
            "installation",
            None,
        )?;
        transaction.commit().map_err(database_error)?;
        Ok(response)
    }

    /// Issues a persistently idempotent signed server-time ticket.
    pub fn issue_time_ticket(
        &self,
        request: TimeTicketRequest,
        now: i64,
    ) -> Result<SignedTimeTicket, OnlineError> {
        let request_json = json_encode(&request)?;
        let mut connection = self.lock_connection()?;
        let transaction = immediate(&mut connection)?;
        if let Some(response) = find_idempotent(
            &transaction,
            "time_ticket",
            request.request_id,
            &request_json,
        )? {
            transaction.commit().map_err(database_error)?;
            return Ok(response);
        }
        let entitlement = active_entitlement(&transaction, request.license_id)?;
        require_activation(&transaction, request.license_id, request.installation_id)?;
        let claims = TimeTicketClaims {
            license_id: request.license_id,
            installation_id: request.installation_id,
            server_time: now,
            valid_until: now.saturating_add(self.inner.ticket_seconds),
            nonce: Uuid::new_v4(),
            revocation_epoch: entitlement.revocation_epoch,
        };
        let response = SignedTimeTicket {
            token: BASE64.encode(sign_time_ticket(
                &claims,
                &self.inner.key_id,
                &self.inner.signing_key,
            )?),
        };
        save_idempotent(
            &transaction,
            "time_ticket",
            request.request_id,
            &request_json,
            &response,
            now,
        )?;
        transaction.commit().map_err(database_error)?;
        Ok(response)
    }

    /// Releases a persisted lease owned by the supplied installation.
    pub fn release_lease(
        &self,
        license_id: Uuid,
        installation_id: Uuid,
        lease_id: Uuid,
        now: i64,
    ) -> Result<bool, OnlineError> {
        let mut connection = self.lock_connection()?;
        let transaction = immediate(&mut connection)?;
        ensure_license_exists(&transaction, license_id)?;
        let owner = transaction
            .query_row(
                "SELECT installation_id FROM leases WHERE license_id = ?1 AND lease_id = ?2",
                params![license_id.to_string(), lease_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?;
        let removed = match owner {
            Some(owner) if parse_uuid(&owner)? != installation_id => {
                return Err(OnlineError::new(
                    OnlineErrorCode::ActivationRequired,
                    "租约不属于当前安装实例",
                ));
            }
            Some(_) => {
                transaction
                    .execute(
                        "DELETE FROM leases WHERE license_id = ?1 AND lease_id = ?2",
                        params![license_id.to_string(), lease_id.to_string()],
                    )
                    .map_err(database_error)?;
                true
            }
            None => false,
        };
        if removed {
            insert_audit(
                &transaction,
                now,
                AuditAction::LeaseReleased,
                license_id,
                Some(installation_id),
                "installation",
                None,
            )?;
        }
        transaction.commit().map_err(database_error)?;
        Ok(removed)
    }

    /// Removes a persisted activation and its lease, recording the actor.
    pub fn deactivate(
        &self,
        license_id: Uuid,
        installation_id: Uuid,
        actor: &str,
        reason: &str,
        now: i64,
    ) -> Result<bool, OnlineError> {
        validate_audit_text("actor", actor)?;
        validate_audit_text("reason", reason)?;
        let mut connection = self.lock_connection()?;
        let transaction = immediate(&mut connection)?;
        ensure_license_exists(&transaction, license_id)?;
        transaction
            .execute(
                "DELETE FROM leases WHERE license_id = ?1 AND installation_id = ?2",
                params![license_id.to_string(), installation_id.to_string()],
            )
            .map_err(database_error)?;
        let removed = transaction
            .execute(
                "DELETE FROM activations WHERE license_id = ?1 AND installation_id = ?2",
                params![license_id.to_string(), installation_id.to_string()],
            )
            .map_err(database_error)?
            != 0;
        if removed {
            insert_audit(
                &transaction,
                now,
                AuditAction::Deactivated,
                license_id,
                Some(installation_id),
                actor,
                Some(reason),
            )?;
        }
        transaction.commit().map_err(database_error)?;
        Ok(removed)
    }

    /// Revokes a persisted entitlement and advances its epoch atomically.
    pub fn revoke_license(
        &self,
        license_id: Uuid,
        actor: &str,
        reason: &str,
        now: i64,
    ) -> Result<u64, OnlineError> {
        validate_audit_text("actor", actor)?;
        validate_audit_text("reason", reason)?;
        let mut connection = self.lock_connection()?;
        let transaction = immediate(&mut connection)?;
        let entitlement = entitlement(&transaction, license_id)?;
        let epoch = entitlement
            .revocation_epoch
            .checked_add(1)
            .ok_or_else(|| OnlineError::new(OnlineErrorCode::Internal, "撤销代际已耗尽"))?;
        let epoch_i64 = i64::try_from(epoch)
            .map_err(|_| OnlineError::new(OnlineErrorCode::Internal, "SQLite 撤销代际已耗尽"))?;
        transaction
            .execute(
                "UPDATE entitlements SET revoked = 1, revocation_epoch = ?2
                 WHERE license_id = ?1",
                params![license_id.to_string(), epoch_i64],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM leases WHERE license_id = ?1",
                [license_id.to_string()],
            )
            .map_err(database_error)?;
        insert_audit(
            &transaction,
            now,
            AuditAction::Revoked,
            license_id,
            None,
            actor,
            Some(reason),
        )?;
        transaction.commit().map_err(database_error)?;
        Ok(epoch)
    }

    /// Reads all persisted audit events in sequence order.
    pub fn audit_events(&self) -> Result<Vec<AuditEvent>, OnlineError> {
        let connection = self.lock_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT sequence, occurred_at, action, license_id, installation_id, actor, reason
                 FROM audit_events ORDER BY sequence",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(database_error)?;
        let mut events = Vec::new();
        for row in rows {
            let (sequence, occurred_at, action, license_id, installation_id, actor, reason) =
                row.map_err(database_error)?;
            events.push(AuditEvent {
                sequence: u64::try_from(sequence).map_err(|_| database_corrupt())?,
                occurred_at,
                action: parse_action(&action)?,
                license_id: parse_uuid(&license_id)?,
                installation_id: installation_id.as_deref().map(parse_uuid).transpose()?,
                actor,
                reason,
            });
        }
        Ok(events)
    }

    /// Creates a new SQLite online backup and verifies it before returning.
    ///
    /// Existing destinations are never overwritten.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<(), OnlineError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "备份目标已存在",
            ));
        }
        let connection = self.lock_connection()?;
        if let Err(error) = connection.backup(MAIN_DB, destination, None) {
            let _ = fs::remove_file(destination);
            return Err(database_error(error));
        }
        drop(connection);
        if let Err(error) = Self::verify_backup(destination) {
            let _ = fs::remove_file(destination);
            return Err(error);
        }
        Ok(())
    }

    /// Checks SQLite integrity and the supported schema version.
    pub fn verify_backup(path: impl AsRef<Path>) -> Result<(), OnlineError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(database_error)?;
        let integrity: String = connection
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .map_err(database_error)?;
        if integrity != "ok" {
            return Err(OnlineError::new(
                OnlineErrorCode::Internal,
                "SQLite 备份完整性检查失败",
            ));
        }
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(database_error)?;
        if version != SCHEMA_VERSION {
            return Err(OnlineError::new(
                OnlineErrorCode::Internal,
                "SQLite 备份 schema 版本不兼容",
            ));
        }
        Ok(())
    }

    /// Checks backup integrity, schema and expected online signing identity.
    pub fn verify_backup_identity(
        path: impl AsRef<Path>,
        expected_key_id: &str,
        expected_verifying_key: &VerifyingKey,
    ) -> Result<(), OnlineError> {
        Self::verify_backup(&path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(database_error)?;
        let (key_id, verifying_key) = connection
            .query_row(
                "SELECT key_id, verifying_key FROM service_identity WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(database_error)?;
        if key_id != expected_key_id
            || verifying_key.as_slice() != expected_verifying_key.as_bytes()
        {
            return Err(OnlineError::new(
                OnlineErrorCode::Internal,
                "SQLite 备份签名身份不匹配",
            ));
        }
        Ok(())
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>, OnlineError> {
        self.inner
            .connection
            .lock()
            .map_err(|_| OnlineError::new(OnlineErrorCode::Internal, "数据库连接锁已损坏"))
    }
}

impl OnlineHttpService for SqliteOnlineLicenseService {
    fn activate(
        &self,
        request: ActivationRequest,
        now: i64,
    ) -> Result<ActivationResponse, OnlineError> {
        Self::activate(self, request, now)
    }

    fn issue_lease(&self, request: LeaseRequest, now: i64) -> Result<SignedLease, OnlineError> {
        Self::issue_lease(self, request, now)
    }

    fn issue_time_ticket(
        &self,
        request: TimeTicketRequest,
        now: i64,
    ) -> Result<SignedTimeTicket, OnlineError> {
        Self::issue_time_ticket(self, request, now)
    }
}

fn migrate(connection: &mut Connection) -> Result<(), OnlineError> {
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_error)?;
    if version > SCHEMA_VERSION {
        return Err(OnlineError::new(
            OnlineErrorCode::Internal,
            "数据库 schema 版本高于当前程序支持版本",
        ));
    }
    if version == 0 {
        let transaction = immediate(connection)?;
        transaction
            .execute_batch(
                "CREATE TABLE entitlements (
                    license_id TEXT PRIMARY KEY NOT NULL,
                    features_json TEXT NOT NULL,
                    max_activations INTEGER NOT NULL CHECK (max_activations > 0),
                    max_concurrent_leases INTEGER NOT NULL CHECK (max_concurrent_leases > 0),
                    revocation_epoch INTEGER NOT NULL CHECK (revocation_epoch >= 0),
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
                );
                CREATE TABLE service_identity (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                    key_id TEXT NOT NULL,
                    verifying_key BLOB NOT NULL CHECK (length(verifying_key) = 32)
                );
                CREATE TABLE activations (
                    license_id TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    activation_id TEXT NOT NULL UNIQUE,
                    activated_at INTEGER NOT NULL,
                    revocation_epoch INTEGER NOT NULL CHECK (revocation_epoch >= 0),
                    PRIMARY KEY (license_id, installation_id),
                    FOREIGN KEY (license_id) REFERENCES entitlements(license_id)
                );
                CREATE TABLE leases (
                    lease_id TEXT PRIMARY KEY NOT NULL,
                    license_id TEXT NOT NULL,
                    installation_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    UNIQUE (license_id, installation_id),
                    FOREIGN KEY (license_id, installation_id)
                        REFERENCES activations(license_id, installation_id)
                );
                CREATE INDEX leases_expiry_idx ON leases(license_id, expires_at);
                CREATE TABLE idempotency (
                    operation TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (operation, request_id)
                );
                CREATE TABLE audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    license_id TEXT NOT NULL,
                    installation_id TEXT,
                    actor TEXT NOT NULL,
                    reason TEXT
                );",
            )
            .map_err(database_error)?;
        transaction
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
    }
    Ok(())
}

fn immediate(connection: &mut Connection) -> Result<Transaction<'_>, OnlineError> {
    // Acquire SQLite's write reservation before quota reads. This prevents two
    // service processes from both observing free capacity and over-allocating.
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database_error)
}

fn ensure_service_identity(
    connection: &mut Connection,
    key_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), OnlineError> {
    let transaction = immediate(connection)?;
    let stored = transaction
        .query_row(
            "SELECT key_id, verifying_key FROM service_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(database_error)?;
    match stored {
        Some((stored_key_id, stored_key))
            if stored_key_id != key_id || stored_key.as_slice() != verifying_key.as_bytes() =>
        {
            return Err(OnlineError::new(
                OnlineErrorCode::Internal,
                "数据库签名身份与当前在线服务密钥不一致",
            ));
        }
        Some(_) => {}
        None => {
            transaction
                .execute(
                    "INSERT INTO service_identity (singleton, key_id, verifying_key)
                     VALUES (1, ?1, ?2)",
                    params![key_id, verifying_key.as_bytes().as_slice()],
                )
                .map_err(database_error)?;
        }
    }
    transaction.commit().map_err(database_error)
}

fn entitlement(
    transaction: &Transaction<'_>,
    license_id: Uuid,
) -> Result<EntitlementRow, OnlineError> {
    let row = transaction
        .query_row(
            "SELECT features_json, max_activations, max_concurrent_leases,
                    revocation_epoch, revoked
             FROM entitlements WHERE license_id = ?1",
            [license_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or_else(unknown_license)?;
    Ok(EntitlementRow {
        features: json_decode(&row.0)?,
        max_activations: u32::try_from(row.1).map_err(|_| database_corrupt())?,
        max_concurrent_leases: u32::try_from(row.2).map_err(|_| database_corrupt())?,
        revocation_epoch: parse_epoch(row.3)?,
        revoked: row.4,
    })
}

fn active_entitlement(
    transaction: &Transaction<'_>,
    license_id: Uuid,
) -> Result<EntitlementRow, OnlineError> {
    let entitlement = entitlement(transaction, license_id)?;
    if entitlement.revoked {
        return Err(OnlineError::new(
            OnlineErrorCode::LicenseRevoked,
            "License 已撤销",
        ));
    }
    Ok(entitlement)
}

fn ensure_license_exists(
    transaction: &Transaction<'_>,
    license_id: Uuid,
) -> Result<(), OnlineError> {
    entitlement(transaction, license_id).map(|_| ())
}

fn require_activation(
    transaction: &Transaction<'_>,
    license_id: Uuid,
    installation_id: Uuid,
) -> Result<(), OnlineError> {
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM activations WHERE license_id = ?1 AND installation_id = ?2
             )",
            params![license_id.to_string(), installation_id.to_string()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !exists {
        return Err(OnlineError::new(
            OnlineErrorCode::ActivationRequired,
            "安装实例尚未激活",
        ));
    }
    Ok(())
}

fn find_idempotent<T: DeserializeOwned>(
    transaction: &Transaction<'_>,
    operation: &str,
    request_id: Uuid,
    request_json: &str,
) -> Result<Option<T>, OnlineError> {
    let previous = transaction
        .query_row(
            "SELECT request_json, response_json FROM idempotency
             WHERE operation = ?1 AND request_id = ?2",
            params![operation, request_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(database_error)?;
    match previous {
        Some((previous_request, _)) if previous_request != request_json => {
            Err(idempotency_conflict())
        }
        Some((_, response)) => json_decode(&response).map(Some),
        None => Ok(None),
    }
}

fn save_idempotent<T: Serialize>(
    transaction: &Transaction<'_>,
    operation: &str,
    request_id: Uuid,
    request_json: &str,
    response: &T,
    now: i64,
) -> Result<(), OnlineError> {
    transaction
        .execute(
            "INSERT INTO idempotency
             (operation, request_id, request_json, response_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation,
                request_id.to_string(),
                request_json,
                json_encode(response)?,
                now,
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

fn insert_audit(
    transaction: &Transaction<'_>,
    occurred_at: i64,
    action: AuditAction,
    license_id: Uuid,
    installation_id: Option<Uuid>,
    actor: &str,
    reason: Option<&str>,
) -> Result<(), OnlineError> {
    transaction
        .execute(
            "INSERT INTO audit_events
             (occurred_at, action, license_id, installation_id, actor, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                occurred_at,
                action_name(action),
                license_id.to_string(),
                installation_id.map(|value| value.to_string()),
                actor,
                reason,
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

fn action_name(action: AuditAction) -> &'static str {
    match action {
        AuditAction::EntitlementRegistered => "entitlement_registered",
        AuditAction::Activated => "activated",
        AuditAction::ActivationReused => "activation_reused",
        AuditAction::LeaseIssued => "lease_issued",
        AuditAction::LeaseReused => "lease_reused",
        AuditAction::LeaseReleased => "lease_released",
        AuditAction::Deactivated => "deactivated",
        AuditAction::Revoked => "revoked",
    }
}

fn parse_action(value: &str) -> Result<AuditAction, OnlineError> {
    match value {
        "entitlement_registered" => Ok(AuditAction::EntitlementRegistered),
        "activated" => Ok(AuditAction::Activated),
        "activation_reused" => Ok(AuditAction::ActivationReused),
        "lease_issued" => Ok(AuditAction::LeaseIssued),
        "lease_reused" => Ok(AuditAction::LeaseReused),
        "lease_released" => Ok(AuditAction::LeaseReleased),
        "deactivated" => Ok(AuditAction::Deactivated),
        "revoked" => Ok(AuditAction::Revoked),
        _ => Err(database_corrupt()),
    }
}

fn validate_key_id(key_id: &str) -> Result<(), OnlineError> {
    if key_id.is_empty() || key_id.len() > 64 || key_id.chars().any(char::is_control) {
        return Err(OnlineError::new(
            OnlineErrorCode::InvalidRequest,
            "在线票据 key_id 无效",
        ));
    }
    Ok(())
}

fn parse_uuid(value: &str) -> Result<Uuid, OnlineError> {
    Uuid::parse_str(value).map_err(|_| database_corrupt())
}

fn parse_epoch(value: i64) -> Result<u64, OnlineError> {
    u64::try_from(value).map_err(|_| database_corrupt())
}

fn json_encode<T: Serialize>(value: &T) -> Result<String, OnlineError> {
    serde_json::to_string(value).map_err(|_| database_corrupt())
}

fn json_decode<T: DeserializeOwned>(value: &str) -> Result<T, OnlineError> {
    serde_json::from_str(value).map_err(|_| database_corrupt())
}

fn database_error(_: rusqlite::Error) -> OnlineError {
    OnlineError::new(OnlineErrorCode::Internal, "持久化存储操作失败")
}

fn database_corrupt() -> OnlineError {
    OnlineError::new(OnlineErrorCode::Internal, "持久化数据格式无效")
}
