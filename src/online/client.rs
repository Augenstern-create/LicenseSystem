use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::VerifyingKey;
use uuid::Uuid;

use super::{
    LeaseClaims, OnlineError, OnlineErrorCode, SignedLease, SignedTimeTicket, TimeTicketClaims,
    token::{DecodedOnlineToken, verify_token},
};

#[derive(Default)]
struct ReplayState {
    leases: HashMap<(Uuid, Uuid), (i64, Uuid)>,
    time_tickets: HashMap<(Uuid, Uuid), (i64, Uuid)>,
}

/// Client-side verifier for signed online leases and time tickets.
///
/// The verifier trusts one local KeyId/public-key pair and keeps an in-process
/// replay cache. Products that require replay protection across restarts must
/// persist equivalent state in protected local storage.
pub struct OnlineTokenVerifier {
    key_id: String,
    verifying_key: VerifyingKey,
    replay: Mutex<ReplayState>,
}

impl OnlineTokenVerifier {
    /// Creates a verifier for one trusted online signing identity.
    pub fn new(
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
    ) -> Result<Self, OnlineError> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > 64 || key_id.chars().any(char::is_control) {
            return Err(OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "在线票据 key_id 无效",
            ));
        }
        Ok(Self {
            key_id,
            verifying_key,
            replay: Mutex::new(ReplayState::default()),
        })
    }

    /// Verifies a lease's signature, subject, time, epoch and replay order.
    pub fn verify_lease(
        &self,
        signed: &SignedLease,
        expected_license_id: Uuid,
        expected_installation_id: Uuid,
        now: i64,
        minimum_revocation_epoch: u64,
    ) -> Result<LeaseClaims, OnlineError> {
        let claims = match self.decode(&signed.token)? {
            DecodedOnlineToken::Lease(claims) => claims,
            DecodedOnlineToken::TimeTicket(_) => return Err(invalid("票据类型不是 Lease")),
        };
        validate_subject(
            claims.license_id,
            claims.installation_id,
            expected_license_id,
            expected_installation_id,
        )?;
        if claims.expires_at <= claims.issued_at || now < claims.issued_at {
            return Err(invalid("Lease 时间范围无效或尚未生效"));
        }
        if now >= claims.expires_at {
            return Err(OnlineError::new(
                OnlineErrorCode::TokenExpired,
                "Lease 已过期",
            ));
        }
        validate_epoch(claims.revocation_epoch, minimum_revocation_epoch)?;

        let mut replay = self.lock_replay()?;
        reject_stale(
            replay
                .leases
                .entry((claims.license_id, claims.installation_id))
                .or_insert((claims.issued_at, claims.lease_id)),
            (claims.issued_at, claims.lease_id),
        )?;
        Ok(claims)
    }

    /// Verifies a time ticket's signature, subject, time, epoch and replay order.
    pub fn verify_time_ticket(
        &self,
        signed: &SignedTimeTicket,
        expected_license_id: Uuid,
        expected_installation_id: Uuid,
        now: i64,
        minimum_revocation_epoch: u64,
    ) -> Result<TimeTicketClaims, OnlineError> {
        let claims = match self.decode(&signed.token)? {
            DecodedOnlineToken::TimeTicket(claims) => claims,
            DecodedOnlineToken::Lease(_) => return Err(invalid("票据类型不是 TimeTicket")),
        };
        validate_subject(
            claims.license_id,
            claims.installation_id,
            expected_license_id,
            expected_installation_id,
        )?;
        if claims.valid_until <= claims.server_time || now < claims.server_time {
            return Err(invalid("TimeTicket 时间范围无效或尚未生效"));
        }
        if now >= claims.valid_until {
            return Err(OnlineError::new(
                OnlineErrorCode::TokenExpired,
                "TimeTicket 已过期",
            ));
        }
        validate_epoch(claims.revocation_epoch, minimum_revocation_epoch)?;

        let mut replay = self.lock_replay()?;
        reject_stale(
            replay
                .time_tickets
                .entry((claims.license_id, claims.installation_id))
                .or_insert((claims.server_time, claims.nonce)),
            (claims.server_time, claims.nonce),
        )?;
        Ok(claims)
    }

    fn decode(&self, encoded: &str) -> Result<DecodedOnlineToken, OnlineError> {
        let bytes = BASE64
            .decode(encoded)
            .map_err(|_| invalid("在线票据 Base64 无效"))?;
        verify_token(&bytes, &self.key_id, &self.verifying_key)
    }

    fn lock_replay(&self) -> Result<MutexGuard<'_, ReplayState>, OnlineError> {
        self.replay
            .lock()
            .map_err(|_| OnlineError::new(OnlineErrorCode::Internal, "票据重放缓存锁已损坏"))
    }
}

fn validate_subject(
    license_id: Uuid,
    installation_id: Uuid,
    expected_license_id: Uuid,
    expected_installation_id: Uuid,
) -> Result<(), OnlineError> {
    if license_id != expected_license_id || installation_id != expected_installation_id {
        return Err(invalid("在线票据不属于当前 License 或安装实例"));
    }
    Ok(())
}

fn validate_epoch(actual: u64, minimum: u64) -> Result<(), OnlineError> {
    if actual < minimum {
        return Err(OnlineError::new(
            OnlineErrorCode::RevocationEpochStale,
            "在线票据撤销代际低于本地已知代际",
        ));
    }
    Ok(())
}

fn reject_stale(current: &mut (i64, Uuid), candidate: (i64, Uuid)) -> Result<(), OnlineError> {
    // Exact retries are allowed for idempotency; older timestamps or a different
    // token at the same timestamp are treated as replay.
    if candidate.0 < current.0 || (candidate.0 == current.0 && candidate.1 != current.1) {
        return Err(OnlineError::new(
            OnlineErrorCode::TokenReplay,
            "检测到旧票据或同时间点的不同票据",
        ));
    }
    if candidate.0 > current.0 {
        *current = candidate;
    }
    Ok(())
}

fn invalid(detail: impl Into<String>) -> OnlineError {
    OnlineError::new(OnlineErrorCode::TokenInvalid, detail)
}
