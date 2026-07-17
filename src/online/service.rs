use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{SigningKey, VerifyingKey};
use uuid::Uuid;

use super::{
    ActivationRequest, ActivationResponse, AuditAction, AuditEvent, LeaseClaims, LeaseRequest,
    OnlineEntitlement, OnlineError, OnlineErrorCode, SignedLease, SignedTimeTicket,
    TimeTicketClaims, TimeTicketRequest,
    token::{sign_lease, sign_time_ticket},
};

pub(crate) const DEFAULT_LEASE_SECONDS: i64 = 5 * 60;
pub(crate) const DEFAULT_TIME_TICKET_SECONDS: i64 = 24 * 60 * 60;

/// In-memory reference implementation of the online License state machine.
///
/// All decisions are serialized by one mutex. State is lost on process restart;
/// use [`crate::online::SqliteOnlineLicenseService`] when persistence is needed.
#[derive(Clone)]
pub struct OnlineLicenseService {
    inner: Arc<ServiceInner>,
}

struct ServiceInner {
    key_id: String,
    signing_key: SigningKey,
    lease_seconds: i64,
    ticket_seconds: i64,
    state: Mutex<ServiceState>,
}

#[derive(Default)]
struct ServiceState {
    licenses: HashMap<Uuid, LicenseRecord>,
    activation_requests: HashMap<Uuid, (ActivationRequest, ActivationResponse)>,
    lease_requests: HashMap<Uuid, (LeaseRequest, SignedLease)>,
    time_requests: HashMap<Uuid, (TimeTicketRequest, SignedTimeTicket)>,
    audit: Vec<AuditEvent>,
    next_audit_sequence: u64,
}

struct LicenseRecord {
    entitlement: OnlineEntitlement,
    revoked: bool,
    activations: HashMap<Uuid, ActivationResponse>,
    leases: HashMap<Uuid, LeaseRecord>,
}

struct LeaseRecord {
    installation_id: Uuid,
    expires_at: i64,
}

impl OnlineLicenseService {
    /// Creates a reference service using the supplied online signing key.
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey) -> Result<Self, OnlineError> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > 64 || key_id.chars().any(char::is_control) {
            return Err(OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "在线票据 key_id 无效",
            ));
        }
        Ok(Self {
            inner: Arc::new(ServiceInner {
                key_id,
                signing_key,
                lease_seconds: DEFAULT_LEASE_SECONDS,
                ticket_seconds: DEFAULT_TIME_TICKET_SECONDS,
                state: Mutex::new(ServiceState::default()),
            }),
        })
    }

    /// Returns the online token verifying key for client configuration.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.signing_key.verifying_key()
    }

    /// Returns the KeyId embedded in online tokens.
    pub fn key_id(&self) -> &str {
        &self.inner.key_id
    }

    /// Registers a controlled entitlement; this is an administrative operation.
    pub fn register_entitlement(
        &self,
        entitlement: OnlineEntitlement,
        actor: &str,
        now: i64,
    ) -> Result<(), OnlineError> {
        validate_entitlement(&entitlement)?;
        validate_audit_text("actor", actor)?;
        let license_id = entitlement.license_id;
        let mut state = self.lock_state()?;
        if state.licenses.contains_key(&license_id) {
            return Err(OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "License entitlement 已存在",
            ));
        }
        state.licenses.insert(
            license_id,
            LicenseRecord {
                entitlement,
                revoked: false,
                activations: HashMap::new(),
                leases: HashMap::new(),
            },
        );
        push_audit(
            &mut state,
            now,
            AuditAction::EntitlementRegistered,
            license_id,
            None,
            actor,
            None,
        );
        Ok(())
    }

    /// Activates an installation with request-id idempotency and quota checks.
    pub fn activate(
        &self,
        request: ActivationRequest,
        now: i64,
    ) -> Result<ActivationResponse, OnlineError> {
        let mut state = self.lock_state()?;
        if let Some((previous_request, response)) =
            state.activation_requests.get(&request.request_id)
        {
            if previous_request != &request {
                return Err(idempotency_conflict());
            }
            return Ok(response.clone());
        }
        let (response, action) = {
            let record = get_active_license(&mut state, request.license_id)?;
            if let Some(existing) = record.activations.get(&request.installation_id) {
                (existing.clone(), AuditAction::ActivationReused)
            } else {
                if record.activations.len() >= record.entitlement.max_activations as usize {
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
                    revocation_epoch: record.entitlement.revocation_epoch,
                };
                record
                    .activations
                    .insert(request.installation_id, response.clone());
                (response, AuditAction::Activated)
            }
        };
        state
            .activation_requests
            .insert(request.request_id, (request.clone(), response.clone()));
        push_audit(
            &mut state,
            now,
            action,
            request.license_id,
            Some(request.installation_id),
            "installation",
            None,
        );
        Ok(response)
    }

    /// Issues or renews a five-minute signed feature lease.
    pub fn issue_lease(&self, request: LeaseRequest, now: i64) -> Result<SignedLease, OnlineError> {
        // The mutex is the reference backend's transaction boundary: cleanup,
        // quota evaluation, signing, idempotency and state insertion are serialized.
        let mut state = self.lock_state()?;
        if let Some((previous_request, response)) = state.lease_requests.get(&request.request_id) {
            if previous_request != &request {
                return Err(idempotency_conflict());
            }
            return Ok(response.clone());
        }
        let claims = {
            let record = get_active_license(&mut state, request.license_id)?;
            require_activation(record, request.installation_id)?;
            if request.features.is_empty()
                || !request.features.is_subset(&record.entitlement.features)
            {
                return Err(OnlineError::new(
                    OnlineErrorCode::FeatureDenied,
                    "请求包含未授权功能或空功能集",
                ));
            }
            record.leases.retain(|_, lease| lease.expires_at > now);
            let renews_existing = record
                .leases
                .values()
                .any(|lease| lease.installation_id == request.installation_id);
            if !renews_existing
                && record.leases.len() >= record.entitlement.max_concurrent_leases as usize
            {
                return Err(OnlineError::new(
                    OnlineErrorCode::LeaseLimit,
                    "浮动租约并发数已达上限",
                ));
            }
            LeaseClaims {
                lease_id: Uuid::new_v4(),
                license_id: request.license_id,
                installation_id: request.installation_id,
                features: request.features.clone(),
                issued_at: now,
                expires_at: now.saturating_add(self.inner.lease_seconds),
                server_nonce: Uuid::new_v4(),
                revocation_epoch: record.entitlement.revocation_epoch,
            }
        };
        let token = sign_lease(&claims, &self.inner.key_id, &self.inner.signing_key)?;
        let response = SignedLease {
            token: BASE64.encode(token),
        };
        let record = state
            .licenses
            .get_mut(&request.license_id)
            .ok_or_else(unknown_license)?;
        record
            .leases
            .retain(|_, lease| lease.installation_id != request.installation_id);
        record.leases.insert(
            claims.lease_id,
            LeaseRecord {
                installation_id: request.installation_id,
                expires_at: claims.expires_at,
            },
        );
        state
            .lease_requests
            .insert(request.request_id, (request.clone(), response.clone()));
        push_audit(
            &mut state,
            now,
            AuditAction::LeaseIssued,
            request.license_id,
            Some(request.installation_id),
            "installation",
            None,
        );
        Ok(response)
    }

    /// Issues a signed 24-hour server-time ticket.
    pub fn issue_time_ticket(
        &self,
        request: TimeTicketRequest,
        now: i64,
    ) -> Result<SignedTimeTicket, OnlineError> {
        let mut state = self.lock_state()?;
        if let Some((previous_request, response)) = state.time_requests.get(&request.request_id) {
            if previous_request != &request {
                return Err(idempotency_conflict());
            }
            return Ok(response.clone());
        }
        let claims = {
            let record = get_active_license(&mut state, request.license_id)?;
            require_activation(record, request.installation_id)?;
            TimeTicketClaims {
                license_id: request.license_id,
                installation_id: request.installation_id,
                server_time: now,
                valid_until: now.saturating_add(self.inner.ticket_seconds),
                nonce: Uuid::new_v4(),
                revocation_epoch: record.entitlement.revocation_epoch,
            }
        };
        let token = sign_time_ticket(&claims, &self.inner.key_id, &self.inner.signing_key)?;
        let response = SignedTimeTicket {
            token: BASE64.encode(token),
        };
        state
            .time_requests
            .insert(request.request_id, (request.clone(), response.clone()));
        Ok(response)
    }

    /// Releases a lease when it belongs to the supplied installation.
    ///
    /// Returns `false` when the lease is already absent.
    pub fn release_lease(
        &self,
        license_id: Uuid,
        installation_id: Uuid,
        lease_id: Uuid,
        now: i64,
    ) -> Result<bool, OnlineError> {
        let mut state = self.lock_state()?;
        let removed = {
            let record = state
                .licenses
                .get_mut(&license_id)
                .ok_or_else(unknown_license)?;
            match record.leases.get(&lease_id) {
                Some(lease) if lease.installation_id != installation_id => {
                    return Err(OnlineError::new(
                        OnlineErrorCode::ActivationRequired,
                        "租约不属于当前安装实例",
                    ));
                }
                Some(_) => record.leases.remove(&lease_id).is_some(),
                None => false,
            }
        };
        if removed {
            push_audit(
                &mut state,
                now,
                AuditAction::LeaseReleased,
                license_id,
                Some(installation_id),
                "installation",
                None,
            );
        }
        Ok(removed)
    }

    /// Removes an installation activation and its active leases.
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
        let mut state = self.lock_state()?;
        let removed = {
            let record = state
                .licenses
                .get_mut(&license_id)
                .ok_or_else(unknown_license)?;
            record
                .leases
                .retain(|_, lease| lease.installation_id != installation_id);
            record.activations.remove(&installation_id).is_some()
        };
        if removed {
            push_audit(
                &mut state,
                now,
                AuditAction::Deactivated,
                license_id,
                Some(installation_id),
                actor,
                Some(reason),
            );
        }
        Ok(removed)
    }

    /// Revokes an entitlement, advances its epoch and clears active leases.
    pub fn revoke_license(
        &self,
        license_id: Uuid,
        actor: &str,
        reason: &str,
        now: i64,
    ) -> Result<u64, OnlineError> {
        validate_audit_text("actor", actor)?;
        validate_audit_text("reason", reason)?;
        let mut state = self.lock_state()?;
        let epoch = {
            let record = state
                .licenses
                .get_mut(&license_id)
                .ok_or_else(unknown_license)?;
            record.revoked = true;
            record.entitlement.revocation_epoch =
                record.entitlement.revocation_epoch.saturating_add(1);
            record.leases.clear();
            record.entitlement.revocation_epoch
        };
        push_audit(
            &mut state,
            now,
            AuditAction::Revoked,
            license_id,
            None,
            actor,
            Some(reason),
        );
        Ok(epoch)
    }

    /// Returns a snapshot of in-memory audit events.
    pub fn audit_events(&self) -> Result<Vec<AuditEvent>, OnlineError> {
        Ok(self.lock_state()?.audit.clone())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ServiceState>, OnlineError> {
        self.inner
            .state
            .lock()
            .map_err(|_| OnlineError::new(OnlineErrorCode::Internal, "在线服务状态锁已损坏"))
    }
}

fn get_active_license(
    state: &mut ServiceState,
    license_id: Uuid,
) -> Result<&mut LicenseRecord, OnlineError> {
    let record = state
        .licenses
        .get_mut(&license_id)
        .ok_or_else(unknown_license)?;
    if record.revoked {
        return Err(OnlineError::new(
            OnlineErrorCode::LicenseRevoked,
            "License 已撤销",
        ));
    }
    Ok(record)
}

fn require_activation(record: &LicenseRecord, installation_id: Uuid) -> Result<(), OnlineError> {
    if !record.activations.contains_key(&installation_id) {
        return Err(OnlineError::new(
            OnlineErrorCode::ActivationRequired,
            "安装实例尚未激活",
        ));
    }
    Ok(())
}

pub(crate) fn validate_entitlement(entitlement: &OnlineEntitlement) -> Result<(), OnlineError> {
    if entitlement.max_activations == 0
        || entitlement.max_concurrent_leases == 0
        || entitlement.features.is_empty()
        || entitlement.features.len() > 256
    {
        return Err(OnlineError::new(
            OnlineErrorCode::InvalidRequest,
            "entitlement 的配额或功能集合无效",
        ));
    }
    for feature in &entitlement.features {
        if feature.is_empty() || feature.len() > 128 || feature.chars().any(char::is_control) {
            return Err(OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "entitlement 功能名无效",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_audit_text(name: &str, value: &str) -> Result<(), OnlineError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(OnlineError::new(
            OnlineErrorCode::InvalidRequest,
            format!("审计字段 {name} 无效"),
        ));
    }
    Ok(())
}

fn push_audit(
    state: &mut ServiceState,
    occurred_at: i64,
    action: AuditAction,
    license_id: Uuid,
    installation_id: Option<Uuid>,
    actor: &str,
    reason: Option<&str>,
) {
    state.next_audit_sequence = state.next_audit_sequence.saturating_add(1);
    state.audit.push(AuditEvent {
        sequence: state.next_audit_sequence,
        occurred_at,
        action,
        license_id,
        installation_id,
        actor: actor.to_owned(),
        reason: reason.map(str::to_owned),
    });
}

pub(crate) fn unknown_license() -> OnlineError {
    OnlineError::new(OnlineErrorCode::UnknownLicense, "License 未注册")
}

pub(crate) fn idempotency_conflict() -> OnlineError {
    OnlineError::new(OnlineErrorCode::InvalidRequest, "request_id 已用于不同请求")
}
