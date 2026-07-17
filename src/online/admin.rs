use std::{collections::BTreeSet, path::PathBuf};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    AuditEvent, OnlineEntitlement, OnlineError, OnlineErrorCode, OperationalMetrics, RequestGuard,
    SqliteOnlineLicenseService, http::HttpError, operations::apply_guard,
};

/// Constant-time Bearer-token authenticator for the reference admin API.
///
/// Only a SHA-256 digest and credential identifier are retained.
#[derive(Clone)]
pub struct AdminAuthenticator {
    credential_id: String,
    token_hash: [u8; 32],
}

impl AdminAuthenticator {
    /// Creates an authenticator from a credential id and high-entropy token.
    pub fn new(credential_id: impl Into<String>, token: &[u8]) -> Result<Self, OnlineError> {
        let credential_id = credential_id.into();
        if credential_id.is_empty()
            || credential_id.len() > 128
            || credential_id.chars().any(char::is_control)
        {
            return Err(OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "管理员 credential_id 无效",
            ));
        }
        if token.len() < 32 || token.len() > 1024 {
            return Err(OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "管理员 token 长度必须为 32..=1024 字节",
            ));
        }
        Ok(Self {
            credential_id,
            token_hash: Sha256::digest(token).into(),
        })
    }

    fn authenticate<'a>(&'a self, headers: &HeaderMap) -> Result<&'a str, OnlineError> {
        let supplied = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty())
            .ok_or_else(unauthorized)?;
        let supplied_hash: [u8; 32] = Sha256::digest(supplied.as_bytes()).into();
        // Compare fixed-size digests in constant time; never compare the bearer
        // token directly or persist it in service state.
        if !bool::from(supplied_hash.ct_eq(&self.token_hash)) {
            return Err(unauthorized());
        }
        Ok(&self.credential_id)
    }
}

#[derive(Clone)]
struct AdminState {
    service: SqliteOnlineLicenseService,
    authenticator: AdminAuthenticator,
    operational_metrics: OperationalMetrics,
    backup_directory: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterEntitlementRequest {
    license_id: Uuid,
    features: BTreeSet<String>,
    max_activations: u32,
    max_concurrent_leases: u32,
    revocation_epoch: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasonRequest {
    reason: String,
}

#[derive(Serialize)]
struct EpochResponse {
    revocation_epoch: u64,
}

#[derive(Serialize)]
struct ChangedResponse {
    changed: bool,
}

#[derive(Serialize)]
struct BackupResponse {
    file_name: String,
}

/// Builds the authenticated SQLite administration router.
///
/// Endpoints register entitlements, revoke or deactivate, read audit/metrics
/// and trigger backups inside a server-configured directory.
pub fn admin_router(
    service: SqliteOnlineLicenseService,
    authenticator: AdminAuthenticator,
    operational_metrics: OperationalMetrics,
    backup_directory: impl Into<PathBuf>,
    guard: RequestGuard,
) -> Result<Router, OnlineError> {
    let backup_directory = backup_directory.into();
    if !backup_directory.is_dir() {
        return Err(OnlineError::new(
            OnlineErrorCode::InvalidRequest,
            "备份目录不存在或不是目录",
        ));
    }
    let state = AdminState {
        service,
        authenticator,
        operational_metrics,
        backup_directory,
    };
    let router = Router::new()
        .route("/admin/v1/entitlements", post(register_entitlement))
        .route("/admin/v1/licenses/{license_id}/revoke", post(revoke))
        .route(
            "/admin/v1/licenses/{license_id}/installations/{installation_id}",
            delete(deactivate),
        )
        .route("/admin/v1/audit", get(audit))
        .route("/admin/v1/metrics", get(get_metrics))
        .route("/admin/v1/backup", post(backup))
        .with_state(state)
        .layer(DefaultBodyLimit::max(64 * 1024));
    Ok(apply_guard(router, guard))
}

async fn register_entitlement(
    State(state): State<AdminState>,
    headers: HeaderMap,
    payload: Result<Json<RegisterEntitlementRequest>, JsonRejection>,
) -> Result<impl IntoResponse, HttpError> {
    let actor = state
        .authenticator
        .authenticate(&headers)
        .map_err(HttpError)?;
    let Json(request) = payload.map_err(json_error)?;
    state
        .service
        .register_entitlement(
            OnlineEntitlement {
                license_id: request.license_id,
                features: request.features,
                max_activations: request.max_activations,
                max_concurrent_leases: request.max_concurrent_leases,
                revocation_epoch: request.revocation_epoch,
            },
            actor,
            now(),
        )
        .map_err(HttpError)?;
    Ok(StatusCode::CREATED)
}

async fn revoke(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(license_id): Path<String>,
    payload: Result<Json<ReasonRequest>, JsonRejection>,
) -> Result<Json<EpochResponse>, HttpError> {
    let actor = state
        .authenticator
        .authenticate(&headers)
        .map_err(HttpError)?;
    let license_id = parse_uuid(&license_id)?;
    let Json(request) = payload.map_err(json_error)?;
    let revocation_epoch = state
        .service
        .revoke_license(license_id, actor, &request.reason, now())
        .map_err(HttpError)?;
    Ok(Json(EpochResponse { revocation_epoch }))
}

async fn deactivate(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path((license_id, installation_id)): Path<(String, String)>,
    payload: Result<Json<ReasonRequest>, JsonRejection>,
) -> Result<Json<ChangedResponse>, HttpError> {
    let actor = state
        .authenticator
        .authenticate(&headers)
        .map_err(HttpError)?;
    let license_id = parse_uuid(&license_id)?;
    let installation_id = parse_uuid(&installation_id)?;
    let Json(request) = payload.map_err(json_error)?;
    let changed = state
        .service
        .deactivate(license_id, installation_id, actor, &request.reason, now())
        .map_err(HttpError)?;
    Ok(Json(ChangedResponse { changed }))
}

async fn audit(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditEvent>>, HttpError> {
    state
        .authenticator
        .authenticate(&headers)
        .map_err(HttpError)?;
    state.service.audit_events().map(Json).map_err(HttpError)
}

async fn get_metrics(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, HttpError> {
    state
        .authenticator
        .authenticate(&headers)
        .map_err(HttpError)?;
    Ok(Json(state.operational_metrics.snapshot()))
}

async fn backup(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Result<Json<BackupResponse>, HttpError> {
    state
        .authenticator
        .authenticate(&headers)
        .map_err(HttpError)?;
    let file_name = format!("license-backup-{}-{}.sqlite", now(), Uuid::new_v4());
    let destination = state.backup_directory.join(&file_name);
    state.service.backup_to(destination).map_err(HttpError)?;
    Ok(Json(BackupResponse { file_name }))
}

fn parse_uuid(value: &str) -> Result<Uuid, HttpError> {
    Uuid::parse_str(value).map_err(|_| {
        HttpError(OnlineError::new(
            OnlineErrorCode::InvalidRequest,
            "路径 UUID 无效",
        ))
    })
}

fn json_error(rejection: JsonRejection) -> HttpError {
    let code = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        OnlineErrorCode::PayloadTooLarge
    } else {
        OnlineErrorCode::InvalidRequest
    };
    HttpError(OnlineError::new(
        code,
        format!("JSON 请求无效：{}", rejection.body_text()),
    ))
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn unauthorized() -> OnlineError {
    OnlineError::new(OnlineErrorCode::Unauthorized, "管理员认证失败")
}
