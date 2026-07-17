use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Serialize;
use time::OffsetDateTime;

use super::{
    ActivationRequest, ActivationResponse, LeaseRequest, OnlineError, OnlineErrorCode,
    OnlineLicenseService, SignedLease, SignedTimeTicket, TimeTicketRequest,
};

/// Minimal service contract consumed by the public HTTP router.
pub trait OnlineHttpService: Clone + Send + Sync + 'static {
    /// Activates an installation.
    fn activate(
        &self,
        request: ActivationRequest,
        now: i64,
    ) -> Result<ActivationResponse, OnlineError>;
    /// Issues or renews a signed feature lease.
    fn issue_lease(&self, request: LeaseRequest, now: i64) -> Result<SignedLease, OnlineError>;
    /// Issues a signed server-time ticket.
    fn issue_time_ticket(
        &self,
        request: TimeTicketRequest,
        now: i64,
    ) -> Result<SignedTimeTicket, OnlineError>;
}

impl OnlineHttpService for OnlineLicenseService {
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

/// Builds the public JSON API router for activation, lease and time tickets.
///
/// The router intentionally exposes no entitlement, revocation or audit
/// administration endpoints and enforces a 64 KiB body limit.
pub fn online_router<S: OnlineHttpService>(service: S) -> Router {
    Router::new()
        .route("/v1/activate", post(activate::<S>))
        .route("/v1/lease", post(issue_lease::<S>))
        .route("/v1/time-ticket", post(issue_time_ticket::<S>))
        .with_state(service)
        .layer(DefaultBodyLimit::max(64 * 1024))
}

async fn activate<S: OnlineHttpService>(
    State(service): State<S>,
    payload: Result<Json<ActivationRequest>, JsonRejection>,
) -> Result<impl IntoResponse, HttpError> {
    let Json(request) = payload.map_err(HttpError::from_rejection)?;
    service
        .activate(request, now())
        .map(Json)
        .map_err(HttpError)
}

async fn issue_lease<S: OnlineHttpService>(
    State(service): State<S>,
    payload: Result<Json<LeaseRequest>, JsonRejection>,
) -> Result<impl IntoResponse, HttpError> {
    let Json(request) = payload.map_err(HttpError::from_rejection)?;
    service
        .issue_lease(request, now())
        .map(Json)
        .map_err(HttpError)
}

async fn issue_time_ticket<S: OnlineHttpService>(
    State(service): State<S>,
    payload: Result<Json<TimeTicketRequest>, JsonRejection>,
) -> Result<impl IntoResponse, HttpError> {
    let Json(request) = payload.map_err(HttpError::from_rejection)?;
    service
        .issue_time_ticket(request, now())
        .map(Json)
        .map_err(HttpError)
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub(crate) struct HttpError(pub(crate) OnlineError);

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: OnlineErrorCode,
    detail: &'a str,
}

impl HttpError {
    fn from_rejection(rejection: JsonRejection) -> Self {
        let code = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            OnlineErrorCode::PayloadTooLarge
        } else {
            OnlineErrorCode::InvalidRequest
        };
        Self(OnlineError::new(
            code,
            format!("JSON 请求无效：{}", rejection.body_text()),
        ))
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = match self.0.code() {
            OnlineErrorCode::UnknownLicense => StatusCode::NOT_FOUND,
            OnlineErrorCode::LicenseRevoked
            | OnlineErrorCode::ActivationRequired
            | OnlineErrorCode::FeatureDenied
            | OnlineErrorCode::RevocationEpochStale => StatusCode::FORBIDDEN,
            OnlineErrorCode::ActivationLimit
            | OnlineErrorCode::LeaseLimit
            | OnlineErrorCode::TokenReplay => StatusCode::CONFLICT,
            OnlineErrorCode::InvalidRequest
            | OnlineErrorCode::TokenInvalid
            | OnlineErrorCode::TokenExpired => StatusCode::BAD_REQUEST,
            OnlineErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            OnlineErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            OnlineErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            OnlineErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = ErrorBody {
            code: self.0.code(),
            detail: self.0.detail(),
        };
        (status, Json(body)).into_response()
    }
}
