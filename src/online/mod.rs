//! Online activation, lease, time-ticket and operational service APIs.
//!
//! Signed online tokens use independent Ed25519 domains from offline License
//! files. The module provides both an in-memory reference service and a
//! transactional SQLite implementation.

mod admin;
mod client;
mod error;
mod http;
mod model;
mod operations;
mod service;
mod sqlite;
mod token;

pub use admin::{AdminAuthenticator, admin_router};
pub use client::OnlineTokenVerifier;
pub use error::{OnlineError, OnlineErrorCode};
pub use http::{OnlineHttpService, online_router};
pub use model::{
    ActivationRequest, ActivationResponse, AuditAction, AuditEvent, LeaseClaims, LeaseRequest,
    OnlineEntitlement, SignedLease, SignedTimeTicket, TimeTicketClaims, TimeTicketRequest,
};
pub use operations::{MetricsSnapshot, OperationalMetrics, RequestGuard, hardened_online_router};
pub use service::OnlineLicenseService;
pub use sqlite::SqliteOnlineLicenseService;
