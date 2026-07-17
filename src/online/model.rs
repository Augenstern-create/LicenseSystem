use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Server-controlled online entitlement and quota definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineEntitlement {
    /// License identifier shared with offline payloads.
    pub license_id: Uuid,
    /// Feature names that online leases may grant.
    pub features: BTreeSet<String>,
    /// Maximum distinct activated installations.
    pub max_activations: u32,
    /// Maximum concurrent installation leases.
    pub max_concurrent_leases: u32,
    /// Current server revocation generation.
    pub revocation_epoch: u64,
}

/// Idempotent client request to activate an installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRequest {
    /// Client-generated idempotency identifier.
    pub request_id: Uuid,
    /// Registered License identifier.
    pub license_id: Uuid,
    /// Random installation identifier.
    pub installation_id: Uuid,
}

/// Activation record returned to the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationResponse {
    /// Server-generated activation identifier.
    pub activation_id: Uuid,
    /// Registered License identifier.
    pub license_id: Uuid,
    /// Activated installation identifier.
    pub installation_id: Uuid,
    /// Server UTC Unix timestamp.
    pub activated_at: i64,
    /// Revocation generation at activation time.
    pub revocation_epoch: u64,
}

/// Idempotent request for a short-lived signed feature lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    /// Client-generated idempotency identifier.
    pub request_id: Uuid,
    /// Registered License identifier.
    pub license_id: Uuid,
    /// Activated installation identifier.
    pub installation_id: Uuid,
    /// Non-empty subset of entitled features.
    pub features: BTreeSet<String>,
}

/// Idempotent request for a signed server-time ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeTicketRequest {
    /// Client-generated idempotency identifier.
    pub request_id: Uuid,
    /// Registered License identifier.
    pub license_id: Uuid,
    /// Activated installation identifier.
    pub installation_id: Uuid,
}

/// Verified claims contained in a signed lease token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseClaims {
    /// Server-generated lease identifier.
    pub lease_id: Uuid,
    /// License identifier.
    pub license_id: Uuid,
    /// Installation receiving the lease.
    pub installation_id: Uuid,
    /// Features granted by this lease.
    pub features: BTreeSet<String>,
    /// Server UTC Unix issuance timestamp.
    pub issued_at: i64,
    /// Exclusive UTC expiration timestamp.
    pub expires_at: i64,
    /// Server-generated replay discriminator.
    pub server_nonce: Uuid,
    /// Revocation generation embedded in the lease.
    pub revocation_epoch: u64,
}

/// Verified claims contained in a signed time ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeTicketClaims {
    /// License identifier.
    pub license_id: Uuid,
    /// Installation receiving the ticket.
    pub installation_id: Uuid,
    /// Server UTC Unix time at issuance.
    pub server_time: i64,
    /// Exclusive UTC validity end.
    pub valid_until: i64,
    /// Server-generated replay discriminator.
    pub nonce: Uuid,
    /// Revocation generation embedded in the ticket.
    pub revocation_epoch: u64,
}

/// Base64-encoded canonical signed lease token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLease {
    /// Base64 token transported by JSON APIs.
    pub token: String,
}

/// Base64-encoded canonical signed time ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTimeTicket {
    /// Base64 token transported by JSON APIs.
    pub token: String,
}

/// Minimal auditable state transition performed by the online service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// A controlled entitlement was registered.
    EntitlementRegistered,
    /// A new installation activation was created.
    Activated,
    /// An existing installation activation was reused.
    ActivationReused,
    /// A lease was issued or renewed.
    LeaseIssued,
    /// A prior idempotent lease response was reused.
    LeaseReused,
    /// An active lease was explicitly released.
    LeaseReleased,
    /// An installation was deactivated.
    Deactivated,
    /// A License was revoked and its epoch advanced.
    Revoked,
}

/// Minimal online-service audit event without private or raw machine data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    /// Monotonically increasing event sequence.
    pub sequence: u64,
    /// Server UTC Unix timestamp.
    pub occurred_at: i64,
    /// State transition type.
    pub action: AuditAction,
    /// Affected License identifier.
    pub license_id: Uuid,
    /// Optional affected installation identifier.
    pub installation_id: Option<Uuid>,
    /// Server-authenticated or fixed system actor.
    pub actor: String,
    /// Optional bounded administrative reason.
    pub reason: Option<String>,
}
