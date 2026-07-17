use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::{
    OnlineError, OnlineErrorCode, OnlineHttpService,
    http::{HttpError, online_router},
};

/// Snapshot of non-sensitive in-process HTTP counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    /// Completed requests, including rate-limited responses.
    pub requests_total: u64,
    /// Requests currently executing inside the protected router.
    pub requests_in_flight: usize,
    /// Completed successful responses.
    pub responses_2xx: u64,
    /// Completed client-error responses.
    pub responses_4xx: u64,
    /// Completed server-error responses.
    pub responses_5xx: u64,
    /// Requests rejected by the fixed-window limiter.
    pub rate_limited: u64,
}

/// Cloneable in-process metrics collector.
#[derive(Clone, Default)]
pub struct OperationalMetrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    requests_total: AtomicU64,
    requests_in_flight: AtomicUsize,
    responses_2xx: AtomicU64,
    responses_4xx: AtomicU64,
    responses_5xx: AtomicU64,
    rate_limited: AtomicU64,
}

impl OperationalMetrics {
    /// Returns an atomic point-in-time snapshot.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.inner.requests_total.load(Ordering::Relaxed),
            requests_in_flight: self.inner.requests_in_flight.load(Ordering::Relaxed),
            responses_2xx: self.inner.responses_2xx.load(Ordering::Relaxed),
            responses_4xx: self.inner.responses_4xx.load(Ordering::Relaxed),
            responses_5xx: self.inner.responses_5xx.load(Ordering::Relaxed),
            rate_limited: self.inner.rate_limited.load(Ordering::Relaxed),
        }
    }

    fn record_response(&self, status: axum::http::StatusCode) {
        self.inner.requests_total.fetch_add(1, Ordering::Relaxed);
        match status.as_u16() {
            200..=299 => self.inner.responses_2xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.inner.responses_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => self.inner.responses_5xx.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }
}

/// Global fixed-window rate guard and associated metrics.
#[derive(Clone)]
pub struct RequestGuard {
    metrics: OperationalMetrics,
    limiter: Arc<Mutex<FixedWindow>>,
}

struct FixedWindow {
    started_at: Instant,
    duration: Duration,
    maximum: u64,
    used: u64,
}

impl RequestGuard {
    /// Creates a guard for `maximum_requests` in each `window`.
    pub fn new(
        maximum_requests: u64,
        window: Duration,
        metrics: OperationalMetrics,
    ) -> Result<Self, OnlineError> {
        if maximum_requests == 0 || window.is_zero() {
            return Err(OnlineError::new(
                OnlineErrorCode::InvalidRequest,
                "限流窗口和请求上限必须大于零",
            ));
        }
        Ok(Self {
            metrics,
            limiter: Arc::new(Mutex::new(FixedWindow {
                started_at: Instant::now(),
                duration: window,
                maximum: maximum_requests,
                used: 0,
            })),
        })
    }

    /// Returns the metrics collector updated by this guard.
    pub fn metrics(&self) -> OperationalMetrics {
        self.metrics.clone()
    }

    fn try_acquire(&self) -> Result<bool, OnlineError> {
        let mut limiter = self
            .limiter
            .lock()
            .map_err(|_| OnlineError::new(OnlineErrorCode::Internal, "限流状态锁已损坏"))?;
        if limiter.started_at.elapsed() >= limiter.duration {
            limiter.started_at = Instant::now();
            limiter.used = 0;
        }
        if limiter.used >= limiter.maximum {
            return Ok(false);
        }
        limiter.used += 1;
        Ok(true)
    }
}

/// Applies rate limiting and metrics to the public online router.
pub fn hardened_online_router<S: OnlineHttpService>(service: S, guard: RequestGuard) -> Router {
    apply_guard(online_router(service), guard)
}

pub(crate) fn apply_guard(router: Router, guard: RequestGuard) -> Router {
    router.layer(middleware::from_fn_with_state(guard, protect_request))
}

async fn protect_request(
    State(guard): State<RequestGuard>,
    request: Request,
    next: Next,
) -> Response {
    match guard.try_acquire() {
        Ok(true) => {}
        Ok(false) => {
            guard
                .metrics
                .inner
                .rate_limited
                .fetch_add(1, Ordering::Relaxed);
            let response = HttpError(OnlineError::new(
                OnlineErrorCode::RateLimited,
                "请求频率超过服务端限制",
            ))
            .into_response();
            guard.metrics.record_response(response.status());
            return response;
        }
        Err(error) => {
            let response = HttpError(error).into_response();
            guard.metrics.record_response(response.status());
            return response;
        }
    }
    guard
        .metrics
        .inner
        .requests_in_flight
        .fetch_add(1, Ordering::Relaxed);
    let response = next.run(request).await;
    guard
        .metrics
        .inner
        .requests_in_flight
        .fetch_sub(1, Ordering::Relaxed);
    guard.metrics.record_response(response.status());
    response
}
