use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::SdkError;

#[derive(Debug)]
pub(crate) struct JobScheduler {
    limit: usize,
    active: AtomicUsize,
}

impl JobScheduler {
    pub(crate) fn new(limit: u64) -> Result<Self, SdkError> {
        let limit = usize::try_from(limit).map_err(|_| SdkError::InvalidLimit {
            name: "max_parallel_jobs",
            value: limit,
        })?;
        if limit == 0 {
            return Err(SdkError::InvalidLimit {
                name: "max_parallel_jobs",
                value: 0,
            });
        }
        Ok(Self {
            limit,
            active: AtomicUsize::new(0),
        })
    }

    pub(crate) fn try_start(scheduler: &Arc<Self>) -> Result<JobPermit, SdkError> {
        let mut current = scheduler.active.load(Ordering::Acquire);
        loop {
            if current >= scheduler.limit {
                return Err(SdkError::ParallelLimitReached {
                    limit: scheduler.limit,
                });
            }
            match scheduler.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(JobPermit {
                        scheduler: Arc::clone(scheduler),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    pub(crate) fn active_jobs(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

/// RAII permit representing one active authorized job slot.
///
/// Dropping the permit atomically releases capacity.
#[derive(Debug)]
pub struct JobPermit {
    scheduler: Arc<JobScheduler>,
}

impl Drop for JobPermit {
    fn drop(&mut self) {
        self.scheduler.active.fetch_sub(1, Ordering::AcqRel);
    }
}
