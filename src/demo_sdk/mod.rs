//! Executable image-SDK example that consumes [`crate::AuthorizationContext`].

mod algorithm;
mod device;
mod error;
mod model;
mod scheduler;

use std::sync::Arc;

use crate::AuthorizationContext;

pub use algorithm::{AlgorithmKind, ProcessingReceipt};
pub use error::SdkError;
pub use scheduler::JobPermit;

use algorithm::AlgorithmRegistry;
use device::DeviceManager;
use model::ModelStore;
use scheduler::JobScheduler;

/// A small, executable image SDK used to demonstrate deep License integration.
///
/// The SDK never reads a License file. It receives the immutable context created
/// by the validator and injects it into the components that consume authorization.
#[derive(Debug)]
pub struct DemoImageSdk {
    authorization: Arc<AuthorizationContext>,
    algorithms: AlgorithmRegistry,
    scheduler: Arc<JobScheduler>,
    models: ModelStore,
    devices: DeviceManager,
}

impl DemoImageSdk {
    /// Builds the SDK and rejects invalid mandatory limits.
    pub fn new(authorization: AuthorizationContext) -> Result<Self, SdkError> {
        let authorization = Arc::new(authorization);
        let scheduler = Arc::new(JobScheduler::new(
            authorization.get_limit("max_parallel_jobs", 0),
        )?);

        Ok(Self {
            algorithms: AlgorithmRegistry::from_authorization(Arc::clone(&authorization)),
            scheduler,
            models: ModelStore::new(Arc::clone(&authorization)),
            devices: DeviceManager::new(Arc::clone(&authorization))?,
            authorization,
        })
    }

    /// Returns algorithms registered from authorized feature flags.
    pub fn registered_algorithms(&self) -> Vec<AlgorithmKind> {
        self.algorithms.registered()
    }

    /// Atomically acquires one parallel job slot.
    pub fn start_job(&self) -> Result<JobPermit, SdkError> {
        JobScheduler::try_start(&self.scheduler)
    }

    /// Returns the current number of active job permits.
    pub fn active_jobs(&self) -> usize {
        self.scheduler.active_jobs()
    }

    /// Validates model scope and algorithm authorization, then simulates processing.
    pub fn run_algorithm(
        &self,
        algorithm: AlgorithmKind,
        model_id: &str,
    ) -> Result<ProcessingReceipt, SdkError> {
        self.models.require_model(model_id)?;
        self.algorithms.run(algorithm, model_id)
    }

    /// Returns `true` for a newly connected device and `false` for an existing one.
    pub fn connect_device(&self, device_id: &str) -> Result<bool, SdkError> {
        self.devices.connect(device_id)
    }

    /// Disconnects a device, returning whether it was connected.
    pub fn disconnect_device(&self, device_id: &str) -> Result<bool, SdkError> {
        self.devices.disconnect(device_id)
    }

    /// Returns the number of currently connected devices.
    pub fn connected_devices(&self) -> Result<usize, SdkError> {
        self.devices.connected_count()
    }

    /// Returns the immutable authorization context injected into the SDK.
    pub fn authorization(&self) -> &AuthorizationContext {
        &self.authorization
    }
}
