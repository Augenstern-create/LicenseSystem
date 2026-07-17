use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use crate::AuthorizationContext;

use super::SdkError;

#[derive(Debug)]
pub(crate) struct DeviceManager {
    authorization: Arc<AuthorizationContext>,
    max_devices: usize,
    connected: Mutex<HashSet<String>>,
}

impl DeviceManager {
    pub(crate) fn new(authorization: Arc<AuthorizationContext>) -> Result<Self, SdkError> {
        let value = authorization.get_limit("max_devices", 0);
        let max_devices = usize::try_from(value).map_err(|_| SdkError::InvalidLimit {
            name: "max_devices",
            value,
        })?;
        Ok(Self {
            authorization,
            max_devices,
            connected: Mutex::new(HashSet::new()),
        })
    }

    pub(crate) fn connect(&self, device_id: &str) -> Result<bool, SdkError> {
        if !self
            .authorization
            .get_resource_scope("device_ids")
            .iter()
            .any(|allowed| allowed == device_id)
        {
            return Err(SdkError::ResourceDenied {
                kind: "device",
                id: device_id.to_owned(),
            });
        }
        let mut connected = self
            .connected
            .lock()
            .map_err(|_| SdkError::InternalStatePoisoned)?;
        if connected.contains(device_id) {
            return Ok(false);
        }
        if connected.len() >= self.max_devices {
            return Err(SdkError::DeviceLimitReached {
                limit: self.max_devices,
            });
        }
        connected.insert(device_id.to_owned());
        Ok(true)
    }

    pub(crate) fn disconnect(&self, device_id: &str) -> Result<bool, SdkError> {
        self.connected
            .lock()
            .map(|mut connected| connected.remove(device_id))
            .map_err(|_| SdkError::InternalStatePoisoned)
    }

    pub(crate) fn connected_count(&self) -> Result<usize, SdkError> {
        self.connected
            .lock()
            .map(|connected| connected.len())
            .map_err(|_| SdkError::InternalStatePoisoned)
    }
}
