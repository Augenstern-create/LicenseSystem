use std::{collections::BTreeSet, sync::Arc};

use crate::AuthorizationContext;

use super::SdkError;

/// Processing algorithm exposed by the demonstration SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlgorithmKind {
    /// Always-available CPU processing.
    Cpu,
    /// GPU processing requiring the `gpu` feature.
    Gpu,
    /// Deep-zoom processing requiring the `deepzoom` feature.
    DeepZoom,
    /// Batch processing requiring the `batch` feature.
    Batch,
}

impl AlgorithmKind {
    /// Returns the stable feature/API name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::DeepZoom => "deepzoom",
            Self::Batch => "batch",
        }
    }

    const fn required_feature(self) -> Option<&'static str> {
        match self {
            Self::Cpu => None,
            Self::Gpu => Some("gpu"),
            Self::DeepZoom => Some("deepzoom"),
            Self::Batch => Some("batch"),
        }
    }
}

/// Result of one successfully authorized demonstration processing call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingReceipt {
    /// Algorithm that ran.
    pub algorithm: AlgorithmKind,
    /// Authorized model identifier consumed by the call.
    pub model_id: String,
}

#[derive(Debug)]
pub(crate) struct AlgorithmRegistry {
    authorization: Arc<AuthorizationContext>,
    registered: BTreeSet<AlgorithmKind>,
}

impl AlgorithmRegistry {
    pub(crate) fn from_authorization(authorization: Arc<AuthorizationContext>) -> Self {
        let mut registered = BTreeSet::from([AlgorithmKind::Cpu]);
        for algorithm in [
            AlgorithmKind::Gpu,
            AlgorithmKind::DeepZoom,
            AlgorithmKind::Batch,
        ] {
            if algorithm
                .required_feature()
                .is_some_and(|feature| authorization.has_feature(feature))
            {
                registered.insert(algorithm);
            }
        }
        Self {
            authorization,
            registered,
        }
    }

    pub(crate) fn registered(&self) -> Vec<AlgorithmKind> {
        self.registered.iter().copied().collect()
    }

    pub(crate) fn run(
        &self,
        algorithm: AlgorithmKind,
        model_id: &str,
    ) -> Result<ProcessingReceipt, SdkError> {
        if !self.registered.contains(&algorithm) {
            return Err(SdkError::AlgorithmUnavailable {
                algorithm: algorithm.name().to_owned(),
            });
        }
        if let Some(feature) = algorithm.required_feature() {
            self.authorization
                .require_feature(feature)
                .map_err(|_| SdkError::FeatureDenied {
                    feature: feature.to_owned(),
                })?;
        }
        Ok(ProcessingReceipt {
            algorithm,
            model_id: model_id.to_owned(),
        })
    }
}
