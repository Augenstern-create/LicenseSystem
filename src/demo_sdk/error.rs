use std::{error::Error, fmt};

/// Product-integration error returned by the demonstration SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdkError {
    /// A required feature flag is disabled.
    FeatureDenied {
        /// Required feature name.
        feature: String,
    },
    /// The algorithm was not registered from the authorization context.
    AlgorithmUnavailable {
        /// Requested algorithm name.
        algorithm: String,
    },
    /// A model or device is outside its signed allowlist.
    ResourceDenied {
        /// Resource category.
        kind: &'static str,
        /// Rejected resource identifier.
        id: String,
    },
    /// All authorized parallel job slots are active.
    ParallelLimitReached {
        /// Signed parallel limit.
        limit: usize,
    },
    /// All authorized device slots are active.
    DeviceLimitReached {
        /// Signed device limit.
        limit: usize,
    },
    /// A mandatory numeric limit is missing or cannot be represented.
    InvalidLimit {
        /// Limit name.
        name: &'static str,
        /// Invalid supplied value.
        value: u64,
    },
    /// A mutex or other shared internal state was poisoned.
    InternalStatePoisoned,
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeatureDenied { feature } => write!(formatter, "功能未授权：{feature}"),
            Self::AlgorithmUnavailable { algorithm } => {
                write!(formatter, "算法未注册：{algorithm}")
            }
            Self::ResourceDenied { kind, id } => {
                write!(formatter, "资源不在授权范围：{kind}/{id}")
            }
            Self::ParallelLimitReached { limit } => {
                write!(formatter, "并行任务额度已用尽：{limit}")
            }
            Self::DeviceLimitReached { limit } => {
                write!(formatter, "设备连接额度已用尽：{limit}")
            }
            Self::InvalidLimit { name, value } => {
                write!(formatter, "License 额度无效：{name}={value}")
            }
            Self::InternalStatePoisoned => write!(formatter, "SDK 内部状态不可用"),
        }
    }
}

impl Error for SdkError {}
