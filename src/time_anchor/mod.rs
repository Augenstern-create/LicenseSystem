//! Protected local time anchor used to detect unacceptable wall-clock rollback.

mod protector;
mod store;

use std::{error::Error, fmt, io};

use crate::ErrorCode;

#[cfg(windows)]
pub use protector::DpapiStateProtector;
pub use protector::{HmacStateProtector, StateProtector};
pub use store::{TimeAnchorObservation, TimeAnchorStatus, TimeAnchorStore};

/// Failure returned by time-anchor protection, storage or rollback checks.
#[derive(Debug)]
pub enum TimeAnchorError {
    /// Filesystem operation failed.
    Io(io::Error),
    /// HMAC or DPAPI protection failed.
    ProtectionFailed(String),
    /// Decoded state is malformed or unsupported.
    StateInvalid(String),
    /// Protected state exceeds the configured size limit.
    StateTooLarge,
    /// A symbolic-link state path was rejected.
    SymlinkNotAllowed,
    /// Another process currently owns the transaction lock.
    Busy,
    /// Trusted UTC moved backward beyond the configured tolerance.
    RollbackDetected {
        /// Highest previously trusted UTC Unix timestamp.
        last_seen_utc: i64,
        /// Current observed UTC Unix timestamp.
        current_utc: i64,
    },
}

impl fmt::Display for TimeAnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "时间锚 I/O 失败：{error}"),
            Self::ProtectionFailed(detail) => write!(formatter, "时间锚鉴权失败：{detail}"),
            Self::StateInvalid(detail) => write!(formatter, "时间锚状态无效：{detail}"),
            Self::StateTooLarge => write!(formatter, "时间锚状态文件过大"),
            Self::SymlinkNotAllowed => write!(formatter, "时间锚路径不允许符号链接"),
            Self::Busy => write!(formatter, "时间锚正在被另一个进程更新"),
            Self::RollbackDetected {
                last_seen_utc,
                current_utc,
            } => write!(
                formatter,
                "检测到系统时间回拨：last_seen={last_seen_utc}, current={current_utc}"
            ),
        }
    }
}

impl TimeAnchorError {
    /// Maps rollback to the stable License error model.
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::RollbackDetected { .. } => ErrorCode::TimeRollback,
            Self::Io(_)
            | Self::ProtectionFailed(_)
            | Self::StateInvalid(_)
            | Self::StateTooLarge
            | Self::SymlinkNotAllowed
            | Self::Busy => ErrorCode::FormatInvalid,
        }
    }
}

impl Error for TimeAnchorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for TimeAnchorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
