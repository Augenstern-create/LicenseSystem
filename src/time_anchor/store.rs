use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{StateProtector, TimeAnchorError};

const STATE_SCHEMA_VERSION: u16 = 1;
const MAX_STATE_FILE_SIZE: u64 = 64 * 1024;
const DEFAULT_ROLLBACK_TOLERANCE: Duration = Duration::from_secs(6 * 60 * 60);

/// Outcome of a successful time-anchor observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeAnchorStatus {
    /// No prior state existed and a new installation anchor was created.
    Created,
    /// UTC advanced or remained at the trusted value.
    Advanced,
    /// UTC moved backward but remained inside the configured tolerance.
    AdjustedWithinTolerance,
}

/// Trusted result returned after observing UTC and monotonic time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeAnchorObservation {
    /// State transition performed by the observation.
    pub status: TimeAnchorStatus,
    /// Stable random installation identifier stored in protected state.
    pub installation_id: Uuid,
    /// Highest trusted UTC Unix timestamp after the observation.
    pub trusted_utc: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorState {
    schema_version: u16,
    installation_id: Uuid,
    last_seen_utc: i64,
    last_monotonic_ms: u64,
    license_id: Uuid,
}

/// Protected, atomically updated time-anchor state store.
#[derive(Debug)]
pub struct TimeAnchorStore<P> {
    path: PathBuf,
    protector: P,
    rollback_tolerance: Duration,
}

impl<P: StateProtector> TimeAnchorStore<P> {
    /// Creates a store using the default six-hour rollback tolerance.
    pub fn new(path: impl Into<PathBuf>, protector: P) -> Self {
        Self {
            path: path.into(),
            protector,
            rollback_tolerance: DEFAULT_ROLLBACK_TOLERANCE,
        }
    }

    /// Overrides the accepted wall-clock rollback tolerance.
    pub fn with_rollback_tolerance(mut self, tolerance: Duration) -> Self {
        self.rollback_tolerance = tolerance;
        self
    }

    /// Observes trusted UTC and monotonic milliseconds, then atomically updates state.
    ///
    /// The method holds an exclusive transaction lock, rejects symlinks and
    /// never moves the persisted trusted UTC backward.
    pub fn observe(
        &self,
        license_id: Uuid,
        now: OffsetDateTime,
        monotonic_ms: u64,
    ) -> Result<TimeAnchorObservation, TimeAnchorError> {
        let _lock = acquire_transaction_lock(&self.path)?;
        let current_utc = now.unix_timestamp();
        let Some(mut state) = self.load()? else {
            let state = AnchorState {
                schema_version: STATE_SCHEMA_VERSION,
                installation_id: Uuid::new_v4(),
                last_seen_utc: current_utc,
                last_monotonic_ms: monotonic_ms,
                license_id,
            };
            self.save(&state)?;
            return Ok(TimeAnchorObservation {
                status: TimeAnchorStatus::Created,
                installation_id: state.installation_id,
                trusted_utc: state.last_seen_utc,
            });
        };

        if state.schema_version != STATE_SCHEMA_VERSION {
            return Err(TimeAnchorError::StateInvalid(
                "不支持的 schema_version".to_owned(),
            ));
        }
        let tolerance = i64::try_from(self.rollback_tolerance.as_secs()).unwrap_or(i64::MAX);
        let utc_floor = state.last_seen_utc.saturating_sub(tolerance);
        let monotonic_floor = if monotonic_ms >= state.last_monotonic_ms {
            let elapsed =
                i64::try_from((monotonic_ms - state.last_monotonic_ms) / 1000).unwrap_or(i64::MAX);
            state
                .last_seen_utc
                .saturating_add(elapsed)
                .saturating_sub(tolerance)
        } else {
            i64::MIN
        };
        if current_utc < utc_floor || current_utc < monotonic_floor {
            return Err(TimeAnchorError::RollbackDetected {
                last_seen_utc: state.last_seen_utc,
                current_utc,
            });
        }

        let status = if current_utc < state.last_seen_utc {
            TimeAnchorStatus::AdjustedWithinTolerance
        } else {
            TimeAnchorStatus::Advanced
        };
        state.last_seen_utc = state.last_seen_utc.max(current_utc);
        state.last_monotonic_ms = monotonic_ms;
        state.license_id = license_id;
        self.save(&state)?;
        Ok(TimeAnchorObservation {
            status,
            installation_id: state.installation_id,
            trusted_utc: state.last_seen_utc,
        })
    }

    fn load(&self) -> Result<Option<AnchorState>, TimeAnchorError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            return Err(TimeAnchorError::SymlinkNotAllowed);
        }
        if metadata.len() > MAX_STATE_FILE_SIZE {
            return Err(TimeAnchorError::StateTooLarge);
        }
        let file = fs::File::open(&self.path)?;
        let mut protected = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_STATE_FILE_SIZE + 1)
            .read_to_end(&mut protected)?;
        if protected.len() as u64 > MAX_STATE_FILE_SIZE {
            return Err(TimeAnchorError::StateTooLarge);
        }
        let plaintext = self.protector.unprotect(&protected)?;
        let state = serde_json::from_slice(&plaintext)
            .map_err(|error| TimeAnchorError::StateInvalid(error.to_string()))?;
        Ok(Some(state))
    }

    fn save(&self, state: &AnchorState) -> Result<(), TimeAnchorError> {
        let plaintext = serde_json::to_vec(state)
            .map_err(|error| TimeAnchorError::StateInvalid(error.to_string()))?;
        let protected = self.protector.protect(&plaintext)?;
        if protected.len() as u64 > MAX_STATE_FILE_SIZE {
            return Err(TimeAnchorError::StateTooLarge);
        }
        atomic_write(&self.path, &protected)
    }
}

fn transaction_lock_path(path: &Path) -> Result<PathBuf, TimeAnchorError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| TimeAnchorError::StateInvalid("状态文件名不是有效文本".to_owned()))?;
    Ok(parent.join(format!("{file_name}.lock")))
}

#[cfg(windows)]
fn acquire_transaction_lock(path: &Path) -> Result<fs::File, TimeAnchorError> {
    use std::os::windows::fs::OpenOptionsExt;

    let lock_path = transaction_lock_path(path)?;
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(lock_path)
        .map_err(|error| {
            if error.raw_os_error() == Some(32) {
                TimeAnchorError::Busy
            } else {
                error.into()
            }
        })
}

#[cfg(not(windows))]
fn acquire_transaction_lock(path: &Path) -> Result<fs::File, TimeAnchorError> {
    let lock_path = transaction_lock_path(path)?;
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), TimeAnchorError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| TimeAnchorError::StateInvalid("状态文件名不是有效文本".to_owned()))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<(), TimeAnchorError> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain([0]).collect();
    let destination: Vec<u16> = destination.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: both paths are valid, NUL-terminated UTF-16 buffers for the duration of the call.
    let success = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> Result<(), TimeAnchorError> {
    fs::rename(source, destination)?;
    Ok(())
}
