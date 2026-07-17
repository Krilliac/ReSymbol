//! Safe, narrow access to one explicitly selected Windows process image.
//!
//! The crate is deliberately smaller than a debugger provider. It does not
//! launch, attach, suspend, resume, step, set breakpoints, or authenticate a
//! helper transport. On Windows it owns one process handle and exposes only
//! exact-binding main-image RVA reads plus same-length compare-before-write
//! mutations. Read-only and mutating opens have separate typestates, and the
//! exact hashed executable file handle remains retained without write/delete
//! sharing. All Win32 FFI remains private to the platform module.

#![deny(unsafe_op_in_unsafe_fn)]

use resymbol_core::BinaryId;
use resymbol_debugger::protocol::{MAX_MEMORY_READ_BYTES, MAX_MEMORY_WRITE_BYTES, ProcessId};
use thiserror::Error;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    LiveAccessError, LiveProcessAccess, MutatingLiveProcessAccess, MutationAccess,
    MutationRecovery, MutationStage, ReadOnlyAccess, ReadOnlyLiveProcessAccess, WriteReceipt,
};

/// Largest exact live read accepted by this boundary.
pub const MAX_EXACT_READ_BYTES: usize = MAX_MEMORY_READ_BYTES as usize;

/// Largest compare-before-write mutation accepted by this boundary.
pub const MAX_COMPARE_WRITE_BYTES: usize = MAX_MEMORY_WRITE_BYTES;

/// Explicit authority-free selection used to open a live process handle.
///
/// This request is not an attach lease and does not authorize execution
/// control. The Windows adapter derives the process start key and runtime image
/// mapping itself and rejects an executable whose exact SHA-256 differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenLiveProcessRequest {
    process_id: ProcessId,
    expected_main_module_binary_id: BinaryId,
}

impl OpenLiveProcessRequest {
    #[must_use]
    pub const fn new(process_id: ProcessId, expected_main_module_binary_id: BinaryId) -> Self {
        Self {
            process_id,
            expected_main_module_binary_id,
        }
    }

    #[must_use]
    pub const fn process_id(&self) -> ProcessId {
        self.process_id
    }

    #[must_use]
    pub const fn expected_main_module_binary_id(&self) -> &BinaryId {
        &self.expected_main_module_binary_id
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum AccessRequestError {
    #[error("live memory reads must request at least one byte")]
    EmptyRead,
    #[error("live memory read size {actual} exceeds the {maximum}-byte limit")]
    ReadTooLarge { actual: usize, maximum: usize },
    #[error("live memory writes must replace at least one byte")]
    EmptyWrite,
    #[error("live memory write size {actual} exceeds the {maximum}-byte limit")]
    WriteTooLarge { actual: usize, maximum: usize },
    #[error("compare-before-write lengths differ: expected {expected}, replacement {replacement}")]
    WriteLengthMismatch { expected: usize, replacement: usize },
    #[error("compare-before-write replacement is identical to the expected bytes")]
    NoopWrite,
}

pub(crate) fn validate_read_size(size: usize) -> Result<(), AccessRequestError> {
    if size == 0 {
        return Err(AccessRequestError::EmptyRead);
    }
    if size > MAX_EXACT_READ_BYTES {
        return Err(AccessRequestError::ReadTooLarge {
            actual: size,
            maximum: MAX_EXACT_READ_BYTES,
        });
    }
    Ok(())
}

pub(crate) fn validate_write_request(
    expected: &[u8],
    replacement: &[u8],
) -> Result<(), AccessRequestError> {
    if expected.is_empty() {
        return Err(AccessRequestError::EmptyWrite);
    }
    if expected.len() > MAX_COMPARE_WRITE_BYTES {
        return Err(AccessRequestError::WriteTooLarge {
            actual: expected.len(),
            maximum: MAX_COMPARE_WRITE_BYTES,
        });
    }
    if expected.len() != replacement.len() {
        return Err(AccessRequestError::WriteLengthMismatch {
            expected: expected.len(),
            replacement: replacement.len(),
        });
    }
    if expected == replacement {
        return Err(AccessRequestError::NoopWrite);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AccessRequestError, MAX_COMPARE_WRITE_BYTES, MAX_EXACT_READ_BYTES, validate_read_size,
        validate_write_request,
    };

    #[test]
    fn read_size_validation_is_nonempty_and_bounded() {
        assert_eq!(validate_read_size(0), Err(AccessRequestError::EmptyRead));
        assert_eq!(validate_read_size(1), Ok(()));
        assert_eq!(validate_read_size(MAX_EXACT_READ_BYTES), Ok(()));
        assert_eq!(
            validate_read_size(MAX_EXACT_READ_BYTES + 1),
            Err(AccessRequestError::ReadTooLarge {
                actual: MAX_EXACT_READ_BYTES + 1,
                maximum: MAX_EXACT_READ_BYTES,
            })
        );
    }

    #[test]
    fn write_validation_requires_equal_changed_bounded_bytes() {
        assert_eq!(
            validate_write_request(&[], &[]),
            Err(AccessRequestError::EmptyWrite)
        );
        assert_eq!(
            validate_write_request(&[1], &[1, 2]),
            Err(AccessRequestError::WriteLengthMismatch {
                expected: 1,
                replacement: 2,
            })
        );
        assert_eq!(
            validate_write_request(&[1], &[1]),
            Err(AccessRequestError::NoopWrite)
        );
        assert_eq!(validate_write_request(&[1], &[2]), Ok(()));

        let oversized = vec![0_u8; MAX_COMPARE_WRITE_BYTES + 1];
        let replacement = vec![1_u8; MAX_COMPARE_WRITE_BYTES + 1];
        assert_eq!(
            validate_write_request(&oversized, &replacement),
            Err(AccessRequestError::WriteTooLarge {
                actual: MAX_COMPARE_WRITE_BYTES + 1,
                maximum: MAX_COMPARE_WRITE_BYTES,
            })
        );
    }
}
