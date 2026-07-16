//! Bounded host-response batches shared by clients and pipe transports.

use thiserror::Error;

use crate::host_codec::HostFrame;
use crate::host_wire::{FrameHeader, MAX_CONTROL_BYTES};
use crate::protocol::MAX_MEMORY_READ_BYTES;

pub const MAX_RESPONSE_FRAMES: usize = 256;
/// Maximum encoded size of one typed host response frame.
///
/// The typed codec permits at most one memory-read payload per frame. This is
/// intentionally narrower than the generic wire layer's raw-payload ceiling.
pub const MAX_RESPONSE_FRAME_BYTES: usize = 4 + MAX_CONTROL_BYTES + MAX_MEMORY_READ_BYTES as usize;
/// Maximum encoded bytes in one synchronous host response batch.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub const DEFAULT_HOST_RESPONSE_LIMITS: HostResponseLimits = HostResponseLimits {
    max_frames: MAX_RESPONSE_FRAMES,
    max_frame_bytes: MAX_RESPONSE_FRAME_BYTES,
    max_total_bytes: MAX_RESPONSE_BYTES,
};

/// Allocation limits supplied by the trusted connection owner to a transport.
///
/// A real pipe transport must read the peer-declared batch count first, create
/// a [`HostResponseBatchBuilder`], and preflight each decoded frame header
/// before allocating or reading its raw payload. The client still revalidates
/// the returned batch under [`DEFAULT_HOST_RESPONSE_LIMITS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostResponseLimits {
    max_frames: usize,
    max_frame_bytes: usize,
    max_total_bytes: usize,
}

impl HostResponseLimits {
    pub fn new(
        max_frames: usize,
        max_frame_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self, HostResponseBudgetError> {
        if max_frames == 0 || max_frame_bytes == 0 || max_total_bytes == 0 {
            return Err(HostResponseBudgetError::InvalidLimits);
        }
        Ok(Self {
            max_frames,
            max_frame_bytes,
            max_total_bytes,
        })
    }

    #[must_use]
    pub const fn max_frames(self) -> usize {
        self.max_frames
    }

    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }

    #[must_use]
    pub const fn max_total_bytes(self) -> usize {
        self.max_total_bytes
    }

    fn validate(self) -> Result<(), HostResponseBudgetError> {
        if self.max_frames == 0 || self.max_frame_bytes == 0 || self.max_total_bytes == 0 {
            Err(HostResponseBudgetError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

impl Default for HostResponseLimits {
    fn default() -> Self {
        DEFAULT_HOST_RESPONSE_LIMITS
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum HostResponseBudgetError {
    #[error("host response limits must all be nonzero")]
    InvalidLimits,
    #[error("host declared {declared} response frames; maximum is {maximum}")]
    DeclaredFrameCountExceeded { declared: usize, maximum: usize },
    #[error("host declared {declared} response frames but supplied {actual}")]
    FrameCountMismatch { declared: usize, actual: usize },
    #[error("host response frame {index} has {actual} encoded bytes; maximum is {maximum}")]
    FrameTooLarge {
        index: usize,
        actual: usize,
        maximum: usize,
    },
    #[error("host response byte-count arithmetic overflow")]
    TotalBytesOverflow,
    #[error("host response batch has {actual} encoded bytes; maximum is {maximum}")]
    TotalBytesExceeded { actual: usize, maximum: usize },
    #[error("host response batch recorded {recorded} bytes but contains {actual}")]
    RecordedTotalMismatch { recorded: usize, actual: usize },
    #[error("host response frame permit is stale or out of order")]
    StaleFramePermit,
    #[error("host response frame has an invalid encoded length")]
    InvalidFrameLength,
}

/// A private-invariant batch returned by a host frame exchange.
///
/// The cached total is an optimization for diagnostics only. `validate`
/// independently recomputes it with checked arithmetic before client use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResponseBatch {
    declared_frame_count: usize,
    frames: Vec<HostFrame>,
    total_bytes: usize,
}

impl HostResponseBatch {
    pub fn try_from_frames(
        frames: Vec<HostFrame>,
        limits: HostResponseLimits,
    ) -> Result<Self, HostResponseBudgetError> {
        let mut builder = HostResponseBatchBuilder::new(frames.len(), limits)?;
        for frame in frames {
            builder.push(frame)?;
        }
        builder.finish()
    }

    pub fn validate(&self, limits: HostResponseLimits) -> Result<(), HostResponseBudgetError> {
        limits.validate()?;
        if self.declared_frame_count > limits.max_frames {
            return Err(HostResponseBudgetError::DeclaredFrameCountExceeded {
                declared: self.declared_frame_count,
                maximum: limits.max_frames,
            });
        }
        if self.declared_frame_count != self.frames.len() {
            return Err(HostResponseBudgetError::FrameCountMismatch {
                declared: self.declared_frame_count,
                actual: self.frames.len(),
            });
        }
        let mut total_bytes = 0usize;
        for (index, frame) in self.frames.iter().enumerate() {
            let frame_bytes = response_frame_len(frame.header())?;
            if frame_bytes > limits.max_frame_bytes {
                return Err(HostResponseBudgetError::FrameTooLarge {
                    index,
                    actual: frame_bytes,
                    maximum: limits.max_frame_bytes,
                });
            }
            total_bytes = total_bytes
                .checked_add(frame_bytes)
                .ok_or(HostResponseBudgetError::TotalBytesOverflow)?;
            if total_bytes > limits.max_total_bytes {
                return Err(HostResponseBudgetError::TotalBytesExceeded {
                    actual: total_bytes,
                    maximum: limits.max_total_bytes,
                });
            }
        }
        if total_bytes != self.total_bytes {
            return Err(HostResponseBudgetError::RecordedTotalMismatch {
                recorded: self.total_bytes,
                actual: total_bytes,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    #[must_use]
    pub fn as_slice(&self) -> &[HostFrame] {
        &self.frames
    }

    #[must_use]
    pub fn into_frames(self) -> Vec<HostFrame> {
        self.frames
    }
}

/// Proof that one decoded header fits the remaining batch allocation budget.
///
/// Pipe transports obtain this before reading `raw_len` bytes, then consume it
/// with [`HostResponseBatchBuilder::push_preflighted`].
#[derive(Debug, PartialEq, Eq)]
pub struct HostResponseFramePermit {
    index: usize,
    frame_bytes: usize,
    total_after: usize,
}

impl HostResponseFramePermit {
    #[must_use]
    pub const fn frame_bytes(&self) -> usize {
        self.frame_bytes
    }
}

/// Incremental bounded response receiver for future pipe transports.
pub struct HostResponseBatchBuilder {
    limits: HostResponseLimits,
    declared_frame_count: usize,
    frames: Vec<HostFrame>,
    total_bytes: usize,
}

impl HostResponseBatchBuilder {
    pub fn new(
        declared_frame_count: usize,
        limits: HostResponseLimits,
    ) -> Result<Self, HostResponseBudgetError> {
        limits.validate()?;
        if declared_frame_count > limits.max_frames {
            return Err(HostResponseBudgetError::DeclaredFrameCountExceeded {
                declared: declared_frame_count,
                maximum: limits.max_frames,
            });
        }
        Ok(Self {
            limits,
            declared_frame_count,
            frames: Vec::with_capacity(declared_frame_count),
            total_bytes: 0,
        })
    }

    /// Validates a decoded header before its raw payload is allocated or read.
    pub fn preflight_frame(
        &self,
        header: &FrameHeader,
    ) -> Result<HostResponseFramePermit, HostResponseBudgetError> {
        let index = self.frames.len();
        if index >= self.declared_frame_count {
            return Err(HostResponseBudgetError::FrameCountMismatch {
                declared: self.declared_frame_count,
                actual: index.saturating_add(1),
            });
        }
        let frame_bytes = response_frame_len(header)?;
        if frame_bytes > self.limits.max_frame_bytes {
            return Err(HostResponseBudgetError::FrameTooLarge {
                index,
                actual: frame_bytes,
                maximum: self.limits.max_frame_bytes,
            });
        }
        let total_after = self
            .total_bytes
            .checked_add(frame_bytes)
            .ok_or(HostResponseBudgetError::TotalBytesOverflow)?;
        if total_after > self.limits.max_total_bytes {
            return Err(HostResponseBudgetError::TotalBytesExceeded {
                actual: total_after,
                maximum: self.limits.max_total_bytes,
            });
        }
        Ok(HostResponseFramePermit {
            index,
            frame_bytes,
            total_after,
        })
    }

    pub fn push(&mut self, frame: HostFrame) -> Result<(), HostResponseBudgetError> {
        let permit = self.preflight_frame(frame.header())?;
        self.push_preflighted(permit, frame)
    }

    pub fn push_preflighted(
        &mut self,
        permit: HostResponseFramePermit,
        frame: HostFrame,
    ) -> Result<(), HostResponseBudgetError> {
        // Re-run the receiver's preflight rather than trusting a permit merely
        // because its private fields match the current index. This keeps a
        // permit minted by a more permissive builder from bypassing this
        // builder's per-frame or cumulative limits.
        let expected = self.preflight_frame(frame.header())?;
        if permit != expected {
            return Err(HostResponseBudgetError::StaleFramePermit);
        }
        self.frames.push(frame);
        self.total_bytes = expected.total_after;
        Ok(())
    }

    pub fn finish(self) -> Result<HostResponseBatch, HostResponseBudgetError> {
        if self.frames.len() != self.declared_frame_count {
            return Err(HostResponseBudgetError::FrameCountMismatch {
                declared: self.declared_frame_count,
                actual: self.frames.len(),
            });
        }
        let limits = self.limits;
        let batch = HostResponseBatch {
            declared_frame_count: self.declared_frame_count,
            frames: self.frames,
            total_bytes: self.total_bytes,
        };
        // Preserve the private batch invariant even if this builder is later
        // extended with another insertion path.
        batch.validate(limits)?;
        Ok(batch)
    }
}

fn response_frame_len(header: &FrameHeader) -> Result<usize, HostResponseBudgetError> {
    header
        .frame_len()
        .map_err(|_| HostResponseBudgetError::InvalidFrameLength)
}

#[cfg(test)]
mod tests {
    use crate::host_codec::HostFrame;
    use crate::host_wire::{ControlBody, FrameHeader, FrameSequence, MessageKind};

    use super::*;

    fn response_frame(raw_bytes: usize) -> HostFrame {
        let raw_len = u32::try_from(raw_bytes).expect("test payload length fits u32");
        HostFrame::new(
            FrameHeader::new(
                FrameSequence::new(2).expect("nonzero sequence"),
                MessageKind::Event,
                raw_len,
                None,
                ControlBody::Bytes(vec![0]),
            )
            .expect("valid test frame header"),
            vec![0; raw_bytes],
        )
        .expect("valid test frame")
    }

    #[test]
    fn permit_from_permissive_builder_cannot_bypass_receiver_frame_limit() {
        let frame = response_frame(64);
        let frame_bytes = response_frame_len(frame.header()).expect("encoded frame length");
        let permissive_limits =
            HostResponseLimits::new(1, frame_bytes, frame_bytes).expect("permissive limits");
        let strict_limits =
            HostResponseLimits::new(1, frame_bytes - 1, frame_bytes).expect("strict frame limits");
        let permissive =
            HostResponseBatchBuilder::new(1, permissive_limits).expect("permissive builder");
        let permit = permissive
            .preflight_frame(frame.header())
            .expect("permissive permit");
        let mut strict = HostResponseBatchBuilder::new(1, strict_limits).expect("strict builder");

        assert_eq!(
            strict.push_preflighted(permit, frame),
            Err(HostResponseBudgetError::FrameTooLarge {
                index: 0,
                actual: frame_bytes,
                maximum: frame_bytes - 1,
            })
        );
    }

    #[test]
    fn permit_from_permissive_builder_cannot_bypass_receiver_total_limit() {
        let first = response_frame(32);
        let second = response_frame(32);
        let frame_bytes = response_frame_len(first.header()).expect("encoded frame length");
        let strict_total = frame_bytes * 2 - 1;
        let strict_limits = HostResponseLimits::new(2, frame_bytes, strict_total)
            .expect("strict cumulative limits");
        let permissive_limits = HostResponseLimits::new(2, frame_bytes, frame_bytes * 2)
            .expect("permissive cumulative limits");
        let mut strict = HostResponseBatchBuilder::new(2, strict_limits).expect("strict builder");
        strict.push(first.clone()).expect("first strict frame");
        let mut permissive =
            HostResponseBatchBuilder::new(2, permissive_limits).expect("permissive builder");
        permissive.push(first).expect("first permissive frame");
        let permit = permissive
            .preflight_frame(second.header())
            .expect("permissive second permit");

        assert_eq!(
            strict.push_preflighted(permit, second),
            Err(HostResponseBudgetError::TotalBytesExceeded {
                actual: frame_bytes * 2,
                maximum: strict_total,
            })
        );
    }

    #[test]
    fn finish_revalidates_private_batch_invariants() {
        let frame = response_frame(16);
        let frame_bytes = response_frame_len(frame.header()).expect("encoded frame length");
        let limits = HostResponseLimits::new(1, frame_bytes, frame_bytes).expect("limits");
        let mut builder = HostResponseBatchBuilder::new(1, limits).expect("builder");
        builder.push(frame).expect("frame fits limits");
        builder.total_bytes += 1;

        assert_eq!(
            builder.finish(),
            Err(HostResponseBudgetError::RecordedTotalMismatch {
                recorded: frame_bytes + 1,
                actual: frame_bytes,
            })
        );
    }
}
