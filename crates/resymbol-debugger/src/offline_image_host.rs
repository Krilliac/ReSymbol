//! Production, strictly non-executing access to one preverified image snapshot.
//!
//! This transport never opens a process, creates a sandbox, or rereads target
//! bytes after construction. It exists to exercise the real host protocol for
//! exact, file-backed static-image reads while keeping every execution-capable
//! command unavailable.

use std::{
    fmt,
    fs::{self, File, Metadata},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use resymbol_analysis::{AnalysisError, BinaryAnalysis, analyze_bytes};
use resymbol_core::{BinaryId, BinaryIdentity};
use thiserror::Error;

use crate::address_space::{
    RelativeAddress, StaticAddressSpace, StaticAddressSpaceError, StaticRegion, StaticRegionKind,
};
use crate::host_client::{ControlShutdownReason, HostFrameExchange, HostTransportError};
use crate::host_codec::{HostFrame, decode_command_frame, encode_event_frame};
use crate::host_response::{HostResponseBatch, HostResponseLimits};
use crate::host_wire::{
    BuildClaimHandshake, EndpointRole, FrameSequence, HandshakeError, HandshakeState,
};
use crate::identity::ProvisioningEpoch;
use crate::protocol::{
    CapabilityAvailability, CapabilityReport, CapabilityStatus, CapabilityUnavailableCode,
    CommandEnvelope, CommandId, CommandOutcome, DebugCapability, DebugCommand, DebugEvent,
    DebugTargetRequest, EventEnvelope, EventSequence, MAX_MEMORY_READ_BYTES, MemoryAddress,
    OfflineTarget, ProtocolVersion, ReadViewToken, SessionId, SessionStateKind,
};
use crate::sandbox::HelperBuildId;
use crate::session_machine::{RemoteCommandCheckpoint, SessionMachine, SessionMachineError};

/// Maximum immutable image snapshot accepted by the offline host (1 GiB).
///
/// This matches the application's default binary-ingestion ceiling and is
/// checked against file metadata before allocating a file-backed snapshot.
pub const MAX_OFFLINE_IMAGE_BYTES: u64 = 1024 * 1024 * 1024;

/// An immutable, identity-checked snapshot used by [`OfflineImageDebugHost`].
///
/// `origin_path` is canonicalized exactly once during construction. `bytes`
/// are retained in an [`Arc`] and are never refreshed from disk, so later file
/// replacement cannot change the image served by an established host.
#[derive(Clone)]
pub struct VerifiedOfflineImage {
    origin_path: PathBuf,
    identity: BinaryIdentity,
    bytes: Arc<[u8]>,
    analysis: BinaryAnalysis,
    address_space: StaticAddressSpace,
}

impl fmt::Debug for VerifiedOfflineImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedOfflineImage")
            .field("origin_path", &self.origin_path)
            .field("identity", &self.identity)
            .field("snapshot_len", &self.bytes.len())
            .field("region_count", &self.address_space.regions().len())
            .finish_non_exhaustive()
    }
}

impl VerifiedOfflineImage {
    /// Reads and freezes one image from its canonical filesystem location.
    pub fn from_path(
        origin_path: impl AsRef<Path>,
        expected_identity: BinaryIdentity,
    ) -> Result<Self, VerifiedOfflineImageError> {
        let canonical = canonical_image_path(origin_path.as_ref())?;
        let mut file =
            File::open(&canonical).map_err(|source| VerifiedOfflineImageError::Read {
                path: canonical.clone(),
                source,
            })?;
        let before = file
            .metadata()
            .map_err(|source| VerifiedOfflineImageError::Metadata {
                path: canonical.clone(),
                source,
            })?;
        let before = FileSnapshotMetadata::from_metadata(&before);
        validate_snapshot_size(before.len)?;
        let bytes = read_exact_snapshot(&mut file, before.len, &canonical)?;
        let after = file
            .metadata()
            .map_err(|source| VerifiedOfflineImageError::Metadata {
                path: canonical.clone(),
                source,
            })?;
        let after = FileSnapshotMetadata::from_metadata(&after);
        require_stable_metadata(&canonical, &before, &after)?;
        let path_after = fs::symlink_metadata(&canonical).map_err(|source| {
            VerifiedOfflineImageError::Metadata {
                path: canonical.clone(),
                source,
            }
        })?;
        if path_after.file_type().is_symlink() || !path_after.is_file() {
            return Err(VerifiedOfflineImageError::FileTypeChangedDuringRead { path: canonical });
        }
        let path_after = FileSnapshotMetadata::from_metadata(&path_after);
        require_stable_metadata(&canonical, &after, &path_after)?;
        Self::from_canonical_snapshot(canonical, expected_identity, Arc::from(bytes))
    }

    /// Freezes caller-supplied bytes and binds them to a canonical origin.
    ///
    /// The origin must exist as a regular file at construction time, but its
    /// current contents are not trusted. The supplied snapshot is independently
    /// hashed, analyzed, and compared with every field of `expected_identity`.
    pub fn from_snapshot(
        origin_path: impl AsRef<Path>,
        expected_identity: BinaryIdentity,
        bytes: Arc<[u8]>,
    ) -> Result<Self, VerifiedOfflineImageError> {
        let actual_size = u64::try_from(bytes.len()).map_err(|_| {
            VerifiedOfflineImageError::SnapshotSizeOverflow {
                actual: bytes.len(),
            }
        })?;
        validate_snapshot_size(actual_size)?;
        let canonical = canonical_image_path(origin_path.as_ref())?;
        Self::from_canonical_snapshot(canonical, expected_identity, bytes)
    }

    fn from_canonical_snapshot(
        origin_path: PathBuf,
        expected_identity: BinaryIdentity,
        bytes: Arc<[u8]>,
    ) -> Result<Self, VerifiedOfflineImageError> {
        let actual_size = u64::try_from(bytes.len()).map_err(|_| {
            VerifiedOfflineImageError::SnapshotSizeOverflow {
                actual: bytes.len(),
            }
        })?;
        validate_snapshot_size(actual_size)?;
        if actual_size != expected_identity.size {
            return Err(VerifiedOfflineImageError::SizeMismatch {
                expected: expected_identity.size,
                actual: actual_size,
            });
        }

        let actual_id = BinaryId::digest(bytes.as_ref());
        if actual_id != expected_identity.id {
            return Err(VerifiedOfflineImageError::IdentityDigestMismatch {
                expected: expected_identity.id,
                actual: actual_id,
            });
        }

        let analysis = analyze_bytes(bytes.as_ref())?;
        if analysis.identity() != &expected_identity {
            return Err(VerifiedOfflineImageError::FullIdentityMismatch {
                expected: Box::new(expected_identity),
                actual: Box::new(analysis.identity().clone()),
            });
        }
        let address_space = StaticAddressSpace::from_analysis(&analysis)?;

        Ok(Self {
            origin_path,
            identity: expected_identity,
            bytes,
            analysis,
            address_space,
        })
    }

    #[must_use]
    pub fn origin_path(&self) -> &Path {
        &self.origin_path
    }

    #[must_use]
    pub const fn identity(&self) -> &BinaryIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn analysis(&self) -> &BinaryAnalysis {
        &self.analysis
    }

    #[must_use]
    pub const fn address_space(&self) -> &StaticAddressSpace {
        &self.address_space
    }

    #[must_use]
    pub fn snapshot_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Produces the only target descriptor accepted by a host owning this image.
    #[must_use]
    pub fn target(&self) -> OfflineTarget {
        OfflineTarget {
            path: self.origin_path.clone(),
        }
    }

    /// Reads exact initialized image bytes using an image-relative address.
    ///
    /// For this API and [`OfflineImageDebugHost`], [`MemoryAddress`] is always
    /// an RVA, never a preferred virtual address or a raw file offset. A read
    /// must remain within one canonical header/section region and within that
    /// region's exact file-backed prefix. Image gaps, zero-fill, loader padding,
    /// raw alignment bytes beyond `VirtualSize`, and cross-boundary spans are
    /// rejected rather than synthesized.
    pub fn read_rva(
        &self,
        address: MemoryAddress,
        size: u32,
    ) -> Result<Vec<u8>, OfflineImageReadError> {
        if size == 0 {
            return Err(OfflineImageReadError::EmptyRead);
        }
        if size > MAX_MEMORY_READ_BYTES {
            return Err(OfflineImageReadError::ReadTooLarge {
                actual: size,
                maximum: MAX_MEMORY_READ_BYTES,
            });
        }

        let start = address.get();
        let size = u64::from(size);
        let end = start
            .checked_add(size)
            .ok_or(OfflineImageReadError::AddressOverflow { start, size })?;
        if start >= self.address_space.image_size || end > self.address_space.image_size {
            return Err(OfflineImageReadError::OutsideImage {
                start,
                end,
                image_size: self.address_space.image_size,
            });
        }

        let relative = RelativeAddress::new(start);
        let region = self
            .address_space
            .region_at(relative)
            .ok_or(OfflineImageReadError::ImageGap { start, end })?;
        if end > region.range.end() {
            return Err(OfflineImageReadError::CrossesRegion {
                start,
                end,
                region_end: region.range.end(),
            });
        }
        if matches!(&region.kind, StaticRegionKind::ImageGap) {
            return Err(OfflineImageReadError::ImageGap { start, end });
        }

        let delta = start - region.range.start().get();
        let Some(backing) = region.file_backing else {
            return Err(self.unbacked_error(region, delta, start, end));
        };
        let backing_end = delta
            .checked_add(size)
            .ok_or(OfflineImageReadError::AddressOverflow { start, size })?;
        if delta >= backing.size {
            return Err(self.unbacked_error(region, delta, start, end));
        }
        if backing_end > backing.size {
            return Err(OfflineImageReadError::CrossesFileBacking {
                start,
                end,
                backed_end: region.range.start().get() + backing.size,
            });
        }

        let file_start =
            backing
                .offset
                .checked_add(delta)
                .ok_or(OfflineImageReadError::FileRangeOverflow {
                    offset: backing.offset,
                    size: delta,
                })?;
        let file_end =
            file_start
                .checked_add(size)
                .ok_or(OfflineImageReadError::FileRangeOverflow {
                    offset: file_start,
                    size,
                })?;
        let file_start_u64 = file_start;
        let file_start = usize::try_from(file_start_u64).map_err(|_| {
            OfflineImageReadError::FileRangeNotRepresentable {
                offset: file_start_u64,
                size,
            }
        })?;
        let file_end = usize::try_from(file_end).map_err(|_| {
            OfflineImageReadError::FileRangeNotRepresentable {
                offset: file_start_u64,
                size,
            }
        })?;
        let bytes = self.bytes.get(file_start..file_end).ok_or(
            OfflineImageReadError::FileRangeOutsideSnapshot {
                offset: file_start,
                size: usize::try_from(size).unwrap_or(usize::MAX),
                snapshot_size: self.bytes.len(),
            },
        )?;
        Ok(bytes.to_vec())
    }

    fn unbacked_error(
        &self,
        region: &StaticRegion,
        delta: u64,
        start: u64,
        end: u64,
    ) -> OfflineImageReadError {
        match &region.kind {
            StaticRegionKind::Headers => OfflineImageReadError::LoaderPadding { start, end },
            StaticRegionKind::ImageGap => OfflineImageReadError::ImageGap { start, end },
            StaticRegionKind::Section {
                table_index,
                loaded_size,
                ..
            } => {
                if delta < *loaded_size {
                    OfflineImageReadError::ZeroFill { start, end }
                } else if self
                    .section_raw_size(*table_index)
                    .is_some_and(|raw_size| delta < raw_size)
                {
                    OfflineImageReadError::RawBytesOutsideVirtualSize { start, end }
                } else {
                    OfflineImageReadError::LoaderPadding { start, end }
                }
            }
            StaticRegionKind::LoadSegment { loaded_size, .. } => {
                if delta < *loaded_size {
                    OfflineImageReadError::ZeroFill { start, end }
                } else {
                    OfflineImageReadError::LoaderPadding { start, end }
                }
            }
        }
    }

    fn section_raw_size(&self, table_index: u32) -> Option<u64> {
        let analysis = match &self.analysis {
            BinaryAnalysis::Pe(analysis) => analysis,
            _ => return None,
        };
        let index = usize::try_from(table_index).ok()?;
        analysis
            .sections
            .get(index)
            .map(|section| u64::from(section.raw_data_size))
    }
}

fn canonical_image_path(path: &Path) -> Result<PathBuf, VerifiedOfflineImageError> {
    let original_metadata =
        fs::symlink_metadata(path).map_err(|source| VerifiedOfflineImageError::Metadata {
            path: path.to_path_buf(),
            source,
        })?;
    if original_metadata.file_type().is_symlink() {
        return Err(VerifiedOfflineImageError::SymlinkNotAllowed {
            path: path.to_path_buf(),
        });
    }
    let canonical =
        fs::canonicalize(path).map_err(|source| VerifiedOfflineImageError::Canonicalize {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata =
        fs::metadata(&canonical).map_err(|source| VerifiedOfflineImageError::Metadata {
            path: canonical.clone(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(VerifiedOfflineImageError::NotRegularFile { path: canonical });
    }
    Ok(canonical)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshotMetadata {
    len: u64,
    modified: Option<SystemTime>,
}

impl FileSnapshotMetadata {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }
}

fn validate_snapshot_size(size: u64) -> Result<(), VerifiedOfflineImageError> {
    if size > MAX_OFFLINE_IMAGE_BYTES {
        Err(VerifiedOfflineImageError::ImageTooLarge {
            actual: size,
            maximum: MAX_OFFLINE_IMAGE_BYTES,
        })
    } else {
        Ok(())
    }
}

fn read_exact_snapshot(
    reader: &mut impl Read,
    declared_size: u64,
    path: &Path,
) -> Result<Vec<u8>, VerifiedOfflineImageError> {
    validate_snapshot_size(declared_size)?;
    let capacity = usize::try_from(declared_size).map_err(|_| {
        VerifiedOfflineImageError::DeclaredSizeNotRepresentable {
            actual: declared_size,
        }
    })?;
    let read_limit = declared_size.checked_add(1).ok_or(
        VerifiedOfflineImageError::DeclaredSizeNotRepresentable {
            actual: declared_size,
        },
    )?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| {
        VerifiedOfflineImageError::SnapshotAllocationFailed {
            requested: declared_size,
        }
    })?;
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| VerifiedOfflineImageError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    let actual = u64::try_from(bytes.len()).map_err(|_| {
        VerifiedOfflineImageError::SnapshotSizeOverflow {
            actual: bytes.len(),
        }
    })?;
    if actual != declared_size {
        return Err(VerifiedOfflineImageError::FileChangedDuringRead {
            path: path.to_path_buf(),
            declared: declared_size,
            actual,
        });
    }
    Ok(bytes)
}

fn require_stable_metadata(
    path: &Path,
    before: &FileSnapshotMetadata,
    after: &FileSnapshotMetadata,
) -> Result<(), VerifiedOfflineImageError> {
    if before == after {
        Ok(())
    } else {
        Err(VerifiedOfflineImageError::FileMetadataChanged {
            path: path.to_path_buf(),
            before_len: before.len,
            after_len: after.len,
        })
    }
}

#[derive(Debug, Error)]
pub enum VerifiedOfflineImageError {
    #[error("could not canonicalize offline image path {path:?}: {source}")]
    Canonicalize { path: PathBuf, source: io::Error },
    #[error("could not inspect offline image path {path:?}: {source}")]
    Metadata { path: PathBuf, source: io::Error },
    #[error("offline image path is not a regular file: {path:?}")]
    NotRegularFile { path: PathBuf },
    #[error("offline image path must not be a symbolic link: {path:?}")]
    SymlinkNotAllowed { path: PathBuf },
    #[error("could not read offline image {path:?}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("offline snapshot length {actual} cannot be represented")]
    SnapshotSizeOverflow { actual: usize },
    #[error("offline image size {actual} exceeds maximum {maximum}")]
    ImageTooLarge { actual: u64, maximum: u64 },
    #[error("offline image declared size {actual} is not representable on this host")]
    DeclaredSizeNotRepresentable { actual: u64 },
    #[error("could not reserve {requested} bytes for the offline image snapshot")]
    SnapshotAllocationFailed { requested: u64 },
    #[error(
        "offline image {path:?} changed while being read: declared {declared} bytes, received {actual}"
    )]
    FileChangedDuringRead {
        path: PathBuf,
        declared: u64,
        actual: u64,
    },
    #[error(
        "offline image {path:?} metadata changed while being read: length {before_len} became {after_len}"
    )]
    FileMetadataChanged {
        path: PathBuf,
        before_len: u64,
        after_len: u64,
    },
    #[error("offline image path changed file type while being read: {path:?}")]
    FileTypeChangedDuringRead { path: PathBuf },
    #[error("offline snapshot size mismatch: expected {expected}, received {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("offline snapshot digest mismatch: expected {expected}, received {actual}")]
    IdentityDigestMismatch {
        expected: BinaryId,
        actual: BinaryId,
    },
    #[error("offline snapshot metadata identity differs from the expected full identity")]
    FullIdentityMismatch {
        expected: Box<BinaryIdentity>,
        actual: Box<BinaryIdentity>,
    },
    #[error(transparent)]
    Analysis(#[from] AnalysisError),
    #[error(transparent)]
    StaticAddressSpace(#[from] StaticAddressSpaceError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OfflineImageReadError {
    #[error("offline memory reads must contain at least one byte")]
    EmptyRead,
    #[error("offline memory read size {actual} exceeds protocol maximum {maximum}")]
    ReadTooLarge { actual: u32, maximum: u32 },
    #[error("offline RVA range {start:#x}+{size:#x} overflows")]
    AddressOverflow { start: u64, size: u64 },
    #[error("offline RVA range {start:#x}..{end:#x} exceeds image size {image_size:#x}")]
    OutsideImage {
        start: u64,
        end: u64,
        image_size: u64,
    },
    #[error("offline RVA range {start:#x}..{end:#x} crosses canonical region end {region_end:#x}")]
    CrossesRegion {
        start: u64,
        end: u64,
        region_end: u64,
    },
    #[error("offline RVA range {start:#x}..{end:#x} lies in an image gap")]
    ImageGap { start: u64, end: u64 },
    #[error("offline RVA range {start:#x}..{end:#x} lies in mapped zero-fill")]
    ZeroFill { start: u64, end: u64 },
    #[error("offline RVA range {start:#x}..{end:#x} lies in loader-rounded padding")]
    LoaderPadding { start: u64, end: u64 },
    #[error(
        "offline RVA range {start:#x}..{end:#x} corresponds only to raw alignment bytes beyond VirtualSize"
    )]
    RawBytesOutsideVirtualSize { start: u64, end: u64 },
    #[error(
        "offline RVA range {start:#x}..{end:#x} crosses file-backed prefix end {backed_end:#x}"
    )]
    CrossesFileBacking {
        start: u64,
        end: u64,
        backed_end: u64,
    },
    #[error("offline file range {offset:#x}+{size:#x} overflows")]
    FileRangeOverflow { offset: u64, size: u64 },
    #[error("offline file range {offset:#x}+{size:#x} is not representable on this host")]
    FileRangeNotRepresentable { offset: u64, size: u64 },
    #[error("offline file range {offset:#x}+{size:#x} exceeds snapshot size {snapshot_size:#x}")]
    FileRangeOutsideSnapshot {
        offset: usize,
        size: usize,
        snapshot_size: usize,
    },
}

/// An in-process, immutable host for one exact offline image.
///
/// This host advertises only [`DebugCapability::OfflineAnalysis`]. It supports
/// capability probing, an exact canonical [`DebugTargetRequest::Offline`]
/// open, bounded file-backed RVA reads, and close. Every other command is
/// rejected without attestation, cleanup, mutation, or target-operation
/// evidence.
pub struct OfflineImageDebugHost {
    image: VerifiedOfflineImage,
    handshake: BuildClaimHandshake,
    provisioning_epoch: ProvisioningEpoch,
    helper_build: HelperBuildId,
    machine: Option<SessionMachine>,
    last_command_id: Option<CommandId>,
    next_command_frame_sequence: u64,
    next_frame_sequence: u64,
    next_event_sequence: u64,
    disconnected: bool,
    shutdown_reason: Option<ControlShutdownReason>,
    #[cfg(test)]
    drop_observer: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl OfflineImageDebugHost {
    pub fn new(
        image: VerifiedOfflineImage,
        host_build: impl Into<String>,
        expected_controller_build: impl Into<String>,
        provisioning_epoch: ProvisioningEpoch,
        helper_build: HelperBuildId,
    ) -> Result<Self, HandshakeError> {
        Ok(Self {
            image,
            handshake: BuildClaimHandshake::responder(
                EndpointRole::Host,
                host_build,
                expected_controller_build,
            )?,
            provisioning_epoch,
            helper_build,
            machine: None,
            last_command_id: None,
            next_command_frame_sequence: 1,
            next_frame_sequence: 2,
            next_event_sequence: 1,
            disconnected: false,
            shutdown_reason: None,
            #[cfg(test)]
            drop_observer: None,
        })
    }

    #[must_use]
    pub const fn image(&self) -> &VerifiedOfflineImage {
        &self.image
    }

    #[must_use]
    pub const fn is_disconnected(&self) -> bool {
        self.disconnected
    }

    #[must_use]
    pub const fn shutdown_reason(&self) -> Option<ControlShutdownReason> {
        self.shutdown_reason
    }

    fn exchange_inner(&mut self, request: HostFrame) -> Result<Vec<HostFrame>, HostTransportError> {
        if self.disconnected {
            return Err(HostTransportError::Disconnected);
        }
        if request.header().sequence.get() != self.next_command_frame_sequence {
            return Err(HostTransportError::protocol(format!(
                "expected frame sequence {}, received {}",
                self.next_command_frame_sequence,
                request.header().sequence.get()
            )));
        }
        self.next_command_frame_sequence = self
            .next_command_frame_sequence
            .checked_add(1)
            .ok_or_else(|| HostTransportError::protocol("frame sequence overflow"))?;

        if self.handshake.state() != HandshakeState::Established {
            if !request.raw().is_empty() {
                return Err(HostTransportError::protocol(
                    "handshake request carried raw payload",
                ));
            }
            let acknowledgement = self
                .handshake
                .accept(request.header())
                .map_err(|error| HostTransportError::protocol(error.to_string()))?
                .ok_or_else(|| HostTransportError::protocol("unexpected handshake direction"))?;
            return HostFrame::new(acknowledgement, Vec::new())
                .map(|frame| vec![frame])
                .map_err(|error| HostTransportError::protocol(error.to_string()));
        }

        if self.handshake.negotiated_version() != Some(request.header().version) {
            return Err(HostTransportError::protocol(
                "command frame version differs from negotiated handshake version",
            ));
        }
        let envelope = decode_command_frame(&request)
            .map_err(|error| HostTransportError::protocol(error.to_string()))?;
        self.handle_command(envelope)
    }

    fn handle_command(
        &mut self,
        envelope: CommandEnvelope,
    ) -> Result<Vec<HostFrame>, HostTransportError> {
        self.observe_command_id(envelope.command_id)?;
        if matches!(&envelope.command, DebugCommand::ProbeCapabilities) {
            return self.handle_capability_probe(envelope.command_id);
        }

        let session_id = envelope
            .session_id
            .ok_or_else(|| HostTransportError::protocol("session command omitted session id"))?;
        if self.machine.is_none() {
            self.machine = Some(SessionMachine::new(
                session_id,
                self.provisioning_epoch.clone(),
                self.helper_build.clone(),
            ));
        }
        if self
            .machine
            .as_ref()
            .is_some_and(|machine| machine.session_id() != session_id)
        {
            return Err(HostTransportError::protocol(
                "connection already owns a different session",
            ));
        }

        let command_id = envelope.command_id;
        let command = envelope.command.clone();
        match command {
            DebugCommand::Open(DebugTargetRequest::Offline(target)) => {
                self.handle_open(envelope, command_id, target)
            }
            DebugCommand::ReadMemory {
                view,
                address,
                size,
            } => self.handle_read(envelope, command_id, view, address, size),
            DebugCommand::Close { .. } => self.handle_close(envelope, command_id),
            DebugCommand::ProbeCapabilities => unreachable!("handled above"),
            DebugCommand::Open(
                DebugTargetRequest::Launch(_)
                | DebugTargetRequest::Attach(_)
                | DebugTargetRequest::Dump(_),
            )
            | DebugCommand::Continue { .. }
            | DebugCommand::Pause { .. }
            | DebugCommand::Step { .. }
            | DebugCommand::WriteMemory { .. }
            | DebugCommand::SetBreakpoint { .. }
            | DebugCommand::RemoveBreakpoint { .. }
            | DebugCommand::CaptureSnapshot { .. }
            | DebugCommand::Detach { .. }
            | DebugCommand::Terminate { .. } => self.reject_unsupported(envelope, command_id),
        }
    }

    fn handle_open(
        &mut self,
        envelope: CommandEnvelope,
        command_id: CommandId,
        target: OfflineTarget,
    ) -> Result<Vec<HostFrame>, HostTransportError> {
        let checkpoint = match self.begin_remote_command(&envelope) {
            Ok(checkpoint) => checkpoint,
            Err(error) => return self.rejected(command_id, "command-rejected", error),
        };
        if target.path != self.image.origin_path {
            self.reject_remote_command(checkpoint, command_id)?;
            return self.rejected(
                command_id,
                "offline-target-mismatch",
                "offline target did not exactly match the preverified canonical image",
            );
        }

        let mut events = Vec::with_capacity(3);
        let opening = self.machine_ref()?.state().clone();
        self.push_session_event(&mut events, command_id, DebugEvent::StateChanged(opening))?;
        let offline = self
            .machine_mut()?
            .complete_open_offline()
            .map_err(machine_error)?
            .clone();
        self.commit_remote_command(checkpoint, command_id)?;
        self.push_session_event(&mut events, command_id, DebugEvent::StateChanged(offline))?;
        self.push_succeeded(&mut events, command_id)?;
        Ok(events)
    }

    fn handle_read(
        &mut self,
        envelope: CommandEnvelope,
        command_id: CommandId,
        view: ReadViewToken,
        address: MemoryAddress,
        size: u32,
    ) -> Result<Vec<HostFrame>, HostTransportError> {
        let checkpoint = match self.begin_remote_command(&envelope) {
            Ok(checkpoint) => checkpoint,
            Err(error) => return self.rejected(command_id, "command-rejected", error),
        };
        if !matches!(view, ReadViewToken::Offline { .. }) {
            self.reject_remote_command(checkpoint, command_id)?;
            return self.rejected(
                command_id,
                "offline-view-required",
                "offline image reads require an exact offline state token",
            );
        }
        let bytes = match self.image.read_rva(address, size) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.reject_remote_command(checkpoint, command_id)?;
                return self.rejected(command_id, "offline-range-unavailable", error);
            }
        };
        self.commit_remote_command(checkpoint, command_id)?;

        let mut events = Vec::with_capacity(2);
        self.push_session_event(
            &mut events,
            command_id,
            DebugEvent::MemoryRead {
                view,
                address,
                bytes,
            },
        )?;
        self.push_succeeded(&mut events, command_id)?;
        Ok(events)
    }

    fn handle_close(
        &mut self,
        envelope: CommandEnvelope,
        command_id: CommandId,
    ) -> Result<Vec<HostFrame>, HostTransportError> {
        let checkpoint = match self.begin_remote_command(&envelope) {
            Ok(checkpoint) => checkpoint,
            Err(error) => return self.rejected(command_id, "command-rejected", error),
        };
        let mut events = Vec::with_capacity(3);
        let closing = self.machine_ref()?.state().clone();
        self.push_session_event(&mut events, command_id, DebugEvent::StateChanged(closing))?;
        let closed = self
            .machine_mut()?
            .complete_close(None)
            .map_err(machine_error)?
            .clone();
        self.commit_remote_command(checkpoint, command_id)?;
        self.push_session_event(&mut events, command_id, DebugEvent::StateChanged(closed))?;
        self.push_succeeded(&mut events, command_id)?;
        Ok(events)
    }

    fn reject_unsupported(
        &mut self,
        envelope: CommandEnvelope,
        command_id: CommandId,
    ) -> Result<Vec<HostFrame>, HostTransportError> {
        if let Ok(checkpoint) = self.begin_remote_command(&envelope) {
            self.reject_remote_command(checkpoint, command_id)?;
        }
        self.rejected(
            command_id,
            "offline-command-unsupported",
            "offline image host did not perform this target operation",
        )
    }

    fn begin_remote_command(
        &mut self,
        envelope: &CommandEnvelope,
    ) -> Result<RemoteCommandCheckpoint, String> {
        let machine = self
            .machine
            .as_mut()
            .ok_or_else(|| "no active session reducer".to_owned())?;
        machine
            .begin_remote_command(envelope)
            .map_err(|error| bounded_rejection_message(&error))
    }

    fn reject_remote_command(
        &mut self,
        checkpoint: RemoteCommandCheckpoint,
        command_id: CommandId,
    ) -> Result<(), HostTransportError> {
        self.machine_mut()?
            .reject_remote_command(checkpoint, command_id)
            .map(|_| ())
            .map_err(machine_error)
    }

    fn commit_remote_command(
        &mut self,
        checkpoint: RemoteCommandCheckpoint,
        command_id: CommandId,
    ) -> Result<(), HostTransportError> {
        self.machine_mut()?
            .commit_remote_command(checkpoint, command_id)
            .map(|_| ())
            .map_err(machine_error)
    }

    fn rejected(
        &mut self,
        command_id: CommandId,
        code: &'static str,
        message: impl ToString,
    ) -> Result<Vec<HostFrame>, HostTransportError> {
        let message = bounded_text(message.to_string());
        let mut events = Vec::with_capacity(1);
        self.push_session_event(
            &mut events,
            command_id,
            DebugEvent::CommandResult {
                command_id,
                outcome: CommandOutcome::Rejected {
                    code: code.to_owned(),
                    message,
                },
            },
        )?;
        Ok(events)
    }

    fn handle_capability_probe(
        &mut self,
        command_id: CommandId,
    ) -> Result<Vec<HostFrame>, HostTransportError> {
        let report = CapabilityReport {
            statuses: DebugCapability::ALL
                .into_iter()
                .map(offline_capability_status)
                .collect(),
        };
        let mut events = Vec::with_capacity(2);
        self.push_global_event(&mut events, command_id, DebugEvent::Capabilities(report))?;
        self.push_global_event(
            &mut events,
            command_id,
            DebugEvent::CommandResult {
                command_id,
                outcome: CommandOutcome::Succeeded,
            },
        )?;
        Ok(events)
    }

    fn push_succeeded(
        &mut self,
        events: &mut Vec<HostFrame>,
        command_id: CommandId,
    ) -> Result<(), HostTransportError> {
        self.push_session_event(
            events,
            command_id,
            DebugEvent::CommandResult {
                command_id,
                outcome: CommandOutcome::Succeeded,
            },
        )
    }

    fn push_global_event(
        &mut self,
        frames: &mut Vec<HostFrame>,
        command_id: CommandId,
        event: DebugEvent,
    ) -> Result<(), HostTransportError> {
        let envelope = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: self.next_event_sequence()?,
            session_id: None,
            state: None,
            caused_by: Some(command_id),
            event,
        };
        self.push_encoded_event(frames, envelope)
    }

    fn push_session_event(
        &mut self,
        frames: &mut Vec<HostFrame>,
        command_id: CommandId,
        event: DebugEvent,
    ) -> Result<(), HostTransportError> {
        let machine = self.machine_ref()?;
        let session_id = machine.session_id();
        let state = machine.state().state_token();
        let envelope = EventEnvelope {
            version: ProtocolVersion::current(),
            sequence: self.next_event_sequence()?,
            session_id: Some(session_id),
            state: Some(state),
            caused_by: Some(command_id),
            event,
        };
        self.push_encoded_event(frames, envelope)
    }

    fn next_event_sequence(&mut self) -> Result<EventSequence, HostTransportError> {
        let sequence = EventSequence::new(self.next_event_sequence)
            .map_err(|error| HostTransportError::protocol(error.to_string()))?;
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .ok_or_else(|| HostTransportError::protocol("event sequence overflow"))?;
        Ok(sequence)
    }

    fn push_encoded_event(
        &mut self,
        frames: &mut Vec<HostFrame>,
        envelope: EventEnvelope,
    ) -> Result<(), HostTransportError> {
        let sequence = FrameSequence::new(self.next_frame_sequence)
            .map_err(|error| HostTransportError::protocol(error.to_string()))?;
        let frame = encode_event_frame(sequence, &envelope)
            .map_err(|error| HostTransportError::protocol(error.to_string()))?;
        self.next_frame_sequence = self
            .next_frame_sequence
            .checked_add(1)
            .ok_or_else(|| HostTransportError::protocol("frame sequence overflow"))?;
        frames.push(frame);
        Ok(())
    }

    fn observe_command_id(&mut self, command_id: CommandId) -> Result<(), HostTransportError> {
        if self.last_command_id.is_some_and(|last| command_id <= last) {
            return Err(HostTransportError::protocol(
                "command identifier is not newer than the previous command",
            ));
        }
        self.last_command_id = Some(command_id);
        Ok(())
    }

    fn machine_ref(&self) -> Result<&SessionMachine, HostTransportError> {
        self.machine
            .as_ref()
            .ok_or_else(|| HostTransportError::protocol("no active session reducer"))
    }

    fn machine_mut(&mut self) -> Result<&mut SessionMachine, HostTransportError> {
        self.machine
            .as_mut()
            .ok_or_else(|| HostTransportError::protocol("no active session reducer"))
    }

    #[cfg(test)]
    fn observe_drop(&mut self, observer: Arc<std::sync::atomic::AtomicBool>) {
        self.drop_observer = Some(observer);
    }
}

impl HostFrameExchange for OfflineImageDebugHost {
    fn exchange(
        &mut self,
        request: HostFrame,
        limits: HostResponseLimits,
    ) -> Result<HostResponseBatch, HostTransportError> {
        let frames = match self.exchange_inner(request) {
            Ok(frames) => frames,
            Err(error) => {
                self.abort_control(ControlShutdownReason::ProtocolFailure);
                return Err(error);
            }
        };
        match HostResponseBatch::try_from_frames(frames, limits) {
            Ok(batch) => Ok(batch),
            Err(error) => {
                self.abort_control(ControlShutdownReason::ProtocolFailure);
                Err(error.into())
            }
        }
    }

    fn release_session(&mut self, session_id: SessionId) -> Result<(), HostTransportError> {
        let machine = self.machine_ref()?;
        if machine.session_id() != session_id || machine.state().kind() != SessionStateKind::Closed
        {
            return Err(HostTransportError::protocol(
                "offline session release was not reducer-confirmed",
            ));
        }
        self.machine = None;
        Ok(())
    }

    fn shutdown_control(
        &mut self,
        reason: ControlShutdownReason,
    ) -> Result<(), HostTransportError> {
        if !self.disconnected {
            self.disconnected = true;
            self.shutdown_reason = Some(reason);
        }
        Ok(())
    }

    fn abort_control(&mut self, reason: ControlShutdownReason) {
        if !self.disconnected {
            self.disconnected = true;
            self.shutdown_reason = Some(reason);
        }
    }
}

impl Drop for OfflineImageDebugHost {
    fn drop(&mut self) {
        if !self.disconnected {
            self.abort_control(ControlShutdownReason::ClientDropped);
        }
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

fn machine_error(error: SessionMachineError) -> HostTransportError {
    HostTransportError::protocol(error.to_string())
}

fn offline_capability_status(capability: DebugCapability) -> CapabilityStatus {
    let availability = match capability {
        DebugCapability::OfflineAnalysis => CapabilityAvailability::Available,
        DebugCapability::LiveMemoryWrite
        | DebugCapability::ExecutionControl
        | DebugCapability::StepInto
        | DebugCapability::StepOver
        | DebugCapability::StepOut
        | DebugCapability::RegisterWrite
        | DebugCapability::SoftwareBreakpoints
        | DebugCapability::HardwareBreakpoints => CapabilityAvailability::Unavailable {
            code: CapabilityUnavailableCode::TargetModeReadOnly,
            reason: "verified offline images are immutable and non-executing".to_owned(),
        },
        DebugCapability::DumpRead
        | DebugCapability::SnapshotRead
        | DebugCapability::ObserveProcess
        | DebugCapability::LiveMemoryRead
        | DebugCapability::RegisterRead
        | DebugCapability::SandboxedLaunch
        | DebugCapability::HostLaunch
        | DebugCapability::HostAttach => CapabilityAvailability::Unavailable {
            code: CapabilityUnavailableCode::BackendUnavailable,
            reason: "offline image host has no live, dump, snapshot, or launch backend".to_owned(),
        },
    };
    CapabilityStatus {
        capability,
        availability,
    }
}

fn bounded_rejection_message(error: &SessionMachineError) -> String {
    bounded_text(error.to_string())
}

fn bounded_text(message: String) -> String {
    if message.is_empty()
        || message.len() > crate::protocol::MAX_REASON_BYTES
        || message.chars().any(char::is_control)
    {
        "offline image host rejected the command".to_owned()
    } else {
        message
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        io::Cursor,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    };

    use resymbol_core::BinaryIdentity;

    use super::*;
    use crate::host_client::{CommandReceipt, DebugHostClient};
    use crate::host_codec::decode_event_frame;
    use crate::protocol::{
        AttachMode, AttachScope, AttachTarget, BreakpointId, BreakpointKind, BreakpointScope,
        BreakpointSpec, DumpTarget, ExecutionToken, LaunchEnvironment, LaunchTarget, LiveToken,
        ProcessId, ProcessIdentity, ProcessStartKey, ReadViewToken, RunId, RunToken,
        StateGeneration, StateToken, StepKind, StopId, StopToken, ThreadId,
    };
    use crate::sandbox::{
        ChildProcessProfile, DynamicCodeProfile, IsolationBoundary, ProcessMitigationProfile,
        SandboxGuarantee, SandboxNetworkMode, SandboxPolicy, SandboxPolicyApprovalId,
        SandboxProviderSelection, SandboxResourceLimits, Win32kProfile,
    };
    use crate::{HostRiskLeaseId, SessionState};

    const FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");
    static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

    struct TempImage {
        path: PathBuf,
    }

    impl TempImage {
        fn new(bytes: &[u8]) -> Self {
            let unique = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "resymbol-offline-image-{}-{unique}.exe",
                std::process::id()
            ));
            fs::write(&path, bytes).expect("write temporary image");
            Self { path }
        }
    }

    impl Drop for TempImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe")
    }

    fn fixture_identity() -> BinaryIdentity {
        analyze_bytes(FIXTURE)
            .expect("fixture analysis")
            .identity()
            .clone()
    }

    fn verified_fixture() -> VerifiedOfflineImage {
        VerifiedOfflineImage::from_snapshot(
            fixture_path(),
            fixture_identity(),
            Arc::<[u8]>::from(FIXTURE),
        )
        .expect("verified fixture")
    }

    fn verified_sparse_elf() -> (TempImage, VerifiedOfflineImage) {
        const ELF_HEADER_SIZE: usize = 52;
        const PROGRAM_HEADER_SIZE: usize = 32;
        let mut bytes = vec![0_u8; 0x200];
        bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        put_test_u16(&mut bytes, 16, 2);
        put_test_u16(&mut bytes, 18, 8);
        put_test_u32(&mut bytes, 20, 1);
        put_test_u32(&mut bytes, 24, 0x1200_0040);
        put_test_u32(&mut bytes, 28, ELF_HEADER_SIZE as u32);
        put_test_u16(&mut bytes, 40, ELF_HEADER_SIZE as u16);
        put_test_u16(&mut bytes, 42, PROGRAM_HEADER_SIZE as u16);
        put_test_u16(&mut bytes, 44, 2);
        put_test_program_header(
            &mut bytes,
            ELF_HEADER_SIZE,
            0,
            0x1200_0000,
            0x100,
            0x200,
            5,
            0x1000,
        );
        put_test_program_header(
            &mut bytes,
            ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE,
            0x180,
            0xf000_0180,
            4,
            0x80,
            6,
            0x10,
        );
        bytes[0x180..0x184].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        let expected = analyze_bytes(&bytes)
            .expect("analyze synthetic sparse ELF")
            .identity()
            .clone();
        let temp = TempImage::new(&bytes);
        let image =
            VerifiedOfflineImage::from_snapshot(&temp.path, expected, Arc::<[u8]>::from(bytes))
                .expect("verify synthetic sparse ELF");
        (temp, image)
    }

    fn put_test_program_header(
        bytes: &mut [u8],
        offset: usize,
        file_offset: u32,
        virtual_address: u32,
        file_size: u32,
        memory_size: u32,
        flags: u32,
        alignment: u32,
    ) {
        put_test_u32(bytes, offset, 1);
        put_test_u32(bytes, offset + 4, file_offset);
        put_test_u32(bytes, offset + 8, virtual_address);
        put_test_u32(bytes, offset + 12, virtual_address);
        put_test_u32(bytes, offset + 16, file_size);
        put_test_u32(bytes, offset + 20, memory_size);
        put_test_u32(bytes, offset + 24, flags);
        put_test_u32(bytes, offset + 28, alignment);
    }

    fn put_test_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_test_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn patched_fixture(
        mutate: impl FnOnce(&mut [u8], usize, usize),
    ) -> (TempImage, VerifiedOfflineImage) {
        let mut bytes = FIXTURE.to_vec();
        let pe_offset = usize::try_from(u32::from_le_bytes(
            bytes[0x3c..0x40].try_into().expect("e_lfanew bytes"),
        ))
        .expect("PE offset");
        let optional_size = usize::from(u16::from_le_bytes(
            bytes[pe_offset + 20..pe_offset + 22]
                .try_into()
                .expect("optional-header size"),
        ));
        let section_table = pe_offset + 24 + optional_size;
        mutate(&mut bytes, pe_offset + 24, section_table);
        let expected = analyze_bytes(&bytes)
            .expect("patched fixture analysis")
            .identity()
            .clone();
        let temp = TempImage::new(&bytes);
        let image =
            VerifiedOfflineImage::from_snapshot(&temp.path, expected, Arc::<[u8]>::from(bytes))
                .expect("verified patched fixture");
        (temp, image)
    }

    fn fixture_with_image_gap() -> (TempImage, VerifiedOfflineImage) {
        patched_fixture(|bytes, optional_header, _| {
            bytes[optional_header + 56..optional_header + 60]
                .copy_from_slice(&0x7000_u32.to_le_bytes());
        })
    }

    fn fixture_with_zero_fill() -> (TempImage, VerifiedOfflineImage) {
        patched_fixture(|bytes, _, section_table| {
            let data_section = section_table + 2 * 40;
            bytes[data_section + 8..data_section + 12].copy_from_slice(&0x300_u32.to_le_bytes());
        })
    }

    fn session_id() -> SessionId {
        SessionId::new(41).expect("session id")
    }

    fn state_token() -> StateToken {
        StateToken {
            session_id: session_id(),
            generation: StateGeneration::new(1).expect("generation"),
        }
    }

    fn provisioning_epoch() -> ProvisioningEpoch {
        ProvisioningEpoch::new("7".repeat(64)).expect("provisioning epoch")
    }

    fn helper_build() -> HelperBuildId {
        HelperBuildId::new("offline-host-test-1").expect("helper build")
    }

    fn host(image: VerifiedOfflineImage) -> OfflineImageDebugHost {
        OfflineImageDebugHost::new(
            image,
            "offline-host/build-1",
            "controller/build-1",
            provisioning_epoch(),
            helper_build(),
        )
        .expect("offline host")
    }

    fn client(image: VerifiedOfflineImage) -> DebugHostClient<OfflineImageDebugHost> {
        DebugHostClient::connect(
            host(image),
            [0x51; 16],
            "controller/build-1",
            "offline-host/build-1",
        )
        .expect("connect offline host")
    }

    fn assert_rejected_without_evidence(receipt: &CommandReceipt) {
        assert!(matches!(&receipt.outcome, CommandOutcome::Rejected { .. }));
        assert_eq!(receipt.events.len(), 1);
        assert!(matches!(
            &receipt.events[0].event,
            DebugEvent::CommandResult {
                outcome: CommandOutcome::Rejected { .. },
                ..
            }
        ));
    }

    #[test]
    fn snapshot_constructor_rejects_size_digest_and_full_identity_mismatch() {
        let path = fixture_path();

        let mut expected = fixture_identity();
        expected.size += 1;
        assert!(matches!(
            VerifiedOfflineImage::from_snapshot(&path, expected, Arc::<[u8]>::from(FIXTURE)),
            Err(VerifiedOfflineImageError::SizeMismatch { .. })
        ));

        let mut expected = fixture_identity();
        expected.id = BinaryId::digest(b"different image");
        assert!(matches!(
            VerifiedOfflineImage::from_snapshot(&path, expected, Arc::<[u8]>::from(FIXTURE)),
            Err(VerifiedOfflineImageError::IdentityDigestMismatch { .. })
        ));

        let mut expected = fixture_identity();
        expected.architecture = "forged-architecture".to_owned();
        assert!(matches!(
            VerifiedOfflineImage::from_snapshot(path, expected, Arc::<[u8]>::from(FIXTURE)),
            Err(VerifiedOfflineImageError::FullIdentityMismatch { .. })
        ));
    }

    #[test]
    fn bounded_file_reader_rejects_limits_truncation_growth_and_metadata_change() {
        assert!(matches!(
            validate_snapshot_size(MAX_OFFLINE_IMAGE_BYTES + 1),
            Err(VerifiedOfflineImageError::ImageTooLarge { .. })
        ));

        let path = Path::new("bounded-reader-test");
        let mut short = Cursor::new(vec![1_u8, 2]);
        assert!(matches!(
            read_exact_snapshot(&mut short, 3, path),
            Err(VerifiedOfflineImageError::FileChangedDuringRead {
                declared: 3,
                actual: 2,
                ..
            })
        ));
        let mut grown = Cursor::new(vec![1_u8, 2, 3, 4]);
        assert!(matches!(
            read_exact_snapshot(&mut grown, 3, path),
            Err(VerifiedOfflineImageError::FileChangedDuringRead {
                declared: 3,
                actual: 4,
                ..
            })
        ));

        let before = FileSnapshotMetadata {
            len: 3,
            modified: Some(SystemTime::UNIX_EPOCH),
        };
        let after = FileSnapshotMetadata {
            len: 3,
            modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
        };
        assert!(matches!(
            require_stable_metadata(path, &before, &after),
            Err(VerifiedOfflineImageError::FileMetadataChanged { .. })
        ));
    }

    #[test]
    fn frozen_snapshot_is_immune_to_later_disk_mutation() {
        let temp = TempImage::new(FIXTURE);
        let image = VerifiedOfflineImage::from_path(&temp.path, fixture_identity())
            .expect("freeze temporary image");
        fs::write(&temp.path, vec![0_u8; FIXTURE.len()]).expect("replace disk contents");

        assert_eq!(image.read_rva(MemoryAddress::new(0), 2).unwrap(), b"MZ");
        assert_eq!(image.snapshot_bytes(), FIXTURE);
    }

    #[test]
    fn debug_output_is_bounded_and_omits_snapshot_bytes() {
        let image = verified_fixture();
        let rendered = format!("{image:?}");

        assert!(
            rendered.len() < 2_048,
            "debug output was unexpectedly large"
        );
        assert!(rendered.contains("snapshot_len"));
        assert!(rendered.contains("region_count"));
        assert!(!rendered.contains("bytes: ["));
        assert!(!rendered.contains("analysis:"));
    }

    #[test]
    fn exact_header_and_section_prefix_reads_map_to_snapshot_offsets() {
        let image = verified_fixture();
        assert_eq!(image.read_rva(MemoryAddress::new(0), 2).unwrap(), b"MZ");

        let section = image
            .address_space()
            .regions()
            .iter()
            .find(|region| {
                matches!(&region.kind, StaticRegionKind::Section { .. })
                    && region.file_backing.is_some_and(|backing| backing.size >= 8)
            })
            .expect("file-backed section");
        let backing = section.file_backing.expect("section backing");
        let expected_start = usize::try_from(backing.offset).unwrap();
        assert_eq!(
            image
                .read_rva(MemoryAddress::new(section.range.start().get()), 8)
                .unwrap(),
            &FIXTURE[expected_start..expected_start + 8]
        );
    }

    #[test]
    fn read_rva_rejects_all_non_file_backed_range_classes() {
        let image = verified_fixture();
        let layout = image.address_space();

        assert!(matches!(
            image.read_rva(MemoryAddress::new(0), 0),
            Err(OfflineImageReadError::EmptyRead)
        ));
        assert!(matches!(
            image.read_rva(MemoryAddress::new(0), MAX_MEMORY_READ_BYTES + 1),
            Err(OfflineImageReadError::ReadTooLarge { .. })
        ));
        assert!(matches!(
            image.read_rva(MemoryAddress::new(u64::MAX), 2),
            Err(OfflineImageReadError::AddressOverflow { .. })
        ));
        assert!(matches!(
            image.read_rva(MemoryAddress::new(layout.image_size), 1),
            Err(OfflineImageReadError::OutsideImage { .. })
        ));

        let cross_region = layout
            .regions()
            .iter()
            .find(|region| region.range.end() < layout.image_size)
            .expect("nonfinal region");
        assert!(matches!(
            image.read_rva(MemoryAddress::new(cross_region.range.end() - 1), 2),
            Err(OfflineImageReadError::CrossesRegion { .. })
        ));

        let (_gap_file, gap_image) = fixture_with_image_gap();
        let gap = gap_image
            .address_space()
            .regions()
            .iter()
            .find(|region| matches!(&region.kind, StaticRegionKind::ImageGap))
            .expect("patched image gap");
        assert!(matches!(
            gap_image.read_rva(MemoryAddress::new(gap.range.start().get()), 1),
            Err(OfflineImageReadError::ImageGap { .. })
        ));

        let cross_backing = layout
            .regions()
            .iter()
            .find(|region| {
                region
                    .file_backing
                    .is_some_and(|backing| backing.size != 0 && backing.size < region.range.size())
            })
            .expect("region with an unbacked suffix");
        let backing = cross_backing.file_backing.unwrap();
        let last_backed = cross_backing.range.start().get() + backing.size - 1;
        assert!(matches!(
            image.read_rva(MemoryAddress::new(last_backed), 2),
            Err(OfflineImageReadError::CrossesFileBacking { .. })
        ));

        let (_zero_file, zero_image) = fixture_with_zero_fill();
        let zero_fill = zero_image
            .address_space()
            .regions()
            .iter()
            .find(|region| region.zero_fill_size() != 0)
            .expect("patched zero-fill region");
        let zero_fill_start = zero_fill.range.start().get()
            + zero_fill.file_backing.map_or(0, |backing| backing.size);
        assert!(matches!(
            zero_image.read_rva(MemoryAddress::new(zero_fill_start), 1),
            Err(OfflineImageReadError::ZeroFill { .. })
        ));

        let headers = layout.regions().first().expect("headers");
        let header_backing = headers.file_backing.expect("header backing");
        assert!(matches!(
            image.read_rva(
                MemoryAddress::new(headers.range.start().get() + header_backing.size),
                1
            ),
            Err(OfflineImageReadError::LoaderPadding { .. })
        ));

        let raw_tail = layout
            .regions()
            .iter()
            .find_map(|region| {
                let StaticRegionKind::Section {
                    table_index,
                    loaded_size,
                    ..
                } = &region.kind
                else {
                    return None;
                };
                image
                    .section_raw_size(*table_index)
                    .filter(|raw_size| *raw_size > *loaded_size)
                    .map(|_| region.range.start().get() + *loaded_size)
            })
            .expect("fixture raw alignment tail");
        assert!(matches!(
            image.read_rva(MemoryAddress::new(raw_tail), 1),
            Err(OfflineImageReadError::RawBytesOutsideVirtualSize { .. })
        ));
    }

    #[test]
    fn sparse_elf_reads_only_exact_file_backed_load_prefixes() {
        let (_file, image) = verified_sparse_elf();
        let layout = image.address_space();
        assert_eq!(layout.regions().len(), 2);

        assert_eq!(
            image.read_rva(MemoryAddress::new(0x40), 4).unwrap(),
            &image.snapshot_bytes()[0x40..0x44]
        );
        assert!(matches!(
            image.read_rva(MemoryAddress::new(0x1000), 1),
            Err(OfflineImageReadError::ImageGap { .. })
        ));
        assert!(matches!(
            image.read_rva(MemoryAddress::new(0x100), 1),
            Err(OfflineImageReadError::ZeroFill { .. })
        ));
        assert!(matches!(
            image.read_rva(MemoryAddress::new(0xff), 2),
            Err(OfflineImageReadError::CrossesFileBacking { .. })
        ));
        assert!(matches!(
            image.read_rva(MemoryAddress::new(0x1ff), 2),
            Err(OfflineImageReadError::CrossesRegion { .. })
        ));

        let second = &layout.regions()[1];
        assert_eq!(
            image
                .read_rva(MemoryAddress::new(second.range.start().get()), 4)
                .unwrap(),
            [0x12, 0x34, 0x56, 0x78]
        );
        assert!(matches!(
            image.read_rva(MemoryAddress::new(second.range.start().get() + 4), 1),
            Err(OfflineImageReadError::ZeroFill { .. })
        ));
    }

    #[test]
    fn host_advertises_only_offline_and_completes_read_only_lifecycle() {
        let image = verified_fixture();
        let target = image.target();
        let section = image
            .address_space()
            .regions()
            .iter()
            .find(|region| region.file_backing.is_some_and(|backing| backing.size >= 4))
            .expect("readable region");
        let address = MemoryAddress::new(section.range.start().get());
        let expected = image.read_rva(address, 4).unwrap();
        let mut client = client(image);

        let capabilities = client.probe_capabilities().expect("capabilities");
        assert_eq!(capabilities.statuses.len(), DebugCapability::ALL.len());
        for capability in DebugCapability::ALL {
            let status = capabilities
                .statuses
                .iter()
                .find(|status| status.capability == capability)
                .expect("complete capability report");
            match capability {
                DebugCapability::OfflineAnalysis => {
                    assert_eq!(status.availability, CapabilityAvailability::Available);
                }
                DebugCapability::LiveMemoryWrite
                | DebugCapability::ExecutionControl
                | DebugCapability::StepInto
                | DebugCapability::StepOver
                | DebugCapability::StepOut
                | DebugCapability::RegisterWrite
                | DebugCapability::SoftwareBreakpoints
                | DebugCapability::HardwareBreakpoints => assert!(matches!(
                    status.availability,
                    CapabilityAvailability::Unavailable {
                        code: CapabilityUnavailableCode::TargetModeReadOnly,
                        ..
                    }
                )),
                _ => assert!(matches!(
                    status.availability,
                    CapabilityAvailability::Unavailable {
                        code: CapabilityUnavailableCode::BackendUnavailable,
                        ..
                    }
                )),
            }
        }

        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .expect("begin session");
        let open = client
            .submit(DebugCommand::Open(DebugTargetRequest::Offline(target)))
            .expect("open command");
        assert_eq!(open.outcome, CommandOutcome::Succeeded);
        let SessionState::Offline { token } = client.session_state().unwrap() else {
            panic!("offline state")
        };
        let state = *token;
        let read = client
            .submit(DebugCommand::ReadMemory {
                view: ReadViewToken::Offline { state },
                address,
                size: 4,
            })
            .expect("read command");
        assert_eq!(read.outcome, CommandOutcome::Succeeded);
        assert!(read.events.iter().any(|event| matches!(
            &event.event,
            DebugEvent::MemoryRead { bytes, .. } if bytes == &expected
        )));

        let close_state = client.session_state().unwrap().state_token();
        let close = client
            .submit(DebugCommand::Close { state: close_state })
            .expect("close command");
        assert_eq!(close.outcome, CommandOutcome::Succeeded);
        client.release_closed_session().expect("release session");
        client.disconnect().expect("disconnect");
    }

    #[test]
    fn target_and_range_rejections_restore_state_without_evidence() {
        let (_temp, image) = fixture_with_image_gap();
        let target = image.target();
        let gap = image
            .address_space()
            .regions()
            .iter()
            .find(|region| matches!(&region.kind, StaticRegionKind::ImageGap))
            .expect("fixture gap")
            .range
            .start()
            .get();
        let mut client = client(image);
        client
            .begin_session(session_id(), provisioning_epoch(), helper_build())
            .unwrap();

        let mismatch = client
            .submit(DebugCommand::Open(DebugTargetRequest::Offline(
                OfflineTarget {
                    path: PathBuf::from("not-the-canonical-target.exe"),
                },
            )))
            .expect("well-formed rejection");
        assert_rejected_without_evidence(&mismatch);
        assert!(matches!(
            client.session_state(),
            Some(SessionState::Idle { .. })
        ));

        let dump = client
            .submit(DebugCommand::Open(DebugTargetRequest::Dump(DumpTarget {
                path: PathBuf::from("unsupported.dmp"),
            })))
            .expect("well-formed rejection");
        assert_rejected_without_evidence(&dump);
        assert!(matches!(
            client.session_state(),
            Some(SessionState::Idle { .. })
        ));

        client
            .submit(DebugCommand::Open(DebugTargetRequest::Offline(target)))
            .expect("retry exact open");
        let SessionState::Offline { token } = client.session_state().unwrap() else {
            panic!("offline state")
        };
        let read = client
            .submit(DebugCommand::ReadMemory {
                view: ReadViewToken::Offline { state: *token },
                address: MemoryAddress::new(gap),
                size: 1,
            })
            .expect("well-formed range rejection");
        assert_rejected_without_evidence(&read);
        assert!(matches!(
            client.session_state(),
            Some(SessionState::Offline { .. })
        ));
    }

    #[test]
    fn every_execution_mutation_and_sandbox_command_is_rejected_without_evidence() {
        let image = verified_fixture();
        let binary_id = image.identity().id.clone();
        let mut host = host(image);
        let state = state_token();
        let stop = StopToken {
            state,
            stop_id: StopId::new(1).unwrap(),
        };
        let run = RunToken {
            state,
            run_id: RunId::new(1).unwrap(),
        };
        let risk_lease = HostRiskLeaseId::new("a".repeat(64)).unwrap();
        let process = ProcessIdentity {
            process_id: ProcessId::new(77).unwrap(),
            start_key: ProcessStartKey::new(88).unwrap(),
            binary_id: binary_id.clone(),
        };
        let breakpoint = BreakpointSpec {
            id: BreakpointId::new(1).unwrap(),
            address: MemoryAddress::new(0x1000),
            kind: BreakpointKind::Software,
            scope: BreakpointScope::Process,
        };

        let commands = vec![
            DebugCommand::Open(DebugTargetRequest::Launch(LaunchTarget {
                binary_id: binary_id.clone(),
                executable: PathBuf::from("host-launch.exe"),
                arguments: Vec::new(),
                working_directory: None,
                environment: LaunchEnvironment::Host {
                    risk_lease: risk_lease.clone(),
                },
                stop_before_entry: true,
            })),
            DebugCommand::Open(DebugTargetRequest::Launch(LaunchTarget {
                binary_id: binary_id.clone(),
                executable: PathBuf::from("sandbox-launch.exe"),
                arguments: Vec::new(),
                working_directory: None,
                environment: LaunchEnvironment::Sandboxed {
                    policy: sandbox_policy(),
                },
                stop_before_entry: true,
            })),
            DebugCommand::Open(DebugTargetRequest::Attach(AttachTarget {
                scope: AttachScope::Host {
                    process,
                    risk_lease,
                },
                mode: AttachMode::Debug,
            })),
            DebugCommand::Open(DebugTargetRequest::Dump(DumpTarget {
                path: PathBuf::from("target.dmp"),
            })),
            DebugCommand::Continue { stop },
            DebugCommand::Pause { run },
            DebugCommand::Step {
                stop,
                thread_id: ThreadId::new(1).unwrap(),
                kind: StepKind::Into,
            },
            DebugCommand::WriteMemory {
                stop,
                address: MemoryAddress::new(0x1000),
                expected: vec![0x90],
                replacement: vec![0xcc],
            },
            DebugCommand::SetBreakpoint {
                stop,
                breakpoint,
                persistence: crate::BreakpointPersistence::Persistent,
            },
            DebugCommand::RemoveBreakpoint {
                stop,
                breakpoint_id: BreakpointId::new(1).unwrap(),
            },
            DebugCommand::CaptureSnapshot {
                live: LiveToken::Observing { state },
            },
            DebugCommand::Detach {
                live: LiveToken::Observing { state },
            },
            DebugCommand::Terminate {
                execution: ExecutionToken::Running { run },
            },
        ];

        for (index, command) in commands.into_iter().enumerate() {
            let command_id = CommandId::new(index as u64 + 1).unwrap();
            let envelope = CommandEnvelope {
                version: ProtocolVersion::current(),
                command_id,
                session_id: Some(session_id()),
                expected_state: Some(state),
                command,
            };
            envelope.validate().expect("structurally valid command");
            let frames = host.handle_command(envelope).expect("bounded rejection");
            assert_eq!(frames.len(), 1);
            let event = decode_event_frame(&frames[0]).expect("decode rejection");
            assert!(matches!(
                event.event,
                DebugEvent::CommandResult {
                    outcome: CommandOutcome::Rejected { .. },
                    ..
                }
            ));
        }
        assert!(matches!(
            host.machine_ref().unwrap().state(),
            SessionState::Idle { .. }
        ));
    }

    #[test]
    fn abort_and_drop_are_non_panicking_terminal_control_operations() {
        let mut aborted = host(verified_fixture());
        aborted.abort_control(ControlShutdownReason::ExplicitAbandon);
        assert!(aborted.is_disconnected());
        assert_eq!(
            aborted.shutdown_reason(),
            Some(ControlShutdownReason::ExplicitAbandon)
        );
        aborted.abort_control(ControlShutdownReason::ProtocolFailure);
        assert_eq!(
            aborted.shutdown_reason(),
            Some(ControlShutdownReason::ExplicitAbandon)
        );

        let dropped = Arc::new(AtomicBool::new(false));
        {
            let mut host = host(verified_fixture());
            host.observe_drop(Arc::clone(&dropped));
        }
        assert!(dropped.load(Ordering::SeqCst));
    }

    fn sandbox_policy() -> SandboxPolicy {
        let required_guarantees: BTreeSet<_> = [
            SandboxGuarantee::FileSystemRedirection,
            SandboxGuarantee::RegistryRedirection,
            SandboxGuarantee::RollbackOnClose,
            SandboxGuarantee::NetworkDisabled,
            SandboxGuarantee::ResourceLimits,
            SandboxGuarantee::ChildProcessControl,
            SandboxGuarantee::ProcessMitigations,
            SandboxGuarantee::JobAssignmentAtCreation,
        ]
        .into_iter()
        .collect();
        SandboxPolicy {
            session_id: session_id(),
            policy_approval: SandboxPolicyApprovalId::new(session_id(), "offline-host-test")
                .unwrap(),
            provider: SandboxProviderSelection::LocalAppContainer,
            required_boundary: IsolationBoundary::UserMode,
            required_guarantees,
            network: SandboxNetworkMode::Disabled,
            resources: SandboxResourceLimits {
                memory_bytes: 256 * 1024 * 1024,
                disk_bytes: 1024 * 1024 * 1024,
                active_process_limit: 4,
                cpu_rate_basis_points: 5_000,
                wall_clock_millis: 60_000,
            },
            process_mitigations: ProcessMitigationProfile::StrictV1,
            child_processes: ChildProcessProfile::Deny,
            dynamic_code: DynamicCodeProfile::Prohibit,
            win32k: Win32kProfile::Disable,
            rollback_on_close: true,
            vm_identity: None,
        }
    }
}
