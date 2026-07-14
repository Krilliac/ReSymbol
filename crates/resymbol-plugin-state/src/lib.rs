//! Deterministic plugin artifact fingerprints and host-owned execution policy state.
//!
//! A dropped-in plugin is not trusted merely because its manifest is valid. This crate binds
//! trust and quarantine decisions to both the declared plugin identifier and an exact digest of
//! the plugin directory. State is stored beneath the configured plugin root, outside each plugin
//! artifact directory, so recording a decision does not change the artifact's fingerprint.

#![forbid(unsafe_code)]

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use resymbol_plugin_api::PluginId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const FINGERPRINT_DOMAIN: &[u8] = b"resymbol.plugin-artifact-fingerprint\0v1\0";
const PLUGIN_ID_DOMAIN: &[u8] = b"resymbol.plugin-state-id\0v1\0";
const STATE_DIRECTORY: &str = ".resymbol";
const STATE_VERSION_DIRECTORY: &str = "v1";
const TRUST_DIRECTORY: &str = "trust";
const QUARANTINE_DIRECTORY: &str = "quarantine";
const DISABLED_SENTINEL: &str = "plugin.disabled";
const STATE_SCHEMA_VERSION: u32 = 1;
const MAX_STATE_RECORD_BYTES: u64 = 16 * 1024;
const MAX_QUARANTINE_REASON_BYTES: usize = 4 * 1024;

/// Resource limits applied while traversing and hashing one unpacked plugin directory.
///
/// Limits are evaluated before file contents are read. Callers may choose tighter values for
/// constrained environments. Zero is a valid limit and therefore permits only an empty value for
/// the corresponding resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintLimits {
    /// Maximum number of regular files, excluding a root `plugin.disabled` sentinel.
    pub max_files: u64,
    /// Maximum combined number of included files and directories.
    pub max_entries: u64,
    /// Maximum size of one regular file.
    pub max_file_bytes: u64,
    /// Maximum combined size of all regular files.
    pub max_total_bytes: u64,
    /// Maximum relative component depth. A file immediately below the root has depth one.
    pub max_depth: usize,
}

impl Default for FingerprintLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_entries: 20_000,
            max_file_bytes: 2 * 1024 * 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
            max_depth: 32,
        }
    }
}

/// A SHA-256 digest of the complete accepted plugin directory representation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactFingerprint([u8; 32]);

impl ArtifactFingerprint {
    /// Returns the raw 32-byte SHA-256 value.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the canonical lowercase hexadecimal representation.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Debug for ArtifactFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ArtifactFingerprint")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for ArtifactFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for ArtifactFingerprint {
    type Err = FingerprintParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(FingerprintParseError(value.to_owned()));
        }

        let mut digest = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high =
                decode_hex_digit(pair[0]).ok_or_else(|| FingerprintParseError(value.to_owned()))?;
            let low =
                decode_hex_digit(pair[1]).ok_or_else(|| FingerprintParseError(value.to_owned()))?;
            digest[index] = (high << 4) | low;
        }
        Ok(Self(digest))
    }
}

/// Summary returned with a computed artifact fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintReport {
    pub fingerprint: ArtifactFingerprint,
    pub file_count: u64,
    pub entry_count: u64,
    pub total_bytes: u64,
}

/// Compute a deterministic fingerprint of an unpacked plugin directory.
///
/// The byte stream contains a domain separator followed by globally sorted records. Every record
/// includes a type tag and a length-prefixed, `/`-separated UTF-8 relative path. File records also
/// contain their length and complete contents. Directory records make empty-directory and layout
/// changes visible. Filesystem metadata such as timestamps, ownership, and mode bits is excluded so
/// identical portable plugin contents hash identically on each supported host.
///
/// The only excluded entry is a regular file named `plugin.disabled` immediately beneath `root`.
/// Symlinks, non-UTF-8 names, and non-file/non-directory entries are rejected rather than followed.
pub fn fingerprint_plugin_directory(
    root: impl AsRef<Path>,
    limits: FingerprintLimits,
) -> Result<FingerprintReport, FingerprintError> {
    let root = root.as_ref();
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| fingerprint_io("inspect plugin root", root, source))?;
    if metadata.file_type().is_symlink() {
        return Err(FingerprintError::Symlink {
            path: root.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(FingerprintError::RootNotDirectory {
            path: root.to_path_buf(),
        });
    }

    let mut entries = Vec::new();
    let mut counters = TraversalCounters::default();
    collect_entries(root, "", 0, limits, &mut counters, &mut entries)?;
    entries.sort_by(|left, right| left.relative.as_bytes().cmp(right.relative.as_bytes()));

    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    for entry in &entries {
        hash_entry(&mut hasher, entry)?;
    }

    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(FingerprintReport {
        fingerprint: ArtifactFingerprint(bytes),
        file_count: counters.files,
        entry_count: counters.entries,
        total_bytes: counters.total_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Directory,
    File { size: u64 },
}

impl EntryKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Directory => b'd',
            Self::File { .. } => b'f',
        }
    }
}

#[derive(Debug)]
struct ArtifactEntry {
    path: PathBuf,
    relative: String,
    kind: EntryKind,
}

#[derive(Debug, Default)]
struct TraversalCounters {
    visited_entries: u64,
    files: u64,
    entries: u64,
    total_bytes: u64,
}

fn collect_entries(
    directory: &Path,
    relative_parent: &str,
    parent_depth: usize,
    limits: FingerprintLimits,
    counters: &mut TraversalCounters,
    entries: &mut Vec<ArtifactEntry>,
) -> Result<(), FingerprintError> {
    let reader = fs::read_dir(directory)
        .map_err(|source| fingerprint_io("read plugin directory", directory, source))?;
    let mut children = Vec::new();
    for child in reader {
        let child = child
            .map_err(|source| fingerprint_io("read plugin directory entry", directory, source))?;
        let path = child.path();
        counters.visited_entries = counters.visited_entries.checked_add(1).ok_or_else(|| {
            FingerprintError::LimitExceeded {
                limit: "artifact traversal entry count",
                maximum: limits.max_entries.saturating_add(1),
                observed: u64::MAX,
                path: path.clone(),
            }
        })?;
        // One additional root entry is allowed because the disabled sentinel is deliberately
        // excluded from the artifact entry count. This check bounds the per-directory sort buffer
        // before metadata inspection and hashing begin.
        enforce_limit(
            "artifact traversal entry count",
            counters.visited_entries,
            limits.max_entries.saturating_add(1),
            &path,
        )?;
        let Some(name) = child.file_name().to_str().map(str::to_owned) else {
            return Err(FingerprintError::NonUtf8Path { path });
        };
        children.push((name, path));
    }
    children.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    for (name, path) in children {
        let depth = parent_depth
            .checked_add(1)
            .ok_or_else(|| FingerprintError::LimitExceeded {
                limit: "relative path depth",
                maximum: usize_to_u64(limits.max_depth),
                observed: u64::MAX,
                path: path.clone(),
            })?;
        if depth > limits.max_depth {
            return Err(FingerprintError::LimitExceeded {
                limit: "relative path depth",
                maximum: usize_to_u64(limits.max_depth),
                observed: usize_to_u64(depth),
                path,
            });
        }

        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| fingerprint_io("inspect plugin entry", &path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(FingerprintError::Symlink { path });
        }

        let relative = if relative_parent.is_empty() {
            name.clone()
        } else {
            format!("{relative_parent}/{name}")
        };
        if parent_depth == 0 && name == DISABLED_SENTINEL && metadata.is_file() {
            continue;
        }

        counters.entries =
            counters
                .entries
                .checked_add(1)
                .ok_or_else(|| FingerprintError::LimitExceeded {
                    limit: "artifact entry count",
                    maximum: limits.max_entries,
                    observed: u64::MAX,
                    path: path.clone(),
                })?;
        enforce_limit(
            "artifact entry count",
            counters.entries,
            limits.max_entries,
            &path,
        )?;

        if metadata.is_dir() {
            entries.push(ArtifactEntry {
                path: path.clone(),
                relative: relative.clone(),
                kind: EntryKind::Directory,
            });
            collect_entries(&path, &relative, depth, limits, counters, entries)?;
        } else if metadata.is_file() {
            let size = metadata.len();
            enforce_limit("individual file size", size, limits.max_file_bytes, &path)?;
            counters.files =
                counters
                    .files
                    .checked_add(1)
                    .ok_or_else(|| FingerprintError::LimitExceeded {
                        limit: "regular file count",
                        maximum: limits.max_files,
                        observed: u64::MAX,
                        path: path.clone(),
                    })?;
            enforce_limit(
                "regular file count",
                counters.files,
                limits.max_files,
                &path,
            )?;
            counters.total_bytes = counters.total_bytes.checked_add(size).ok_or_else(|| {
                FingerprintError::LimitExceeded {
                    limit: "total artifact bytes",
                    maximum: limits.max_total_bytes,
                    observed: u64::MAX,
                    path: path.clone(),
                }
            })?;
            enforce_limit(
                "total artifact bytes",
                counters.total_bytes,
                limits.max_total_bytes,
                &path,
            )?;
            entries.push(ArtifactEntry {
                path,
                relative,
                kind: EntryKind::File { size },
            });
        } else {
            return Err(FingerprintError::UnsupportedFileType { path });
        }
    }

    Ok(())
}

fn hash_entry(hasher: &mut Sha256, entry: &ArtifactEntry) -> Result<(), FingerprintError> {
    hasher.update([entry.kind.tag()]);
    hash_length_prefixed(hasher, entry.relative.as_bytes());

    let EntryKind::File { size } = entry.kind else {
        return Ok(());
    };
    hasher.update(size.to_le_bytes());

    let before = fs::symlink_metadata(&entry.path).map_err(|source| {
        fingerprint_io("inspect plugin file before hashing", &entry.path, source)
    })?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() != size {
        return Err(FingerprintError::FileChanged {
            path: entry.path.clone(),
        });
    }

    let mut file = File::open(&entry.path)
        .map_err(|source| fingerprint_io("open plugin file", &entry.path, source))?;
    let opened = file
        .metadata()
        .map_err(|source| fingerprint_io("inspect opened plugin file", &entry.path, source))?;
    if !opened.is_file() || opened.len() != size {
        return Err(FingerprintError::FileChanged {
            path: entry.path.clone(),
        });
    }

    let mut read = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| fingerprint_io("read plugin file", &entry.path, source))?;
        if count == 0 {
            break;
        }
        read =
            read.checked_add(usize_to_u64(count))
                .ok_or_else(|| FingerprintError::FileChanged {
                    path: entry.path.clone(),
                })?;
        if read > size {
            return Err(FingerprintError::FileChanged {
                path: entry.path.clone(),
            });
        }
        hasher.update(&buffer[..count]);
    }
    if read != size {
        return Err(FingerprintError::FileChanged {
            path: entry.path.clone(),
        });
    }

    let after = fs::symlink_metadata(&entry.path).map_err(|source| {
        fingerprint_io("inspect plugin file after hashing", &entry.path, source)
    })?;
    if after.file_type().is_symlink() || !after.is_file() || after.len() != size {
        return Err(FingerprintError::FileChanged {
            path: entry.path.clone(),
        });
    }
    Ok(())
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(usize_to_u64(value.len()).to_le_bytes());
    hasher.update(value);
}

fn enforce_limit(
    limit: &'static str,
    observed: u64,
    maximum: u64,
    path: &Path,
) -> Result<(), FingerprintError> {
    if observed > maximum {
        Err(FingerprintError::LimitExceeded {
            limit,
            maximum,
            observed,
            path: path.to_path_buf(),
        })
    } else {
        Ok(())
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Exact identity to which one trust or quarantine decision applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactStateKey {
    plugin_id: PluginId,
    fingerprint: ArtifactFingerprint,
}

impl ArtifactStateKey {
    #[must_use]
    pub const fn new(plugin_id: PluginId, fingerprint: ArtifactFingerprint) -> Self {
        Self {
            plugin_id,
            fingerprint,
        }
    }

    #[must_use]
    pub const fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    #[must_use]
    pub const fn fingerprint(&self) -> ArtifactFingerprint {
        self.fingerprint
    }
}

/// Effective host policy for an exact plugin artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginArtifactStatus {
    /// No exact trust record exists. The artifact must not be launched.
    ApprovalRequired,
    /// The user explicitly trusted this exact plugin ID and artifact digest.
    Trusted,
    /// The exact artifact was isolated following a validation or runtime fault.
    Quarantined { reason: String },
}

/// Whether a requested state mutation changed durable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateChange {
    Changed,
    Unchanged,
}

/// Trust and quarantine records rooted outside individual plugin directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStateStore {
    plugins_root: PathBuf,
}

impl PluginStateStore {
    /// Address a store beneath `<plugins-root>/.resymbol/`.
    ///
    /// Construction performs no I/O. Every operation verifies that existing state-directory
    /// components are real directories rather than links before accessing a record.
    #[must_use]
    pub fn new(plugins_root: impl Into<PathBuf>) -> Self {
        Self {
            plugins_root: plugins_root.into(),
        }
    }

    #[must_use]
    pub fn plugins_root(&self) -> &Path {
        &self.plugins_root
    }

    #[must_use]
    pub fn state_root(&self) -> PathBuf {
        self.plugins_root.join(STATE_DIRECTORY)
    }

    /// Read the effective state. Corrupt or unsafe exact records return an error so callers fail
    /// closed instead of launching the plugin.
    pub fn status(&self, key: &ArtifactStateKey) -> Result<PluginArtifactStatus, StateError> {
        // Read both records before selecting precedence so a corrupt exact record can never be
        // hidden by another otherwise-valid record.
        let quarantine = self.read_record(RecordKind::Quarantine, key)?;
        let trusted = self.read_record(RecordKind::Trust, key)?;

        if let Some(record) = quarantine {
            return Ok(PluginArtifactStatus::Quarantined {
                reason: record
                    .reason
                    .expect("validated quarantine records contain a reason"),
            });
        }
        if trusted.is_some() {
            Ok(PluginArtifactStatus::Trusted)
        } else {
            Ok(PluginArtifactStatus::ApprovalRequired)
        }
    }

    /// Persist explicit trust for one exact artifact. Existing records are never overwritten.
    pub fn trust(&self, key: &ArtifactStateKey) -> Result<StateChange, StateError> {
        self.create_record(StateRecord::new(RecordKind::Trust, key, None))
    }

    /// Remove trust for one exact artifact. This also permits explicit recovery from a corrupt
    /// exact trust record, because deletion cannot grant execution authority.
    pub fn untrust(&self, key: &ArtifactStateKey) -> Result<StateChange, StateError> {
        self.remove_record(RecordKind::Trust, key)
    }

    /// Quarantine one exact artifact with a bounded, human-readable reason.
    pub fn quarantine(
        &self,
        key: &ArtifactStateKey,
        reason: impl Into<String>,
    ) -> Result<StateChange, StateError> {
        let reason = reason.into();
        validate_quarantine_reason(&reason)?;
        self.create_record(StateRecord::new(RecordKind::Quarantine, key, Some(reason)))
    }

    /// Clear quarantine for one exact artifact without granting trust to a different digest.
    pub fn reset(&self, key: &ArtifactStateKey) -> Result<StateChange, StateError> {
        self.remove_record(RecordKind::Quarantine, key)
    }

    fn create_record(&self, record: StateRecord) -> Result<StateChange, StateError> {
        let key = record.key()?;
        let directory = self.ensure_state_directory(record.kind)?;
        let path = directory.join(record_filename(&key));
        let mut bytes = serde_json::to_vec(&record).map_err(|source| StateError::Serialize {
            path: path.clone(),
            source,
        })?;
        bytes.push(b'\n');
        if usize_to_u64(bytes.len()) > MAX_STATE_RECORD_BYTES {
            return Err(StateError::RecordTooLarge { path });
        }

        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                let existing = self.read_record(record.kind, &key)?.ok_or_else(|| {
                    StateError::CorruptRecord {
                        path: path.clone(),
                        reason: "record exists but could not be read".to_owned(),
                    }
                })?;
                return if existing == record {
                    Ok(StateChange::Unchanged)
                } else {
                    Err(StateError::ConflictingRecord { path })
                };
            }
            Err(source) => return Err(state_io("create state record", &path, source)),
        };

        if let Err(source) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(state_io("write state record", &path, source));
        }
        sync_directory(&directory)?;
        Ok(StateChange::Changed)
    }

    fn remove_record(
        &self,
        kind: RecordKind,
        key: &ArtifactStateKey,
    ) -> Result<StateChange, StateError> {
        let Some(directory) = self.existing_state_directory(kind)? else {
            return Ok(StateChange::Unchanged);
        };
        let path = directory.join(record_filename(key));
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(StateChange::Unchanged);
            }
            Err(source) => return Err(state_io("inspect state record", &path, source)),
        };
        if metadata.is_dir() || (!metadata.is_file() && !metadata.file_type().is_symlink()) {
            return Err(StateError::UnsafeStatePath { path });
        }
        fs::remove_file(&path).map_err(|source| state_io("remove state record", &path, source))?;
        sync_directory(&directory)?;
        Ok(StateChange::Changed)
    }

    fn read_record(
        &self,
        kind: RecordKind,
        key: &ArtifactStateKey,
    ) -> Result<Option<StateRecord>, StateError> {
        let Some(directory) = self.existing_state_directory(kind)? else {
            return Ok(None);
        };
        let path = directory.join(record_filename(key));
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(state_io("inspect state record", &path, source)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(StateError::UnsafeStatePath { path });
        }
        if metadata.len() > MAX_STATE_RECORD_BYTES {
            return Err(StateError::RecordTooLarge { path });
        }

        let mut file =
            File::open(&path).map_err(|source| state_io("open state record", &path, source))?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_STATE_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| state_io("read state record", &path, source))?;
        if usize_to_u64(bytes.len()) > MAX_STATE_RECORD_BYTES {
            return Err(StateError::RecordTooLarge { path });
        }
        let record = serde_json::from_slice::<StateRecord>(&bytes).map_err(|source| {
            StateError::CorruptRecord {
                path: path.clone(),
                reason: source.to_string(),
            }
        })?;
        record.validate(kind, key, &path)?;
        Ok(Some(record))
    }

    fn existing_state_directory(&self, kind: RecordKind) -> Result<Option<PathBuf>, StateError> {
        validate_real_directory(&self.plugins_root, true)?.ok_or_else(|| {
            StateError::PluginsRootMissing {
                path: self.plugins_root.clone(),
            }
        })?;

        let mut directory = self.plugins_root.clone();
        for component in [
            STATE_DIRECTORY,
            STATE_VERSION_DIRECTORY,
            kind.directory_name(),
        ] {
            directory.push(component);
            if validate_real_directory(&directory, true)?.is_none() {
                return Ok(None);
            }
        }
        Ok(Some(directory))
    }

    fn ensure_state_directory(&self, kind: RecordKind) -> Result<PathBuf, StateError> {
        validate_real_directory(&self.plugins_root, true)?.ok_or_else(|| {
            StateError::PluginsRootMissing {
                path: self.plugins_root.clone(),
            }
        })?;

        let mut directory = self.plugins_root.clone();
        for component in [
            STATE_DIRECTORY,
            STATE_VERSION_DIRECTORY,
            kind.directory_name(),
        ] {
            directory.push(component);
            match validate_real_directory(&directory, true)? {
                Some(()) => {}
                None => match fs::create_dir(&directory) {
                    Ok(()) => {}
                    Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(source) => {
                        return Err(state_io("create state directory", &directory, source));
                    }
                },
            }
            validate_real_directory(&directory, false)?.ok_or_else(|| {
                StateError::UnsafeStatePath {
                    path: directory.clone(),
                }
            })?;
        }
        Ok(directory)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RecordKind {
    Trust,
    Quarantine,
}

impl RecordKind {
    const fn directory_name(self) -> &'static str {
        match self {
            Self::Trust => TRUST_DIRECTORY,
            Self::Quarantine => QUARANTINE_DIRECTORY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateRecord {
    schema_version: u32,
    kind: RecordKind,
    plugin_id: String,
    artifact_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl StateRecord {
    fn new(kind: RecordKind, key: &ArtifactStateKey, reason: Option<String>) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            kind,
            plugin_id: key.plugin_id.to_string(),
            artifact_sha256: key.fingerprint.to_hex(),
            reason,
        }
    }

    fn key(&self) -> Result<ArtifactStateKey, StateError> {
        let plugin_id = PluginId::new(self.plugin_id.clone()).map_err(|error| {
            StateError::InvalidRecordValue {
                reason: error.to_string(),
            }
        })?;
        let fingerprint =
            self.artifact_sha256
                .parse()
                .map_err(
                    |FingerprintParseError(value)| StateError::InvalidRecordValue {
                        reason: format!("invalid artifact fingerprint `{value}`"),
                    },
                )?;
        Ok(ArtifactStateKey::new(plugin_id, fingerprint))
    }

    fn validate(
        &self,
        expected_kind: RecordKind,
        expected_key: &ArtifactStateKey,
        path: &Path,
    ) -> Result<(), StateError> {
        let invalid = |reason: &str| StateError::CorruptRecord {
            path: path.to_path_buf(),
            reason: reason.to_owned(),
        };
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(invalid("unsupported state schema version"));
        }
        if self.kind != expected_kind {
            return Err(invalid("record kind does not match its state directory"));
        }
        if self.plugin_id != expected_key.plugin_id.as_str() {
            return Err(invalid("record plugin ID does not match its filename key"));
        }
        if self.artifact_sha256 != expected_key.fingerprint.to_hex() {
            return Err(invalid(
                "record artifact fingerprint does not match its filename key",
            ));
        }
        match (self.kind, &self.reason) {
            (RecordKind::Trust, None) => Ok(()),
            (RecordKind::Trust, Some(_)) => Err(invalid("trust records cannot contain a reason")),
            (RecordKind::Quarantine, Some(reason)) => {
                validate_quarantine_reason(reason).map_err(|error| invalid(&error.to_string()))
            }
            (RecordKind::Quarantine, None) => {
                Err(invalid("quarantine records must contain a reason"))
            }
        }
    }
}

fn record_filename(key: &ArtifactStateKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PLUGIN_ID_DOMAIN);
    hasher.update(key.plugin_id.as_str().as_bytes());
    let plugin_id_digest = hasher.finalize();
    format!("{}-{}.json", encode_hex(&plugin_id_digest), key.fingerprint)
}

fn validate_real_directory(path: &Path, missing_is_ok: bool) -> Result<Option<()>, StateError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if missing_is_ok && source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => return Err(state_io("inspect state directory", path, source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StateError::UnsafeStatePath {
            path: path.to_path_buf(),
        });
    }
    Ok(Some(()))
}

fn validate_quarantine_reason(reason: &str) -> Result<(), StateError> {
    if reason.trim().is_empty()
        || reason.len() > MAX_QUARANTINE_REASON_BYTES
        || reason.chars().any(|character| character == '\0')
    {
        Err(StateError::InvalidQuarantineReason)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn sync_directory(path: &Path) -> Result<(), StateError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| state_io("synchronize state directory", path, source))
}

#[cfg(not(target_os = "linux"))]
const fn sync_directory(_path: &Path) -> Result<(), StateError> {
    // Standard Rust has no portable directory-fsync operation. The immutable record itself was
    // still created with create-new semantics and synchronized before this point.
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

const fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn fingerprint_io(operation: &'static str, path: &Path, source: io::Error) -> FingerprintError {
    FingerprintError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn state_io(operation: &'static str, path: &Path, source: io::Error) -> StateError {
    StateError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid SHA-256 artifact fingerprint `{0}`")]
pub struct FingerprintParseError(String);

/// Failure while validating or hashing a plugin directory.
#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("plugin artifact root is not a directory: {path}", path = .path.display())]
    RootNotDirectory { path: PathBuf },
    #[error("plugin artifact contains a symbolic link: {path}", path = .path.display())]
    Symlink { path: PathBuf },
    #[error("plugin artifact path is not valid UTF-8: {path:?}")]
    NonUtf8Path { path: PathBuf },
    #[error("plugin artifact contains a special file: {path}", path = .path.display())]
    UnsupportedFileType { path: PathBuf },
    #[error(
        "plugin artifact exceeded {limit} limit {maximum} with {observed} at {path}",
        path = .path.display()
    )]
    LimitExceeded {
        limit: &'static str,
        maximum: u64,
        observed: u64,
        path: PathBuf,
    },
    #[error("plugin file changed while it was being fingerprinted: {path}", path = .path.display())]
    FileChanged { path: PathBuf },
    #[error("cannot {operation} {path}: {source}", path = .path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Failure while reading or updating host-owned plugin policy state.
#[derive(Debug, Error)]
pub enum StateError {
    #[error("plugin root does not exist: {path}", path = .path.display())]
    PluginsRootMissing { path: PathBuf },
    #[error("plugin state path is linked or has an unsafe file type: {path}", path = .path.display())]
    UnsafeStatePath { path: PathBuf },
    #[error("plugin state record is too large: {path}", path = .path.display())]
    RecordTooLarge { path: PathBuf },
    #[error("corrupt plugin state record {path}: {reason}", path = .path.display())]
    CorruptRecord { path: PathBuf, reason: String },
    #[error("a different immutable plugin state record already exists at {path}", path = .path.display())]
    ConflictingRecord { path: PathBuf },
    #[error("quarantine reason must be nonempty, at most 4096 bytes, and contain no NUL")]
    InvalidQuarantineReason,
    #[error("invalid state record value: {reason}")]
    InvalidRecordValue { reason: String },
    #[error("cannot serialize plugin state record {path}: {source}", path = .path.display())]
    Serialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("cannot {operation} {path}: {source}", path = .path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_plugin(root: &Path) -> PathBuf {
        let plugin = root.join("plugin");
        fs::create_dir(&plugin).expect("create plugin directory");
        fs::write(
            plugin.join("plugin.toml"),
            br#"manifest_version = 1
id = "community.test"
name = "Test"
version = "0.1.0"
api = "^0.1.0"

[runtime]
kind = "external-process"
entrypoint = "plugin.bin"
args = ["--stdio"]
"#,
        )
        .expect("write manifest");
        fs::write(plugin.join("plugin.bin"), b"executable-v1").expect("write entrypoint");
        fs::create_dir(plugin.join("data")).expect("create sidecar directory");
        fs::write(plugin.join("data/signatures.db"), b"sidecar-v1").expect("write sidecar");
        plugin
    }

    fn fingerprint(plugin: &Path) -> ArtifactFingerprint {
        fingerprint_plugin_directory(plugin, FingerprintLimits::default())
            .expect("fingerprint plugin")
            .fingerprint
    }

    fn key(id: &str, fingerprint: ArtifactFingerprint) -> ArtifactStateKey {
        ArtifactStateKey::new(PluginId::new(id).expect("valid plugin ID"), fingerprint)
    }

    #[test]
    fn artifact_fingerprint_parser_requires_canonical_lowercase_hex() {
        let lowercase = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            lowercase
                .parse::<ArtifactFingerprint>()
                .expect("canonical fingerprint")
                .to_hex(),
            lowercase
        );
        assert!(
            lowercase
                .to_ascii_uppercase()
                .parse::<ArtifactFingerprint>()
                .is_err()
        );
    }

    #[test]
    fn manifest_entrypoint_and_sidecar_changes_change_the_fingerprint() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let plugin = write_plugin(temporary.path());
        let baseline = fingerprint(&plugin);

        fs::write(plugin.join("plugin.bin"), b"executable-v2").expect("change entrypoint");
        let changed_entrypoint = fingerprint(&plugin);
        assert_ne!(baseline, changed_entrypoint);

        fs::write(plugin.join("plugin.bin"), b"executable-v1").expect("restore entrypoint");
        fs::write(plugin.join("data/signatures.db"), b"sidecar-v2").expect("change sidecar");
        let changed_sidecar = fingerprint(&plugin);
        assert_ne!(baseline, changed_sidecar);

        fs::write(plugin.join("data/signatures.db"), b"sidecar-v1").expect("restore sidecar");
        let manifest = fs::read_to_string(plugin.join("plugin.toml")).expect("read manifest");
        fs::write(
            plugin.join("plugin.toml"),
            manifest.replace(
                "args = [\"--stdio\"]",
                "args = [\"--stdio\", \"--verbose\"]",
            ),
        )
        .expect("change manifest arguments");
        let changed_arguments = fingerprint(&plugin);
        assert_ne!(baseline, changed_arguments);
    }

    #[test]
    fn root_disable_sentinel_is_the_only_excluded_file() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let plugin = write_plugin(temporary.path());
        let baseline = fingerprint(&plugin);

        fs::write(plugin.join(DISABLED_SENTINEL), b"disabled").expect("write sentinel");
        assert_eq!(baseline, fingerprint(&plugin));
        fs::write(plugin.join(DISABLED_SENTINEL), b"different contents").expect("change sentinel");
        assert_eq!(baseline, fingerprint(&plugin));

        fs::write(plugin.join("data/plugin.disabled"), b"nested")
            .expect("write nested sentinel-like file");
        assert_ne!(baseline, fingerprint(&plugin));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_rejected_without_being_followed() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("create temporary directory");
        let plugin = write_plugin(temporary.path());
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"outside data").expect("write outside file");
        symlink(&outside, plugin.join("data/linked")).expect("create symlink");

        let error = fingerprint_plugin_directory(&plugin, FingerprintLimits::default())
            .expect_err("symlink must be rejected");
        assert!(matches!(error, FingerprintError::Symlink { .. }));
    }

    #[test]
    fn limits_are_enforced_before_file_contents_are_accepted() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let plugin = write_plugin(temporary.path());
        let limits = FingerprintLimits {
            max_file_bytes: 4,
            ..FingerprintLimits::default()
        };
        let error = fingerprint_plugin_directory(&plugin, limits)
            .expect_err("oversized file must be rejected");
        assert!(matches!(
            error,
            FingerprintError::LimitExceeded {
                limit: "individual file size",
                ..
            }
        ));
    }

    #[test]
    fn trust_is_bound_to_the_exact_fingerprint() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let plugins = temporary.path().join("plugins");
        fs::create_dir(&plugins).expect("create plugin root");
        let plugin = write_plugin(&plugins);
        let store = PluginStateStore::new(&plugins);
        let original_key = key("community.test", fingerprint(&plugin));

        assert_eq!(
            store.trust(&original_key).expect("trust plugin"),
            StateChange::Changed
        );
        assert_eq!(
            store.status(&original_key).expect("read trusted state"),
            PluginArtifactStatus::Trusted
        );

        fs::write(plugin.join("data/signatures.db"), b"updated").expect("change plugin artifact");
        let changed_key = key("community.test", fingerprint(&plugin));
        assert_eq!(
            store.status(&changed_key).expect("read changed state"),
            PluginArtifactStatus::ApprovalRequired
        );
        assert_eq!(
            store.status(&original_key).expect("read original state"),
            PluginArtifactStatus::Trusted
        );
    }

    #[test]
    fn corrupt_exact_state_fails_closed_and_can_be_explicitly_removed() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let plugins = temporary.path().join("plugins");
        fs::create_dir(&plugins).expect("create plugin root");
        let plugin = write_plugin(&plugins);
        let store = PluginStateStore::new(&plugins);
        let key = key("community.test", fingerprint(&plugin));
        store.trust(&key).expect("trust plugin");

        let trust_path = store
            .state_root()
            .join(STATE_VERSION_DIRECTORY)
            .join(TRUST_DIRECTORY)
            .join(record_filename(&key));
        fs::write(&trust_path, b"not valid JSON").expect("corrupt trust record");
        assert!(matches!(
            store.status(&key),
            Err(StateError::CorruptRecord { .. })
        ));

        assert_eq!(
            store.untrust(&key).expect("remove corrupt record"),
            StateChange::Changed
        );
        assert_eq!(
            store.status(&key).expect("read cleared state"),
            PluginArtifactStatus::ApprovalRequired
        );
    }

    #[test]
    fn trust_and_quarantine_are_isolated_by_plugin_identity() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let plugins = temporary.path().join("plugins");
        fs::create_dir(&plugins).expect("create plugin root");
        let plugin = write_plugin(&plugins);
        let digest = fingerprint(&plugin);
        let first = key("community.first", digest);
        let second = key("community.second", digest);
        let store = PluginStateStore::new(&plugins);

        store.trust(&first).expect("trust first plugin");
        store
            .quarantine(&first, "protocol violation")
            .expect("quarantine first plugin");
        assert_eq!(
            store.status(&first).expect("read first state"),
            PluginArtifactStatus::Quarantined {
                reason: "protocol violation".to_owned()
            }
        );
        assert_eq!(
            store.status(&second).expect("read second state"),
            PluginArtifactStatus::ApprovalRequired
        );

        store.reset(&first).expect("reset first quarantine");
        assert_eq!(
            store.status(&first).expect("read reset state"),
            PluginArtifactStatus::Trusted
        );
        store.untrust(&first).expect("untrust first plugin");
        assert_eq!(
            store.status(&first).expect("read untrusted state"),
            PluginArtifactStatus::ApprovalRequired
        );
    }

    #[test]
    fn state_is_outside_artifact_and_does_not_change_its_fingerprint() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let plugins = temporary.path().join("plugins");
        fs::create_dir(&plugins).expect("create plugin root");
        let plugin = write_plugin(&plugins);
        let before = fingerprint(&plugin);
        let state_key = key("community.test", before);
        let store = PluginStateStore::new(&plugins);

        store.trust(&state_key).expect("trust plugin");
        store
            .quarantine(&state_key, "test quarantine")
            .expect("quarantine plugin");
        assert!(store.state_root().starts_with(&plugins));
        assert!(!store.state_root().starts_with(&plugin));
        assert_eq!(before, fingerprint(&plugin));
    }
}
