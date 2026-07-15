//! Portable `.resym` package envelopes.
//!
//! This crate deliberately knows nothing about ReSymbol's analysis graph. It
//! wraps any Serde-compatible payload with the minimum metadata needed to
//! identify the exact input binary and evolve the on-disk schema safely.
//!
//! Packages emitted by [`to_vec`] are compact canonical JSON: object keys are
//! recursively sorted and no timestamp or other ambient value is added. The
//! same valid package value therefore produces the same bytes. Payload types
//! must themselves serialize deterministically (for example, they must not
//! derive values from iteration over a randomly ordered collection).

#![forbid(unsafe_code)]

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;

pub use resymbol_core::{BinaryId, ClaimValidationError};

/// The package schema written by this crate.
pub const CURRENT_SCHEMA_VERSION: u32 = 3;

/// Default maximum encoded or decoded package size: 64 MiB.
pub const DEFAULT_MAX_PACKAGE_BYTES: usize = 64 * 1024 * 1024;

const MAX_GENERATOR_VERSION_LENGTH: usize = 128;

/// A payload whose contents identify the binary they describe.
///
/// Implement this for payloads that embed a [`BinaryId`] (directly or through
/// a validated analysis identity). The bound read helpers then reject an
/// envelope whose outer identity disagrees with its payload identity.
pub trait BinaryBoundPayload {
    /// Returns the exact binary identity embedded in this payload.
    fn binary_id(&self) -> &BinaryId;
}

/// Inclusive schema versions a reader is prepared to understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaCompatibility {
    minimum: u32,
    maximum: u32,
}

impl SchemaCompatibility {
    /// Accepts only the schema emitted by this crate.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            minimum: CURRENT_SCHEMA_VERSION,
            maximum: CURRENT_SCHEMA_VERSION,
        }
    }

    /// Creates an inclusive supported schema range.
    pub fn inclusive(minimum: u32, maximum: u32) -> Result<Self, PackageError> {
        if minimum > maximum {
            return Err(PackageError::InvalidSchemaRange { minimum, maximum });
        }
        Ok(Self { minimum, maximum })
    }

    /// The oldest accepted schema.
    #[must_use]
    pub const fn minimum(self) -> u32 {
        self.minimum
    }

    /// The newest accepted schema.
    #[must_use]
    pub const fn maximum(self) -> u32 {
        self.maximum
    }

    #[must_use]
    fn supports(self, schema_version: u32) -> bool {
        (self.minimum..=self.maximum).contains(&schema_version)
    }
}

impl Default for SchemaCompatibility {
    fn default() -> Self {
        Self::current()
    }
}

/// Limits and compatibility policy applied by package I/O helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageOptions {
    max_bytes: usize,
    schema_compatibility: SchemaCompatibility,
}

impl PackageOptions {
    /// Builds options with an explicit non-zero size limit and schema policy.
    pub fn new(
        max_bytes: usize,
        schema_compatibility: SchemaCompatibility,
    ) -> Result<Self, PackageError> {
        if max_bytes == 0 {
            return Err(PackageError::InvalidSizeLimit);
        }
        Ok(Self {
            max_bytes,
            schema_compatibility,
        })
    }

    /// Maximum accepted or emitted package size in bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Schema versions accepted by this operation.
    #[must_use]
    pub const fn schema_compatibility(self) -> SchemaCompatibility {
        self.schema_compatibility
    }
}

impl Default for PackageOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_PACKAGE_BYTES,
            schema_compatibility: SchemaCompatibility::current(),
        }
    }
}

/// A versioned `.resym` envelope around an analysis-format-independent payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResymPackage<T> {
    schema_version: u32,
    generator_version: String,
    binary_sha256: BinaryId,
    payload: T,
}

impl<T> ResymPackage<T> {
    /// Creates a package using [`CURRENT_SCHEMA_VERSION`].
    pub fn new(
        generator_version: impl Into<String>,
        binary_sha256: BinaryId,
        payload: T,
    ) -> Result<Self, PackageError> {
        let generator_version = generator_version.into();
        validate_generator_version(&generator_version)?;
        Ok(Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            generator_version,
            binary_sha256,
            payload,
        })
    }

    /// Package schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Version string supplied by the package-producing application.
    #[must_use]
    pub fn generator_version(&self) -> &str {
        &self.generator_version
    }

    /// SHA-256 identity of the exact binary the payload describes.
    #[must_use]
    pub const fn binary_sha256(&self) -> &BinaryId {
        &self.binary_sha256
    }

    /// The analysis payload.
    #[must_use]
    pub const fn payload(&self) -> &T {
        &self.payload
    }

    /// Consumes the envelope and returns its payload.
    #[must_use]
    pub fn into_payload(self) -> T {
        self.payload
    }

    /// Transforms the payload while preserving the validated envelope metadata.
    ///
    /// This is useful when an application must migrate an older payload schema
    /// after the generic envelope has been size- and version-checked.
    pub fn try_map_payload<U, E>(
        self,
        map: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<ResymPackage<U>, E> {
        Ok(ResymPackage {
            schema_version: self.schema_version,
            generator_version: self.generator_version,
            binary_sha256: self.binary_sha256,
            payload: map(self.payload)?,
        })
    }

    /// Checks that a separately computed identity refers to this package's binary.
    pub fn ensure_binary_id(&self, expected: &BinaryId) -> Result<(), PackageError> {
        if &self.binary_sha256 == expected {
            Ok(())
        } else {
            Err(PackageError::BinaryIdMismatch {
                expected: expected.clone(),
                actual: self.binary_sha256.clone(),
            })
        }
    }

    /// Runs an application-defined consistency check against the package identity.
    ///
    /// This hook lets callers compare against a digest computed by another crate,
    /// a content store, or an already-open binary without coupling this envelope
    /// crate to any of those systems.
    pub fn check_binary_id<F, E>(&self, check: F) -> Result<(), PackageError>
    where
        F: FnOnce(&BinaryId) -> Result<(), E>,
        E: fmt::Display,
    {
        check(&self.binary_sha256).map_err(|error| PackageError::BinaryIdRejected {
            binary_sha256: self.binary_sha256.clone(),
            reason: error.to_string(),
        })
    }

    fn validate(&self, compatibility: SchemaCompatibility) -> Result<(), PackageError> {
        validate_schema(self.schema_version, compatibility)?;
        validate_generator_version(&self.generator_version)
    }
}

impl<T: BinaryBoundPayload> ResymPackage<T> {
    /// Creates an envelope whose identity is derived from its bound payload.
    ///
    /// Prefer this over [`ResymPackage::new`] when the payload implements
    /// [`BinaryBoundPayload`], because it cannot construct a mismatched pair.
    pub fn from_bound_payload(
        generator_version: impl Into<String>,
        payload: T,
    ) -> Result<Self, PackageError> {
        let binary_sha256 = payload.binary_id().clone();
        Self::new(generator_version, binary_sha256, payload)
    }

    /// Ensures the envelope and its embedded payload name the same binary.
    pub fn ensure_payload_binding(&self) -> Result<(), PackageError> {
        let payload = self.payload.binary_id();
        if &self.binary_sha256 == payload {
            Ok(())
        } else {
            Err(PackageError::PayloadBinaryIdMismatch {
                envelope: self.binary_sha256.clone(),
                payload: payload.clone(),
            })
        }
    }

    /// Checks both the envelope-to-payload binding and a separately loaded binary.
    pub fn ensure_bound_to(&self, expected: &BinaryId) -> Result<(), PackageError> {
        self.ensure_payload_binding()?;
        self.ensure_binary_id(expected)
    }
}

/// Encodes a package as deterministic, compact JSON using default limits.
pub fn to_vec<T: Serialize>(package: &ResymPackage<T>) -> Result<Vec<u8>, PackageError> {
    to_vec_with_options(package, PackageOptions::default())
}

/// Encodes a package as deterministic, compact JSON using explicit limits.
///
/// The output limit is checked before bytes are returned, but encoding first
/// materializes the generic payload as a JSON value so its keys can be sorted.
/// It is therefore an output acceptance limit, not a bound on transient memory
/// used while serializing an already-constructed payload.
pub fn to_vec_with_options<T: Serialize>(
    package: &ResymPackage<T>,
    options: PackageOptions,
) -> Result<Vec<u8>, PackageError> {
    package.validate(options.schema_compatibility)?;
    let value = serde_json::to_value(package).map_err(PackageError::Serialize)?;
    let value = canonicalize(value);
    let bytes = serde_json::to_vec(&value).map_err(PackageError::Serialize)?;
    if bytes.len() > options.max_bytes {
        return Err(PackageError::OutputTooLarge {
            actual: bytes.len(),
            maximum: options.max_bytes,
        });
    }
    Ok(bytes)
}

/// Encodes a binary-bound package after validating its inner identity.
pub fn to_vec_bound<T>(package: &ResymPackage<T>) -> Result<Vec<u8>, PackageError>
where
    T: BinaryBoundPayload + Serialize,
{
    to_vec_bound_with_options(package, PackageOptions::default())
}

/// Encodes a binary-bound package with explicit limits after validating its
/// inner identity.
pub fn to_vec_bound_with_options<T>(
    package: &ResymPackage<T>,
    options: PackageOptions,
) -> Result<Vec<u8>, PackageError>
where
    T: BinaryBoundPayload + Serialize,
{
    package.ensure_payload_binding()?;
    to_vec_with_options(package, options)
}

/// Decodes and validates a package using current-schema and default size limits.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<ResymPackage<T>, PackageError> {
    from_slice_with_options(bytes, PackageOptions::default())
}

/// Decodes and validates a package using explicit limits and compatibility policy.
pub fn from_slice_with_options<T: DeserializeOwned>(
    bytes: &[u8],
    options: PackageOptions,
) -> Result<ResymPackage<T>, PackageError> {
    check_input_size(bytes.len(), options.max_bytes)?;

    let wire: WirePackage = serde_json::from_slice(bytes).map_err(PackageError::Deserialize)?;
    validate_schema(wire.schema_version, options.schema_compatibility)?;
    validate_generator_version(&wire.generator_version)?;
    let binary_sha256 =
        BinaryId::from_sha256(wire.binary_sha256).map_err(PackageError::InvalidBinaryId)?;
    let payload = serde_json::from_value(wire.payload).map_err(PackageError::Deserialize)?;

    Ok(ResymPackage {
        schema_version: wire.schema_version,
        generator_version: wire.generator_version,
        binary_sha256,
        payload,
    })
}

/// Decodes a package and immediately applies an application-defined identity check.
pub fn from_slice_checked<T, F, E>(
    bytes: &[u8],
    options: PackageOptions,
    check: F,
) -> Result<ResymPackage<T>, PackageError>
where
    T: DeserializeOwned,
    F: FnOnce(&BinaryId) -> Result<(), E>,
    E: fmt::Display,
{
    let package = from_slice_with_options(bytes, options)?;
    package.check_binary_id(check)?;
    Ok(package)
}

/// Decodes a binary-bound payload and rejects an envelope/payload ID mismatch.
pub fn from_slice_bound<T>(bytes: &[u8]) -> Result<ResymPackage<T>, PackageError>
where
    T: BinaryBoundPayload + DeserializeOwned,
{
    from_slice_bound_with_options(bytes, PackageOptions::default())
}

/// Decodes a binary-bound payload with explicit limits and rejects an
/// envelope/payload ID mismatch.
pub fn from_slice_bound_with_options<T>(
    bytes: &[u8],
    options: PackageOptions,
) -> Result<ResymPackage<T>, PackageError>
where
    T: BinaryBoundPayload + DeserializeOwned,
{
    let package = from_slice_with_options(bytes, options)?;
    package.ensure_payload_binding()?;
    Ok(package)
}

/// Reads and validates a package file using default limits.
pub fn read_file<T: DeserializeOwned>(
    path: impl AsRef<Path>,
) -> Result<ResymPackage<T>, PackageError> {
    read_file_with_options(path, PackageOptions::default())
}

/// Reads and validates a package file without ever buffering beyond the
/// configured limit plus one byte.
pub fn read_file_with_options<T: DeserializeOwned>(
    path: impl AsRef<Path>,
    options: PackageOptions,
) -> Result<ResymPackage<T>, PackageError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| PackageError::Io {
        operation: "open package for reading",
        path: path.to_path_buf(),
        source,
    })?;

    if let Ok(metadata) = file.metadata() {
        let maximum = u64::try_from(options.max_bytes).unwrap_or(u64::MAX);
        if metadata.len() > maximum {
            return Err(PackageError::InputTooLarge {
                actual: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
                maximum: options.max_bytes,
            });
        }
    }

    let read_limit = u64::try_from(options.max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| PackageError::Io {
            operation: "read package",
            path: path.to_path_buf(),
            source,
        })?;
    check_input_size(bytes.len(), options.max_bytes)?;
    from_slice_with_options(&bytes, options)
}

/// Reads a binary-bound package using default limits and validates its inner binding.
pub fn read_file_bound<T>(path: impl AsRef<Path>) -> Result<ResymPackage<T>, PackageError>
where
    T: BinaryBoundPayload + DeserializeOwned,
{
    read_file_bound_with_options(path, PackageOptions::default())
}

/// Reads a binary-bound package using explicit limits and validates its inner binding.
pub fn read_file_bound_with_options<T>(
    path: impl AsRef<Path>,
    options: PackageOptions,
) -> Result<ResymPackage<T>, PackageError>
where
    T: BinaryBoundPayload + DeserializeOwned,
{
    let package = read_file_with_options(path, options)?;
    package.ensure_payload_binding()?;
    Ok(package)
}

/// Creates and writes a package file using default limits.
///
/// The destination is opened with the operating system's create-new primitive.
/// An existing path is never truncated or overwritten. If a write or durability
/// flush fails after creation, a partial destination file may remain and the
/// returned error identifies that path.
pub fn write_file_new<T: Serialize>(
    path: impl AsRef<Path>,
    package: &ResymPackage<T>,
) -> Result<(), PackageError> {
    write_file_new_with_options(path, package, PackageOptions::default())
}

/// Creates and writes a package file using explicit limits.
pub fn write_file_new_with_options<T: Serialize>(
    path: impl AsRef<Path>,
    package: &ResymPackage<T>,
    options: PackageOptions,
) -> Result<(), PackageError> {
    let path = path.as_ref();
    let bytes = to_vec_with_options(package, options)?;
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(PackageError::TargetAlreadyExists {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(PackageError::Io {
                operation: "create package",
                path: path.to_path_buf(),
                source,
            });
        }
    };

    file.write_all(&bytes).map_err(|source| PackageError::Io {
        operation: "write package",
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| PackageError::Io {
        operation: "flush package to durable storage",
        path: path.to_path_buf(),
        source,
    })
}

/// Creates a binary-bound package file after validating its inner identity.
pub fn write_file_new_bound<T>(
    path: impl AsRef<Path>,
    package: &ResymPackage<T>,
) -> Result<(), PackageError>
where
    T: BinaryBoundPayload + Serialize,
{
    write_file_new_bound_with_options(path, package, PackageOptions::default())
}

/// Creates a binary-bound package file with explicit limits after validating
/// its inner identity.
pub fn write_file_new_bound_with_options<T>(
    path: impl AsRef<Path>,
    package: &ResymPackage<T>,
    options: PackageOptions,
) -> Result<(), PackageError>
where
    T: BinaryBoundPayload + Serialize,
{
    package.ensure_payload_binding()?;
    write_file_new_with_options(path, package, options)
}

/// Failures produced while validating, encoding, or reading a `.resym` package.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PackageError {
    #[error("package size limit must be greater than zero")]
    InvalidSizeLimit,

    #[error("invalid supported schema range {minimum}..={maximum}: minimum exceeds maximum")]
    InvalidSchemaRange { minimum: u32, maximum: u32 },

    #[error(
        "unsupported package schema {found}; this reader accepts schemas {minimum} through {maximum}"
    )]
    UnsupportedSchema {
        found: u32,
        minimum: u32,
        maximum: u32,
    },

    #[error("invalid generator version: {reason}")]
    InvalidGeneratorVersion { reason: &'static str },

    #[error(
        "invalid package binary identity: expected exactly 64 hexadecimal SHA-256 characters ({0})"
    )]
    InvalidBinaryId(#[source] ClaimValidationError),

    #[error("package describes binary {actual}, but binary {expected} was expected")]
    BinaryIdMismatch {
        expected: BinaryId,
        actual: BinaryId,
    },

    #[error(
        "package envelope identifies binary {envelope}, but its payload identifies binary {payload}"
    )]
    PayloadBinaryIdMismatch {
        envelope: BinaryId,
        payload: BinaryId,
    },

    #[error("binary identity check rejected package identity {binary_sha256}: {reason}")]
    BinaryIdRejected {
        binary_sha256: BinaryId,
        reason: String,
    },

    #[error("package input is {actual} bytes, exceeding the configured {maximum}-byte limit")]
    InputTooLarge { actual: usize, maximum: usize },

    #[error("encoded package is {actual} bytes, exceeding the configured {maximum}-byte limit")]
    OutputTooLarge { actual: usize, maximum: usize },

    #[error("could not serialize package JSON: {0}")]
    Serialize(#[source] serde_json::Error),

    #[error("could not decode package JSON: {0}")]
    Deserialize(#[source] serde_json::Error),

    #[error("refusing to overwrite existing package {path:?}")]
    TargetAlreadyExists { path: PathBuf },

    #[error("could not {operation} {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePackage {
    schema_version: u32,
    generator_version: String,
    binary_sha256: String,
    payload: Value,
}

fn validate_schema(
    schema_version: u32,
    compatibility: SchemaCompatibility,
) -> Result<(), PackageError> {
    if compatibility.supports(schema_version) {
        Ok(())
    } else {
        Err(PackageError::UnsupportedSchema {
            found: schema_version,
            minimum: compatibility.minimum,
            maximum: compatibility.maximum,
        })
    }
}

fn validate_generator_version(generator_version: &str) -> Result<(), PackageError> {
    let reason = if generator_version.is_empty() {
        Some("value is empty")
    } else if generator_version.len() > MAX_GENERATOR_VERSION_LENGTH {
        Some("value exceeds 128 bytes")
    } else if generator_version.trim() != generator_version {
        Some("leading or trailing whitespace is not allowed")
    } else if generator_version.chars().any(char::is_control) {
        Some("control characters are not allowed")
    } else {
        None
    };

    match reason {
        Some(reason) => Err(PackageError::InvalidGeneratorVersion { reason }),
        None => Ok(()),
    }
}

fn check_input_size(actual: usize, maximum: usize) -> Result<(), PackageError> {
    if actual > maximum {
        Err(PackageError::InputTooLarge { actual, maximum })
    } else {
        Ok(())
    }
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = serde_json::Map::new();
            for (key, value) in entries {
                sorted.insert(key, canonicalize(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs};

    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestPayload {
        label: String,
        values: Vec<u64>,
        metadata: HashMap<String, String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct BoundPayload {
        binary_id: BinaryId,
        value: u64,
    }

    impl BinaryBoundPayload for BoundPayload {
        fn binary_id(&self) -> &BinaryId {
            &self.binary_id
        }
    }

    fn package() -> ResymPackage<TestPayload> {
        let metadata = HashMap::from([
            ("zeta".to_owned(), "last".to_owned()),
            ("alpha".to_owned(), "first".to_owned()),
        ]);
        ResymPackage::new(
            "0.1.0-test",
            BinaryId::from_sha256(DIGEST_A).expect("valid test digest"),
            TestPayload {
                label: "fixture".to_owned(),
                values: vec![1, 2, 3],
                metadata,
            },
        )
        .expect("valid package")
    }

    #[test]
    fn deterministic_round_trip_canonicalizes_nested_keys() {
        let package = package();
        let first = to_vec(&package).expect("package encodes");
        let second = to_vec(&package).expect("same package encodes again");
        assert_eq!(first, second);

        let json = std::str::from_utf8(&first).expect("JSON is UTF-8");
        assert_eq!(
            json,
            concat!(
                "{\"binary_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
                "\"generator_version\":\"0.1.0-test\",",
                "\"payload\":{\"label\":\"fixture\",",
                "\"metadata\":{\"alpha\":\"first\",\"zeta\":\"last\"},",
                "\"values\":[1,2,3]},\"schema_version\":3}"
            )
        );

        let decoded: ResymPackage<TestPayload> = from_slice(&first).expect("package decodes");
        assert_eq!(decoded, package);
        assert_eq!(to_vec(&decoded).expect("decoded package re-encodes"), first);
    }

    #[test]
    fn unsupported_schema_is_reported_before_payload_decoding() {
        let bytes = format!(
            "{{\"schema_version\":4,\"generator_version\":\"0.1.0\",\"binary_sha256\":\"{DIGEST_A}\",\"payload\":\"not the requested type\"}}"
        );
        let error = from_slice::<TestPayload>(bytes.as_bytes()).expect_err("schema is unsupported");
        assert!(matches!(
            error,
            PackageError::UnsupportedSchema {
                found: 4,
                minimum: CURRENT_SCHEMA_VERSION,
                maximum: CURRENT_SCHEMA_VERSION,
            }
        ));
    }

    #[test]
    fn unknown_envelope_fields_are_rejected() {
        let bytes = format!(
            "{{\"schema_version\":3,\"generator_version\":\"0.1.0\",\"binary_sha256\":\"{DIGEST_A}\",\"payload\":null,\"unexpected\":true}}"
        );
        let error = from_slice::<Value>(bytes.as_bytes()).expect_err("unknown field is rejected");
        assert!(matches!(&error, PackageError::Deserialize(_)));
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn oversized_input_is_rejected_before_json_parsing() {
        let options = PackageOptions::new(8, SchemaCompatibility::current()).expect("valid limit");
        let error = from_slice_with_options::<Value>(b"definitely-not-json", options)
            .expect_err("input exceeds limit");
        assert!(matches!(
            error,
            PackageError::InputTooLarge {
                actual: 19,
                maximum: 8,
            }
        ));
    }

    #[test]
    fn oversized_output_is_rejected() {
        let options = PackageOptions::new(8, SchemaCompatibility::current()).expect("valid limit");
        let error = to_vec_with_options(&package(), options).expect_err("output exceeds limit");
        assert!(matches!(
            error,
            PackageError::OutputTooLarge { maximum: 8, .. }
        ));
    }

    #[test]
    fn invalid_binary_identity_is_actionable() {
        let bytes = br#"{
            "schema_version": 3,
            "generator_version": "0.1.0",
            "binary_sha256": "not-a-sha256",
            "payload": null
        }"#;
        let error = from_slice::<Value>(bytes).expect_err("identity is invalid");
        assert!(matches!(
            &error,
            PackageError::InvalidBinaryId(ClaimValidationError::InvalidBinaryId(value))
                if value == "not-a-sha256"
        ));
        assert!(error.to_string().contains("exactly 64 hexadecimal"));
    }

    #[test]
    fn uppercase_binary_identity_is_canonicalized() {
        let identity = BinaryId::from_sha256(DIGEST_A.to_ascii_uppercase())
            .expect("uppercase hexadecimal is accepted");
        assert_eq!(identity.as_str(), DIGEST_A);
    }

    #[test]
    fn non_hexadecimal_binary_identity_is_rejected() {
        let malformed = format!("{}g", &DIGEST_A[..DIGEST_A.len() - 1]);
        let error = BinaryId::from_sha256(malformed).expect_err("non-hexadecimal digest fails");
        assert!(matches!(
            error,
            ClaimValidationError::InvalidBinaryId(value) if value.ends_with('g')
        ));
    }

    #[test]
    fn explicit_compatibility_range_can_accept_a_newer_envelope() {
        let bytes = format!(
            "{{\"schema_version\":4,\"generator_version\":\"0.2.0\",\"binary_sha256\":\"{DIGEST_A}\",\"payload\":42}}"
        );
        let compatibility = SchemaCompatibility::inclusive(3, 4).expect("valid range");
        let options = PackageOptions::new(1024, compatibility).expect("valid options");
        let decoded =
            from_slice_with_options::<u64>(bytes.as_bytes(), options).expect("schema is accepted");

        assert_eq!(decoded.schema_version(), 4);
        assert_eq!(*decoded.payload(), 42);
    }

    #[test]
    fn schema_v1_requires_explicit_read_compatibility_and_remains_decodable() {
        let bytes = format!(
            "{{\"schema_version\":1,\"generator_version\":\"0.1.0-alpha.1\",\"binary_sha256\":\"{DIGEST_A}\",\"payload\":42}}"
        );
        let error = from_slice::<u64>(bytes.as_bytes())
            .expect_err("the default policy accepts only newly emitted packages");
        assert!(matches!(
            error,
            PackageError::UnsupportedSchema {
                found: 1,
                minimum: CURRENT_SCHEMA_VERSION,
                maximum: CURRENT_SCHEMA_VERSION,
            }
        ));

        let compatibility = SchemaCompatibility::inclusive(1, CURRENT_SCHEMA_VERSION)
            .expect("valid compatibility range");
        let options = PackageOptions::new(1024, compatibility).expect("valid options");
        let decoded = from_slice_with_options::<u64>(bytes.as_bytes(), options)
            .expect("prior package schema is accepted explicitly");

        assert_eq!(decoded.schema_version(), 1);
        assert_eq!(*decoded.payload(), 42);

        let migrated = decoded
            .try_map_payload(|payload| {
                Ok::<_, std::convert::Infallible>(format!("migrated-{payload}"))
            })
            .expect("infallible payload migration");
        assert_eq!(migrated.schema_version(), 1);
        assert_eq!(migrated.generator_version(), "0.1.0-alpha.1");
        assert_eq!(migrated.binary_sha256().as_str(), DIGEST_A);
        assert_eq!(migrated.payload(), "migrated-42");
    }

    #[test]
    fn schema_v2_requires_explicit_read_compatibility_and_remains_decodable() {
        let bytes = format!(
            "{{\"schema_version\":2,\"generator_version\":\"0.1.0-alpha.2\",\"binary_sha256\":\"{DIGEST_A}\",\"payload\":42}}"
        );
        let error = from_slice::<u64>(bytes.as_bytes())
            .expect_err("the default policy accepts only newly emitted packages");
        assert!(matches!(
            error,
            PackageError::UnsupportedSchema {
                found: 2,
                minimum: CURRENT_SCHEMA_VERSION,
                maximum: CURRENT_SCHEMA_VERSION,
            }
        ));

        let compatibility = SchemaCompatibility::inclusive(1, CURRENT_SCHEMA_VERSION)
            .expect("valid compatibility range");
        let options = PackageOptions::new(1024, compatibility).expect("valid options");
        let decoded = from_slice_with_options::<u64>(bytes.as_bytes(), options)
            .expect("schema 2 is accepted explicitly");

        assert_eq!(decoded.schema_version(), 2);
        assert_eq!(*decoded.payload(), 42);
    }

    #[test]
    fn consistency_helpers_detect_wrong_binary() {
        let package = package();
        let expected = BinaryId::from_sha256(DIGEST_B).expect("valid test digest");
        assert!(matches!(
            package.ensure_binary_id(&expected),
            Err(PackageError::BinaryIdMismatch { .. })
        ));

        let bytes = to_vec(&package).expect("package encodes");
        let error =
            from_slice_checked::<TestPayload, _, _>(&bytes, PackageOptions::default(), |_| {
                Err("content-store digest differs")
            })
            .expect_err("custom check rejects identity");
        assert!(matches!(&error, PackageError::BinaryIdRejected { .. }));
        assert!(error.to_string().contains("content-store digest differs"));
    }

    #[test]
    fn bound_payload_constructor_derives_the_envelope_identity() {
        let payload = BoundPayload {
            binary_id: BinaryId::from_sha256(DIGEST_A).expect("valid test digest"),
            value: 7,
        };
        let package =
            ResymPackage::from_bound_payload("0.1.0", payload).expect("bound package is valid");

        assert_eq!(package.binary_sha256().as_str(), DIGEST_A);
        package
            .ensure_payload_binding()
            .expect("envelope and payload agree");
    }

    #[test]
    fn bound_decode_rejects_envelope_payload_identity_mismatch() {
        let bytes = format!(
            "{{\"schema_version\":3,\"generator_version\":\"0.1.0\",\"binary_sha256\":\"{DIGEST_A}\",\"payload\":{{\"binary_id\":\"{DIGEST_B}\",\"value\":7}}}}"
        );
        let error =
            from_slice_bound::<BoundPayload>(bytes.as_bytes()).expect_err("binding must fail");

        assert!(matches!(
            error,
            PackageError::PayloadBinaryIdMismatch { envelope, payload }
                if envelope.as_str() == DIGEST_A && payload.as_str() == DIGEST_B
        ));
    }

    #[test]
    fn bound_write_rejects_mismatch_before_creating_a_file() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("mismatched.resym");
        let package = ResymPackage::new(
            "0.1.0",
            BinaryId::from_sha256(DIGEST_A).expect("valid test digest"),
            BoundPayload {
                binary_id: BinaryId::from_sha256(DIGEST_B).expect("valid test digest"),
                value: 7,
            },
        )
        .expect("generic constructor permits application-defined payloads");

        let error = write_file_new_bound(&path, &package).expect_err("binding must fail");
        assert!(matches!(
            error,
            PackageError::PayloadBinaryIdMismatch { .. }
        ));
        assert!(!path.exists());
    }

    #[test]
    fn create_new_never_overwrites_existing_file() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("analysis.resym");
        fs::write(&path, b"keep this content").expect("seed existing file");

        let error = write_file_new(&path, &package()).expect_err("overwrite must be refused");
        assert!(matches!(error, PackageError::TargetAlreadyExists { .. }));
        assert_eq!(
            fs::read(&path).expect("read existing file"),
            b"keep this content"
        );
    }

    #[test]
    fn file_round_trip_uses_create_new_and_bounded_read() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("analysis.resym");
        let package = package();

        write_file_new(&path, &package).expect("new package is written");
        let decoded: ResymPackage<TestPayload> = read_file(&path).expect("package is read");
        assert_eq!(decoded, package);

        let error = write_file_new(&path, &package).expect_err("second write is refused");
        assert!(matches!(error, PackageError::TargetAlreadyExists { .. }));
    }

    #[test]
    fn oversized_file_is_rejected() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("oversized.resym");
        fs::write(&path, b"123456789").expect("write oversized fixture");
        let options = PackageOptions::new(8, SchemaCompatibility::current()).expect("valid limit");

        let error = read_file_with_options::<Value>(&path, options)
            .expect_err("oversized file is rejected");
        assert!(matches!(
            error,
            PackageError::InputTooLarge {
                actual: 9,
                maximum: 8,
            }
        ));
    }

    #[test]
    fn invalid_options_are_rejected() {
        assert!(matches!(
            PackageOptions::new(0, SchemaCompatibility::current()),
            Err(PackageError::InvalidSizeLimit)
        ));
        assert!(matches!(
            SchemaCompatibility::inclusive(2, 1),
            Err(PackageError::InvalidSchemaRange {
                minimum: 2,
                maximum: 1,
            })
        ));
    }
}
