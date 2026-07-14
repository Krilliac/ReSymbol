use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path, PathBuf},
    str::FromStr,
};

use semver::{Version, VersionReq};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

/// Current on-disk manifest schema.
pub const MANIFEST_VERSION: u32 = 1;

/// Current host/plugin contract version.
pub const PLUGIN_API_VERSION: &str = "0.1.0";

/// Stable reverse-domain plugin identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginId(String);

impl PluginId {
    pub fn new(value: impl Into<String>) -> Result<Self, ManifestValidationError> {
        let value = value.into();
        validate_identifier("plugin id", &value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for PluginId {
    type Err = ManifestValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for PluginId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PluginId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

macro_rules! extensible_manifest_value {
    ($name:ident, $label:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ManifestValidationError> {
                let value = value.into();
                validate_identifier($label, &value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ManifestValidationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

extensible_manifest_value!(PluginCapability, "plugin capability");
extensible_manifest_value!(PluginPermission, "plugin permission");

impl PluginCapability {
    pub const ANALYZER_BINARY: &'static str = "analyzer.binary";
    pub const ANALYZER_RTTI: &'static str = "analyzer.rtti";
    pub const MATCHER_FUNCTIONS: &'static str = "matcher.functions";
    pub const RESOLVER_SYMBOLS: &'static str = "resolver.symbols";
    pub const EXPORTER_SYMBOLS: &'static str = "exporter.symbols";
    pub const BRIDGE_TOOL: &'static str = "bridge.tool";
}

impl PluginPermission {
    pub const BINARY_READ: &'static str = "binary.read";
    pub const SYMBOLS_READ: &'static str = "symbols.read";
    pub const CLAIMS_SUBMIT: &'static str = "claims.submit";
    pub const FILESYSTEM_READ: &'static str = "filesystem.read";
    pub const FILESYSTEM_WRITE: &'static str = "filesystem.write";
    pub const NETWORK_CONNECT: &'static str = "network.connect";
    pub const PROCESS_SPAWN: &'static str = "process.spawn";
    pub const UNSAFE_IN_PROCESS: &'static str = "unsafe.in-process";
}

/// Isolation choice for native plugins. Out-of-process is the safe default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NativeIsolation {
    #[default]
    OutOfProcess,
    InProcess,
}

/// Execution host selected by the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PluginRuntime {
    Wasm {
        entrypoint: PathBuf,
    },
    Native {
        entrypoint: PathBuf,
        #[serde(default)]
        isolation: NativeIsolation,
    },
    Managed {
        entrypoint: PathBuf,
    },
    ExternalProcess {
        entrypoint: PathBuf,
        #[serde(default)]
        args: Vec<String>,
    },
    ToolAdapter {
        tool: String,
        entrypoint: PathBuf,
    },
}

impl PluginRuntime {
    #[must_use]
    pub fn entrypoint(&self) -> &Path {
        match self {
            Self::Wasm { entrypoint }
            | Self::Native { entrypoint, .. }
            | Self::Managed { entrypoint }
            | Self::ExternalProcess { entrypoint, .. }
            | Self::ToolAdapter { entrypoint, .. } => entrypoint,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> PluginRuntimeKind {
        match self {
            Self::Wasm { .. } => PluginRuntimeKind::Wasm,
            Self::Native { .. } => PluginRuntimeKind::Native,
            Self::Managed { .. } => PluginRuntimeKind::Managed,
            Self::ExternalProcess { .. } => PluginRuntimeKind::ExternalProcess,
            Self::ToolAdapter { .. } => PluginRuntimeKind::ToolAdapter,
        }
    }
}

/// Runtime kind without variant-specific configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginRuntimeKind {
    Wasm,
    Native,
    Managed,
    ExternalProcess,
    ToolAdapter,
}

/// Versioned manifest loaded from `plugins/<plugin>/plugin.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    #[serde(default = "default_manifest_version")]
    pub manifest_version: u32,
    pub id: PluginId,
    pub name: String,
    pub version: Version,
    pub api: VersionReq,
    pub runtime: PluginRuntime,
    #[serde(default)]
    pub capabilities: BTreeSet<PluginCapability>,
    #[serde(default)]
    pub permissions: BTreeSet<PluginPermission>,
    #[serde(default)]
    pub dependencies: BTreeMap<PluginId, VersionReq>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
}

const fn default_manifest_version() -> u32 {
    MANIFEST_VERSION
}

impl PluginManifest {
    /// Validate schema invariants that are independent from the host version.
    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(ManifestValidationError::UnsupportedManifestVersion {
                found: self.manifest_version,
                supported: MANIFEST_VERSION,
            });
        }
        if self.name.trim().is_empty() {
            return Err(ManifestValidationError::EmptyField("name"));
        }

        validate_relative_entrypoint(self.runtime.entrypoint())?;

        match &self.runtime {
            PluginRuntime::ToolAdapter { tool, .. } if tool.trim().is_empty() => {
                return Err(ManifestValidationError::EmptyField("runtime.tool"));
            }
            _ => {}
        }

        if matches!(
            &self.runtime,
            PluginRuntime::Native {
                isolation: NativeIsolation::InProcess,
                ..
            }
        ) && !self
            .permissions
            .iter()
            .any(|permission| permission.as_str() == PluginPermission::UNSAFE_IN_PROCESS)
        {
            return Err(ManifestValidationError::MissingInProcessPermission);
        }

        Ok(())
    }

    /// Validate both schema invariants and compatibility with a concrete host.
    pub fn validate_for_host(
        &self,
        host_api: &Version,
    ) -> Result<(), ManifestValidationError> {
        self.validate()?;
        if !self.api.matches(host_api) {
            return Err(ManifestValidationError::IncompatibleApi {
                requirement: self.api.clone(),
                host: host_api.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ManifestValidationError {
    #[error("{field} must not be empty")]
    EmptyField(&'static str),
    #[error("invalid {field} `{value}`: use lowercase dotted identifiers")]
    InvalidIdentifier { field: &'static str, value: String },
    #[error("manifest version {found} is unsupported; this host supports {supported}")]
    UnsupportedManifestVersion { found: u32, supported: u32 },
    #[error("plugin requires API {requirement}, but the host provides {host}")]
    IncompatibleApi {
        requirement: VersionReq,
        host: Version,
    },
    #[error("runtime entrypoint must be a non-empty relative path without parent components")]
    InvalidEntrypoint,
    #[error("in-process native plugins must request the `unsafe.in-process` permission")]
    MissingInProcessPermission,
}

fn validate_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), ManifestValidationError> {
    let valid = (3..=128).contains(&value.len())
        && value.split('.').all(|segment| {
            let first = segment.as_bytes().first().copied();
            let last = segment.as_bytes().last().copied();
            !segment.is_empty()
                && !matches!(first, Some(b'-' | b'_'))
                && !matches!(last, Some(b'-' | b'_'))
                && segment
                    .bytes()
                    .all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || b"-_".contains(&byte)
                    })
        });

    if valid {
        Ok(())
    } else {
        Err(ManifestValidationError::InvalidIdentifier {
            field,
            value: value.to_owned(),
        })
    }
}

fn validate_relative_entrypoint(entrypoint: &Path) -> Result<(), ManifestValidationError> {
    let mut components = entrypoint.components();
    let Some(first) = components.next() else {
        return Err(ManifestValidationError::InvalidEntrypoint);
    };

    let valid_first = matches!(first, Component::Normal(_) | Component::CurDir);
    let valid_rest = components.all(|component| matches!(component, Component::Normal(_)));
    if entrypoint.is_absolute() || !valid_first || !valid_rest {
        return Err(ManifestValidationError::InvalidEntrypoint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(runtime: PluginRuntime) -> PluginManifest {
        PluginManifest {
            manifest_version: MANIFEST_VERSION,
            id: PluginId::new("community.example").expect("valid id"),
            name: "Example".to_owned(),
            version: Version::new(1, 0, 0),
            api: VersionReq::parse("^0.1").expect("valid requirement"),
            runtime,
            capabilities: BTreeSet::new(),
            permissions: BTreeSet::new(),
            dependencies: BTreeMap::new(),
            description: None,
            authors: Vec::new(),
            license: None,
            homepage: None,
        }
    }

    #[test]
    fn identifiers_are_validated_during_deserialization() {
        let error = serde_json::from_str::<PluginId>(r#""Not Valid""#)
            .expect_err("invalid id must fail");
        assert!(error.to_string().contains("lowercase dotted identifiers"));
    }

    #[test]
    fn in_process_native_runtime_requires_explicit_permission() {
        let manifest = manifest(PluginRuntime::Native {
            entrypoint: "plugin.dll".into(),
            isolation: NativeIsolation::InProcess,
        });
        assert_eq!(
            manifest.validate(),
            Err(ManifestValidationError::MissingInProcessPermission)
        );
    }

    #[test]
    fn parent_entrypoint_is_rejected() {
        let manifest = manifest(PluginRuntime::Wasm {
            entrypoint: "../escape.wasm".into(),
        });
        assert_eq!(
            manifest.validate(),
            Err(ManifestValidationError::InvalidEntrypoint)
        );
    }

    #[test]
    fn runtime_serialization_uses_stable_kind_names() {
        let runtime = PluginRuntime::ExternalProcess {
            entrypoint: "worker".into(),
            args: vec!["--stdio".to_owned()],
        };
        let json = serde_json::to_value(runtime).expect("serialize runtime");
        assert_eq!(json["kind"], "external-process");
        assert_eq!(json["entrypoint"], "worker");
    }
}
