#![deny(unsafe_code)]

mod bindings {
    // `wit-bindgen`'s generated canonical-ABI boundary necessarily contains
    // raw exports and unsafe glue. Plugin-authored code remains outside this
    // module under the crate-level `deny(unsafe_code)` policy.
    #![allow(unsafe_code)]

    wit_bindgen::generate!({
        path: "../../../../sdk/wit",
        world: "resymbol-plugin",
    });

    use crate::ExamplePlugin;

    export!(ExamplePlugin);
}

use bindings::exports::resymbol::plugin::guest::Guest;
use bindings::resymbol::plugin::{
    host,
    types::{
        AnalysisRequest, ClaimEvidence, HealthState, Initialization, LogLevel, PluginError,
        PluginHealth, PluginMetadata, SymbolClaim,
    },
};

struct ExamplePlugin;

impl Guest for ExamplePlugin {
    fn metadata() -> PluginMetadata {
        PluginMetadata {
            id: "dev.resymbol.example.wasm-resolver".to_owned(),
            name: "Example WASM Symbol Resolver".to_owned(),
            version: "0.1.0".to_owned(),
            capabilities: vec!["analyzer.binary".to_owned(), "resolver.symbols".to_owned()],
            requested_permissions: vec!["binary.read".to_owned(), "claims.submit".to_owned()],
        }
    }

    fn initialize(context: Initialization) -> Result<(), PluginError> {
        for permission in ["binary.read", "claims.submit"] {
            if !context
                .granted_permissions
                .iter()
                .any(|granted| granted == permission)
            {
                return Err(PluginError::PermissionDenied(format!(
                    "required permission `{permission}` was not granted"
                )));
            }
        }

        host::log(
            LogLevel::Debug,
            "Example WASM resolver initialized without ambient authority.",
        );
        Ok(())
    }

    fn analyze(request: AnalysisRequest) -> Result<(), PluginError> {
        if host::is_cancelled() {
            return Err(PluginError::Cancelled);
        }
        if request.binary.sha256.len() != 64
            || !request
                .binary
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(PluginError::InvalidArgument(
                "binary SHA-256 must be 64 hexadecimal characters".to_owned(),
            ));
        }

        let header = host::read_binary(0, 2)?;
        if header.as_slice() != b"MZ" {
            host::log(
                LogLevel::Warn,
                "Example found no exact DOS MZ signature; no claim was submitted.",
            );
            return Ok(());
        }

        let claim = SymbolClaim {
            subject_json: format!(
                r#"{{"kind":"global","binary":"{}","rva":0,"size":2}}"#,
                request.binary.sha256
            ),
            claim_json: r#"{"kind":"comment","text":"WASM example verified the DOS MZ signature via binary.read."}"#
                .to_owned(),
            confidence: 1.0,
            evidence: vec![ClaimEvidence {
                kind: "binary-read".to_owned(),
                description: "exact image bytes at RVA 0 were 4d 5a".to_owned(),
                data_json: Some(r#"{"rva":0,"bytes":"4d5a"}"#.to_owned()),
            }],
        };
        host::submit_claim(&claim)?;
        host::log(
            LogLevel::Info,
            "Example WASM resolver submitted one exact MZ evidence claim.",
        );
        Ok(())
    }

    fn health() -> Result<PluginHealth, PluginError> {
        Ok(PluginHealth {
            state: HealthState::Healthy,
            message: Some("ready".to_owned()),
            details_json: None,
        })
    }

    fn shutdown() {}
}
