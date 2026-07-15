#![deny(unsafe_code)]

mod bindings {
    #![allow(unsafe_code)]

    wit_bindgen::generate!({
        path: "../../../../../sdk/wit",
        world: "resymbol-plugin",
    });

    use crate::ViolationFixture;

    export!(ViolationFixture);
}

use bindings::exports::resymbol::plugin::guest::Guest;
use bindings::resymbol::plugin::{
    host,
    types::{
        AnalysisRequest, HealthState, Initialization, PluginError, PluginHealth, PluginMetadata,
        SymbolClaim,
    },
};

struct ViolationFixture;

impl Guest for ViolationFixture {
    fn metadata() -> PluginMetadata {
        PluginMetadata {
            id: "dev.resymbol.test.wasm-violations".to_owned(),
            name: "Wasm violation fixture".to_owned(),
            version: "0.0.0".to_owned(),
            capabilities: Vec::new(),
            requested_permissions: vec!["binary.read".to_owned(), "claims.submit".to_owned()],
        }
    }

    fn initialize(context: Initialization) -> Result<(), PluginError> {
        match context.session_id.as_str() {
            "wrong-phase-propagated" => host::submit_claim(&placeholder_claim()),
            "wrong-phase-swallowed" => {
                let _ignored = host::submit_claim(&placeholder_claim());
                Ok(())
            }
            "wrong-phase-then-trap" => {
                let _ignored = host::submit_claim(&placeholder_claim());
                panic!("guest trap after a host-recorded phase violation");
            }
            "ungranted-propagated" => {
                let _bytes = host::read_binary(0, 1)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn analyze(_request: AnalysisRequest) -> Result<(), PluginError> {
        Ok(())
    }

    fn health() -> Result<PluginHealth, PluginError> {
        Ok(PluginHealth {
            state: HealthState::Healthy,
            message: None,
            details_json: None,
        })
    }

    fn shutdown() {}
}

fn placeholder_claim() -> SymbolClaim {
    SymbolClaim {
        subject_json: "{}".to_owned(),
        claim_json: "{}".to_owned(),
        confidence: 0.0,
        evidence: Vec::new(),
    }
}
