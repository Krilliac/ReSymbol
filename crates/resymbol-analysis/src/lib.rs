//! Safe, bounded binary ingestion for ReSymbol.
//!
//! This crate treats every input byte as untrusted. It does not load or execute
//! binaries, and the PE parser uses checked arithmetic and explicit collection
//! limits throughout.

mod code_recovery;
mod error;
mod msvc_rtti;
mod pe;
mod session;
mod types;

pub use error::AnalysisError;
pub use pe::analyze_pe;
pub use session::{AnalysisSession, PluginRunRecord, PluginRunStatus, SessionValidationError};
pub use types::{
    BinaryAnalysis, CoffHeader, DataDirectory, ImportTarget, MsvcRttiBaseClass, MsvcRttiVftable,
    PeAnalysis, PeControlFlowTarget, PeDataDirectories, PeDirectCall, PeExport, PeExportName,
    PeImport, PeImportLibrary, PeSection, PeThunk, RuntimeFunction,
};

/// Detect and analyze a supported binary container.
///
/// Currently only PE32+ x86-64 images are accepted. Unsupported formats are
/// reported explicitly rather than guessed from a filename.
pub fn analyze_bytes(bytes: &[u8]) -> Result<BinaryAnalysis, AnalysisError> {
    if bytes.starts_with(b"MZ") {
        return analyze_pe(bytes).map(BinaryAnalysis::Pe);
    }

    let magic = bytes
        .get(..bytes.len().min(8))
        .map_or_else(String::new, format_bytes);
    Err(AnalysisError::UnsupportedBinaryFormat { magic })
}

impl resymbol_package::BinaryBoundPayload for BinaryAnalysis {
    fn binary_id(&self) -> &resymbol_core::BinaryId {
        &self.identity().id
    }
}

impl resymbol_package::BinaryBoundPayload for AnalysisSession {
    fn binary_id(&self) -> &resymbol_core::BinaryId {
        &self.base_analysis().identity().id
    }
}

fn format_bytes(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            result.push(' ');
        }
        push_hex_byte(&mut result, *byte);
    }
    result
}

fn push_hex_byte(output: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
}
