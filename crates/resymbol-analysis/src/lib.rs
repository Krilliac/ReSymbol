//! Safe, bounded binary ingestion for ReSymbol.
//!
//! This crate treats every input byte as untrusted. It does not load or execute
//! binaries, and each container parser uses checked arithmetic and explicit
//! collection limits throughout.

mod code_recovery;
mod elf;
mod error;
mod instruction;
mod linear_disassembly;
mod msvc_rtti;
mod pe;
mod session;
mod string_recovery;
mod types;

pub use elf::{ElfMachine, analyze_elf};
pub use error::AnalysisError;
pub use instruction::{
    ExactX64InstructionError, MAX_X64_INSTRUCTION_BYTES, validate_exact_x64_instruction,
};
pub use linear_disassembly::{
    LinearDisassemblyError, LinearDisassemblyLimits, LinearDisassemblyPreview,
    LinearDisassemblyStopReason, LinearFlowControlCategory, LinearInstructionRow,
    LinearTruncationBoundary, MAX_LINEAR_DISASSEMBLY_BYTES, MAX_LINEAR_DISASSEMBLY_INSTRUCTIONS,
    disassemble_x64_linear,
};
pub use pe::{
    PeCodeViewInspection, PeCodeViewRsds, PeLayoutInspection, analyze_pe, inspect_pe_codeview,
    inspect_pe_layout,
};
pub use session::{AnalysisSession, PluginRunRecord, PluginRunStatus, SessionValidationError};
pub use types::{
    BinaryAnalysis, CoffHeader, DataDirectory, ElfAnalysis, ElfClass, ElfEndian, ElfLoadSegment,
    ElfProgramHeader, ElfSectionHeader, ElfSymbol, ImportTarget, MsvcRttiBaseClass,
    MsvcRttiVftable, PeAnalysis, PeControlFlowTarget, PeDataDirectories, PeDataReference,
    PeDelayImportLibrary, PeDirectCall, PeExport, PeExportName, PeGuardAddressTakenIatEntry,
    PeGuardCfFunction, PeGuardEhContinuationTarget, PeGuardLongJumpTarget, PeImport,
    PeImportLibrary, PeLoadConfigGuardMemcpyAnchor, PeLoadConfigSecurityAnchors,
    PeLoadConfigXfgAnchors, PeRecoveredString, PeSection, PeStringEncoding, PeThunk, PeTlsCallback,
    RuntimeFunction,
};

/// Detect and analyze a supported binary container.
///
/// PE32+ x86-64 images and bounded ELF containers are accepted. ELF ingestion
/// covers ELF32 and ELF64, either byte order, and any `e_machine` value;
/// container parsing is machine-independent and records only bounded metadata,
/// sparse `PT_LOAD` mappings, and symbol-table name claims. Unsupported formats
/// are reported explicitly rather than guessed from a filename.
pub fn analyze_bytes(bytes: &[u8]) -> Result<BinaryAnalysis, AnalysisError> {
    if bytes.starts_with(b"MZ") {
        return analyze_pe(bytes).map(BinaryAnalysis::Pe);
    }
    if bytes.starts_with(b"\x7fELF") {
        return analyze_elf(bytes).map(BinaryAnalysis::Elf);
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
