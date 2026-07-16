//! Deterministic, exact-RSDS synthetic PDB export for PE images.
//!
//! This first writer deliberately emits only selected public function and
//! global names. It does not invent private symbols, compilands, source lines,
//! types, or function extents. The generated PDB copies the exact GUID and age
//! from one unambiguous `RSDS` record in the original PE so ordinary Windows
//! symbol matching can reject the wrong binary.

use resymbol_analysis::{
    AnalysisSession, BinaryAnalysis, PeAnalysis, PeCodeViewInspection, PeSection,
    inspect_pe_codeview,
};
use resymbol_core::BinaryId;
use thiserror::Error;

use crate::{ExportBinaryFormat, ExportProjection, ProjectionValidationError};

mod msf;
mod streams;

use streams::{PdbPublicSymbol, build_logical_streams};

/// Maximum selected named function/global candidates accepted by one PDB export.
///
/// A same-RVA function/global pair counts twice at this pre-allocation gate,
/// even though the deterministic collision policy emits only the function.
pub const MAX_PDB_PUBLIC_SYMBOLS: usize = streams::MAX_PDB_PUBLIC_SYMBOLS;

/// Failure to render a deterministic public-symbol PDB.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PdbError {
    #[error("the analysis session is invalid: {0}")]
    InvalidSession(#[source] resymbol_analysis::SessionValidationError),
    #[error("the export projection is invalid: {0}")]
    InvalidProjection(#[from] ProjectionValidationError),
    #[error("the exact source PE has no usable CodeView RSDS identity: {0}")]
    SourceInspection(#[source] resymbol_analysis::AnalysisError),
    #[error("PDB export currently supports only PE analysis sessions")]
    UnsupportedAnalysisFormat,
    #[error("PDB export currently supports only PE projections")]
    UnsupportedBinaryFormat,
    #[error("the inspected source PE does not match the analysis session field `{field}`")]
    SourceSessionMismatch { field: &'static str },
    #[error("the projection does not match the analysis session field `{field}`")]
    ProjectionSessionMismatch { field: &'static str },
    #[error("the selected PDB public-symbol candidate limit of {limit} was exceeded")]
    SymbolLimitExceeded { limit: usize },
    #[error("{kind} symbol `{name}` at RVA {rva:#x} is not contained in a PE section")]
    SymbolOutsideSections {
        kind: &'static str,
        name: String,
        rva: u64,
    },
    #[error("cannot encode PDB logical streams: {reason}")]
    LogicalStreamEncoding { reason: String },
    #[error("cannot encode the PDB MSF container: {reason}")]
    MsfEncoding { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SymbolKind {
    Function,
    Global,
}

impl SymbolKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Global => "global",
        }
    }

    const fn is_function(self) -> bool {
        matches!(self, Self::Function)
    }
}

#[derive(Debug)]
struct CandidateSymbol<'projection> {
    rva: u64,
    kind: SymbolKind,
    name: &'projection str,
}

#[derive(Debug, Clone, Copy)]
struct SectionAddress {
    index: u16,
    offset: u32,
}

/// Render one complete deterministic MSF 7.00 PDB without creating a file.
///
/// `source_pe` must contain the exact original PE bytes. The writer hashes them,
/// performs its own strict CodeView inspection, and binds that result to both
/// the validated analysis session and neutral projection before emitting any
/// bytes. It copies the PE's original section-table records byte-for-byte into
/// the PDB section-header stream.
///
/// The output contains `S_PUB32` records only. Function flags distinguish
/// selected function names from selected global names, but no private function
/// record, size, prototype, local, line, compiland, or type information is
/// synthesized.
pub fn render_pdb(
    session: &AnalysisSession,
    projection: &ExportProjection,
    source_pe: &[u8],
) -> Result<Vec<u8>, PdbError> {
    session.validate().map_err(PdbError::InvalidSession)?;
    let BinaryAnalysis::Pe(analysis) = session.base_analysis() else {
        return Err(PdbError::UnsupportedAnalysisFormat);
    };
    if !matches!(projection.binary.format, ExportBinaryFormat::Pe) {
        return Err(PdbError::UnsupportedBinaryFormat);
    }

    let source_size =
        u64::try_from(source_pe.len()).map_err(|_| PdbError::SourceSessionMismatch {
            field: "binary.file_size",
        })?;
    if source_size != analysis.identity.size {
        return Err(PdbError::SourceSessionMismatch {
            field: "binary.file_size",
        });
    }
    if BinaryId::digest(source_pe) != analysis.identity.id {
        return Err(PdbError::SourceSessionMismatch { field: "binary.id" });
    }
    let source = inspect_pe_codeview(source_pe).map_err(PdbError::SourceInspection)?;

    // Enforce the cheap pre-allocation gate before deep validation or symbol
    // collection so an oversized hostile model cannot force writer growth.
    let selected_count = projection
        .functions
        .iter()
        .filter(|value| value.selected_name.is_some())
        .count()
        .checked_add(
            projection
                .globals
                .iter()
                .filter(|value| value.selected_name.is_some())
                .count(),
        )
        .ok_or(PdbError::SymbolLimitExceeded {
            limit: MAX_PDB_PUBLIC_SYMBOLS,
        })?;
    if selected_count > MAX_PDB_PUBLIC_SYMBOLS {
        return Err(PdbError::SymbolLimitExceeded {
            limit: MAX_PDB_PUBLIC_SYMBOLS,
        });
    }

    projection.validate()?;
    validate_projection_binding(analysis, projection)?;
    validate_source_binding(analysis, &source)?;

    let candidates = collect_symbols(projection, selected_count)?;
    let mut publics = Vec::new();
    publics
        .try_reserve_exact(candidates.len())
        .map_err(|_| PdbError::LogicalStreamEncoding {
            reason: "memory allocation failed while collecting public symbols".to_owned(),
        })?;
    for candidate in &candidates {
        let address = section_address(candidate.rva, &analysis.sections).ok_or_else(|| {
            PdbError::SymbolOutsideSections {
                kind: candidate.kind.as_str(),
                name: candidate.name.to_owned(),
                rva: candidate.rva,
            }
        })?;
        publics.push(PdbPublicSymbol {
            name: candidate.name,
            section: address.index,
            offset: address.offset,
            is_function: candidate.kind.is_function(),
        });
    }

    let streams = build_logical_streams(
        source.rsds().guid(),
        source.rsds().age(),
        source.machine(),
        source.section_headers(),
        &publics,
    )
    .map_err(|error| PdbError::LogicalStreamEncoding {
        reason: error.to_string(),
    })?;
    msf::write_msf(&streams).map_err(|error| PdbError::MsfEncoding {
        reason: error.to_string(),
    })
}

fn validate_projection_binding(
    analysis: &PeAnalysis,
    projection: &ExportProjection,
) -> Result<(), PdbError> {
    let identity = &analysis.identity;
    if projection.binary.id != identity.id {
        return Err(PdbError::ProjectionSessionMismatch { field: "binary.id" });
    }
    if projection.binary.file_size != identity.size {
        return Err(PdbError::ProjectionSessionMismatch {
            field: "binary.file_size",
        });
    }
    if projection.binary.image_base != identity.image_base {
        return Err(PdbError::ProjectionSessionMismatch {
            field: "binary.image_base",
        });
    }
    if projection.binary.image_size != u64::from(analysis.size_of_image) {
        return Err(PdbError::ProjectionSessionMismatch {
            field: "binary.image_size",
        });
    }
    if projection.binary.architecture != identity.architecture {
        return Err(PdbError::ProjectionSessionMismatch {
            field: "binary.architecture",
        });
    }
    Ok(())
}

fn validate_source_binding(
    analysis: &PeAnalysis,
    source: &PeCodeViewInspection,
) -> Result<(), PdbError> {
    for (matches, field) in [
        (source.identity().id == analysis.identity.id, "binary.id"),
        (
            source.identity().size == analysis.identity.size,
            "binary.file_size",
        ),
        (
            source.identity().format == analysis.identity.format,
            "binary.format",
        ),
        (
            source.identity().architecture == analysis.identity.architecture,
            "binary.architecture",
        ),
        (
            source.identity().image_base == analysis.identity.image_base,
            "binary.image_base",
        ),
        (source.machine() == analysis.coff.machine, "coff.machine"),
        (
            source.section_headers().len() == analysis.sections.len(),
            "coff.section_count",
        ),
    ] {
        if !matches {
            return Err(PdbError::SourceSessionMismatch { field });
        }
    }

    for (header, section) in source.section_headers().iter().zip(&analysis.sections) {
        if !section_header_matches(header, section) {
            return Err(PdbError::SourceSessionMismatch {
                field: "coff.section_table",
            });
        }
    }
    Ok(())
}

fn section_header_matches(header: &[u8; 40], section: &PeSection) -> bool {
    header[..8] == section.raw_name
        && read_u32(header, 8) == section.virtual_size
        && read_u32(header, 12) == section.virtual_address
        && read_u32(header, 16) == section.raw_data_size
        && read_u32(header, 20) == section.raw_data_offset
        && read_u32(header, 36) == section.characteristics
}

fn read_u32(bytes: &[u8; 40], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed PE section-header field is four bytes"),
    )
}

fn collect_symbols(
    projection: &ExportProjection,
    selected_count: usize,
) -> Result<Vec<CandidateSymbol<'_>>, PdbError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(selected_count)
        .map_err(|_| PdbError::LogicalStreamEncoding {
            reason: "memory allocation failed while planning public symbols".to_owned(),
        })?;
    for function in &projection.functions {
        if let Some(name) = &function.selected_name {
            values.push(CandidateSymbol {
                rva: function.rva,
                kind: SymbolKind::Function,
                name: &name.output_name,
            });
        }
    }
    for global in &projection.globals {
        if let Some(name) = &global.selected_name {
            values.push(CandidateSymbol {
                rva: global.rva,
                kind: SymbolKind::Global,
                name: &name.output_name,
            });
        }
    }
    values.sort_unstable_by(|left, right| {
        (left.rva, left.kind, left.name).cmp(&(right.rva, right.kind, right.name))
    });

    // Function candidates sort before globals and win only when they actually
    // have a selected name. Equal-kind duplicate RVAs are already forbidden by
    // projection validation.
    values.dedup_by_key(|value| value.rva);
    Ok(values)
}

fn section_address(rva: u64, sections: &[PeSection]) -> Option<SectionAddress> {
    sections.iter().enumerate().find_map(|(index, section)| {
        let start = u64::from(section.virtual_address);
        let length = u64::from(section.loaded_size());
        let end = start.checked_add(length)?;
        if !(start..end).contains(&rva) {
            return None;
        }
        Some(SectionAddress {
            index: u16::try_from(index.checked_add(1)?).ok()?,
            offset: u32::try_from(rva.checked_sub(start)?).ok()?,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section() -> PeSection {
        PeSection {
            name: ".text".to_owned(),
            raw_name: *b".text\0\0\0",
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_data_offset: 0x200,
            raw_data_size: 0x200,
            characteristics: 0x6000_0020,
        }
    }

    fn raw_header(section: &PeSection) -> [u8; 40] {
        let mut header = [0_u8; 40];
        header[..8].copy_from_slice(&section.raw_name);
        header[8..12].copy_from_slice(&section.virtual_size.to_le_bytes());
        header[12..16].copy_from_slice(&section.virtual_address.to_le_bytes());
        header[16..20].copy_from_slice(&section.raw_data_size.to_le_bytes());
        header[20..24].copy_from_slice(&section.raw_data_offset.to_le_bytes());
        header[36..40].copy_from_slice(&section.characteristics.to_le_bytes());
        header
    }

    #[test]
    fn source_section_headers_must_match_persisted_address_fields() {
        let section = section();
        let mut header = raw_header(&section);
        assert!(section_header_matches(&header, &section));
        header[12] ^= 1;
        assert!(!section_header_matches(&header, &section));
    }

    #[test]
    fn section_mapping_excludes_raw_alignment_padding() {
        let section = section();
        assert_eq!(
            section_address(0x10ff, std::slice::from_ref(&section))
                .expect("last byte in the loaded section extent")
                .offset,
            0xff
        );
        assert!(section_address(0x1100, std::slice::from_ref(&section)).is_none());
    }
}
