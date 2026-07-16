use std::fmt::Write as _;

use resymbol_analysis::{AnalysisSession, BinaryAnalysis, PeAnalysis, PeSection};
use thiserror::Error;

use crate::{ExportBinaryFormat, ExportProjection, ProjectionValidationError};

/// Maximum UTF-8 byte length accepted for the display module name in a MAP header.
pub const MAX_MAP_MODULE_NAME_BYTES: usize = 255;

/// Maximum number of selected named symbol candidates accepted by one MAP export.
///
/// A same-RVA function/global pair counts twice at this pre-allocation gate,
/// even though the deterministic collision policy emits only the function.
pub const MAX_MAP_SYMBOLS: usize = 262_144;

/// Hard ceiling for generated MAP text.
const MAX_MAP_BYTES: usize = 64 * 1024 * 1024;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

/// Failure to render deterministic Microsoft-linker-style MAP text.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MapError {
    #[error("the analysis session is invalid: {0}")]
    InvalidSession(#[source] resymbol_analysis::SessionValidationError),
    #[error("the export projection is invalid: {0}")]
    InvalidProjection(#[from] ProjectionValidationError),
    #[error("MAP export currently supports only PE analysis sessions")]
    UnsupportedAnalysisFormat,
    #[error("MAP export currently supports only PE projections")]
    UnsupportedBinaryFormat,
    #[error("the projection does not match the analysis session field `{field}`")]
    ProjectionSessionMismatch { field: &'static str },
    #[error(
        "module name must be 1..={MAX_MAP_MODULE_NAME_BYTES} bytes of portable ASCII filename text"
    )]
    InvalidModuleName,
    #[error("the selected MAP symbol candidate limit of {limit} was exceeded")]
    SymbolLimitExceeded { limit: usize },
    #[error("{kind} symbol `{name}` at RVA {rva:#x} is not contained in a PE section")]
    SymbolOutsideSections {
        kind: &'static str,
        name: String,
        rva: u64,
    },
    #[error("the PE entry point at RVA {rva:#x} is not contained in a PE section")]
    EntryPointOutsideSections { rva: u64 },
    #[error("the generated MAP text exceeds {limit} bytes")]
    OutputLimitExceeded { limit: usize },
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
}

#[derive(Debug)]
struct MapSymbol<'projection> {
    rva: u64,
    kind: SymbolKind,
    name: &'projection str,
}

#[derive(Debug, Clone, Copy)]
struct SectionAddress {
    index: usize,
    offset: u32,
}

/// Render deterministic Microsoft-linker-style MAP text without creating a file.
///
/// The field layout follows Microsoft's documented [`/MAP` contract][ms-map]
/// and the concrete x64 formatting used by [LLVM lld's COFF writer][lld-map],
/// which implements the observed `link.exe` format. ReSymbol emits one group for
/// each final PE section because a parsed image has no trustworthy source
/// `.obj`/COMDAT grouping; `<resymbol>` is therefore an explicit synthetic
/// provenance token rather than an invented object filename.
///
/// Only the projection's validated portable `output_name` values are emitted.
/// A named function that is actually emitted wins over a named global at the
/// same RVA, matching the other debugger writers' mutation-aware deterministic
/// collision policy; an unnamed function suppresses nothing. Any named RVA
/// outside a real PE section is rejected instead of being represented as a
/// misleading absolute symbol.
///
/// Exact binary identity is retained in semicolon-prefixed conventional MAP
/// comments. Microsoft's `/MAP` documentation does not specify a comment
/// grammar, so compatibility with a consumer that requires byte-for-byte
/// `link.exe` output must be verified independently.
///
/// [ms-map]: https://learn.microsoft.com/en-us/cpp/build/reference/map-generate-mapfile?view=msvc-170
/// [lld-map]: https://github.com/llvm/llvm-project/blob/454a66a65c66012004b2e1e711247f5ebf729957/lld/COFF/MapFile.cpp
pub fn render_map(
    session: &AnalysisSession,
    projection: &ExportProjection,
    module_name: &str,
) -> Result<String, MapError> {
    validate_module_name(module_name)?;
    session.validate().map_err(MapError::InvalidSession)?;

    let BinaryAnalysis::Pe(analysis) = session.base_analysis() else {
        return Err(MapError::UnsupportedAnalysisFormat);
    };
    if !matches!(projection.binary.format, ExportBinaryFormat::Pe) {
        return Err(MapError::UnsupportedBinaryFormat);
    }

    // Count before deep projection validation so a deliberately oversized
    // package cannot force the writer to allocate or sort an unbounded row set.
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
        .ok_or(MapError::SymbolLimitExceeded {
            limit: MAX_MAP_SYMBOLS,
        })?;
    enforce_symbol_limit(selected_count)?;

    projection.validate()?;
    validate_projection_binding(analysis, projection)?;

    let symbols = collect_symbols(projection);
    let mut mapped_symbols = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        let address = section_address(symbol.rva, &analysis.sections).ok_or_else(|| {
            MapError::SymbolOutsideSections {
                kind: symbol.kind.as_str(),
                name: symbol.name.to_owned(),
                rva: symbol.rva,
            }
        })?;
        mapped_symbols.push((symbol, address));
    }

    let entry_address = if analysis.entry_point_rva == 0 {
        SectionAddress {
            index: 0,
            offset: 0,
        }
    } else {
        section_address(u64::from(analysis.entry_point_rva), &analysis.sections).ok_or(
            MapError::EntryPointOutsideSections {
                rva: u64::from(analysis.entry_point_rva),
            },
        )?
    };

    let mut output = String::new();
    push_format(&mut output, format_args!(" {module_name}\n\n"))?;
    push_format(
        &mut output,
        format_args!(" Timestamp is {:08x}\n\n", analysis.coff.timestamp),
    )?;
    push_format(
        &mut output,
        format_args!(
            " Preferred load address is {:016x}\n\n",
            projection.binary.image_base
        ),
    )?;
    push_format(
        &mut output,
        format_args!(
            "; ReSymbol exact binary SHA-256: {}\n\
             ; ReSymbol exact binary file size: {} bytes\n\
             ; ReSymbol virtual image size: 0x{:x} bytes\n\n",
            projection.binary.id.as_str(),
            projection.binary.file_size,
            projection.binary.image_size,
        ),
    )?;

    push_checked(
        &mut output,
        " Start         Length     Name                   Class\n",
    )?;
    for (zero_based_index, section) in analysis.sections.iter().enumerate() {
        let one_based_index = zero_based_index + 1;
        let length = section.loaded_size();
        let name = escaped_section_name(&section.raw_name);
        let class = section_class(section);
        push_format(
            &mut output,
            format_args!(" {one_based_index:04x}:00000000 {length:08x}H {name:<23} {class}\n"),
        )?;
    }

    push_checked(
        &mut output,
        "\n  Address         Publics by Value              Rva+Base               Lib:Object\n\n",
    )?;
    for (symbol, address) in mapped_symbols {
        let flat_address = projection.binary.image_base.checked_add(symbol.rva).ok_or(
            MapError::ProjectionSessionMismatch {
                field: "binary.image_range",
            },
        )?;
        push_format(
            &mut output,
            format_args!(
                " {:04x}:{:08x}       {:<26} {:016x}     <resymbol>\n",
                address.index, address.offset, symbol.name, flat_address
            ),
        )?;
    }

    push_format(
        &mut output,
        format_args!(
            "\n entry point at         {:04x}:{:08x}\n",
            entry_address.index, entry_address.offset
        ),
    )?;
    Ok(output)
}

fn validate_module_name(value: &str) -> Result<(), MapError> {
    if value.is_empty()
        || value.len() > MAX_MAP_MODULE_NAME_BYTES
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(MapError::InvalidModuleName);
    }
    Ok(())
}

fn enforce_symbol_limit(selected_count: usize) -> Result<(), MapError> {
    if selected_count > MAX_MAP_SYMBOLS {
        return Err(MapError::SymbolLimitExceeded {
            limit: MAX_MAP_SYMBOLS,
        });
    }
    Ok(())
}

fn validate_projection_binding(
    analysis: &PeAnalysis,
    projection: &ExportProjection,
) -> Result<(), MapError> {
    let identity = &analysis.identity;
    if projection.binary.id != identity.id {
        return Err(MapError::ProjectionSessionMismatch { field: "binary.id" });
    }
    if projection.binary.file_size != identity.size {
        return Err(MapError::ProjectionSessionMismatch {
            field: "binary.file_size",
        });
    }
    if projection.binary.image_base != identity.image_base {
        return Err(MapError::ProjectionSessionMismatch {
            field: "binary.image_base",
        });
    }
    if projection.binary.image_size != u64::from(analysis.size_of_image) {
        return Err(MapError::ProjectionSessionMismatch {
            field: "binary.image_size",
        });
    }
    if projection.binary.architecture != identity.architecture {
        return Err(MapError::ProjectionSessionMismatch {
            field: "binary.architecture",
        });
    }
    Ok(())
}

fn collect_symbols(projection: &ExportProjection) -> Vec<MapSymbol<'_>> {
    let mut values = Vec::new();
    for function in &projection.functions {
        if let Some(name) = &function.selected_name {
            values.push(MapSymbol {
                rva: function.rva,
                kind: SymbolKind::Function,
                name: &name.output_name,
            });
        }
    }
    for global in &projection.globals {
        if let Some(name) = &global.selected_name {
            values.push(MapSymbol {
                rva: global.rva,
                kind: SymbolKind::Global,
                name: &name.output_name,
            });
        }
    }
    values.sort_by(|left, right| {
        (left.rva, left.kind, left.name).cmp(&(right.rva, right.kind, right.name))
    });

    // A function is ordered first and is the one retained for an address-kind
    // collision. Equal-kind duplicate RVAs are already forbidden by projection
    // validation.
    values.dedup_by_key(|value| value.rva);
    values
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
            index: index.checked_add(1)?,
            offset: u32::try_from(rva.checked_sub(start)?).ok()?,
        })
    })
}

fn section_class(section: &PeSection) -> &'static str {
    let required = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    if section.characteristics & required == required {
        "CODE"
    } else {
        "DATA"
    }
}

fn escaped_section_name(raw_name: &[u8; 8]) -> String {
    let end = raw_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(raw_name.len());
    if end == 0 {
        return "_x00_".to_owned();
    }

    let mut output = String::new();
    for byte in &raw_name[..end] {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'$' | b'?' | b'@' | b'-') {
            output.push(char::from(*byte));
        } else {
            write!(output, "_x{byte:02x}_").expect("writing to a String cannot fail");
        }
    }
    output
}

fn push_format(output: &mut String, arguments: std::fmt::Arguments<'_>) -> Result<(), MapError> {
    let mut fragment = String::new();
    fragment
        .write_fmt(arguments)
        .expect("writing to a String cannot fail");
    push_checked(output, &fragment)
}

fn push_checked(output: &mut String, value: &str) -> Result<(), MapError> {
    push_checked_with_limit(output, value, MAX_MAP_BYTES)
}

fn push_checked_with_limit(output: &mut String, value: &str, limit: usize) -> Result<(), MapError> {
    if output
        .len()
        .checked_add(value.len())
        .is_none_or(|size| size > limit)
    {
        return Err(MapError::OutputLimitExceeded { limit });
    }
    output.push_str(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_names_are_portably_escaped() {
        assert_eq!(escaped_section_name(b".r data\0"), ".r_x20_data");
        assert_eq!(escaped_section_name(&[0; 8]), "_x00_");
        assert_eq!(escaped_section_name(b".text\0\0\0"), ".text");
    }

    #[test]
    fn section_mapping_uses_the_canonical_loaded_extent() {
        let section = |virtual_size, raw_data_size| PeSection {
            name: ".test".to_owned(),
            raw_name: *b".test\0\0\0",
            virtual_address: 0x1000,
            virtual_size,
            raw_data_offset: 0x200,
            raw_data_size,
            characteristics: IMAGE_SCN_MEM_READ,
        };

        let raw_padding = section(0x100, 0x200);
        assert_eq!(
            section_address(0x10ff, std::slice::from_ref(&raw_padding))
                .expect("last byte declared by VirtualSize")
                .offset,
            0xff
        );
        assert!(section_address(0x1100, std::slice::from_ref(&raw_padding)).is_none());

        let zero_fill = section(0x200, 0x100);
        assert_eq!(
            section_address(0x11ff, std::slice::from_ref(&zero_fill))
                .expect("last byte declared by VirtualSize")
                .offset,
            0x1ff
        );
        assert!(section_address(0x1200, std::slice::from_ref(&zero_fill)).is_none());

        let zero_virtual_size = section(0, 0x200);
        assert_eq!(
            section_address(0x11ff, std::slice::from_ref(&zero_virtual_size))
                .expect("zero VirtualSize falls back to SizeOfRawData")
                .offset,
            0x1ff
        );
    }

    #[test]
    fn fixed_writer_bounds_fail_before_growth() {
        assert!(matches!(
            enforce_symbol_limit(MAX_MAP_SYMBOLS + 1),
            Err(MapError::SymbolLimitExceeded {
                limit: MAX_MAP_SYMBOLS
            })
        ));

        let mut output = "1234".to_owned();
        assert!(matches!(
            push_checked_with_limit(&mut output, "56", 5),
            Err(MapError::OutputLimitExceeded { limit: 5 })
        ));
        assert_eq!(output, "1234");
    }
}
