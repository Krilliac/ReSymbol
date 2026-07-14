use resymbol_core::{BinaryIdentity, SymbolGraph};
use serde::{Deserialize, Serialize};

/// A supported, fully parsed binary analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format", content = "analysis", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum BinaryAnalysis {
    Pe(PeAnalysis),
}

impl BinaryAnalysis {
    /// Exact build identity shared by every supported analysis format.
    #[must_use]
    pub const fn identity(&self) -> &BinaryIdentity {
        match self {
            Self::Pe(analysis) => &analysis.identity,
        }
    }

    /// Validated metadata claims shared by every supported analysis format.
    #[must_use]
    pub const fn symbol_graph(&self) -> &SymbolGraph {
        match self {
            Self::Pe(analysis) => &analysis.symbol_graph,
        }
    }

    /// Revalidate the format-specific model and its deterministic base graph.
    pub fn validate(&self) -> Result<(), crate::AnalysisError> {
        match self {
            Self::Pe(analysis) => analysis.validate(),
        }
    }

    /// Virtual image size used to validate address-bearing plugin claims.
    #[must_use]
    pub(crate) const fn image_size(&self) -> u64 {
        match self {
            Self::Pe(analysis) => analysis.size_of_image as u64,
        }
    }
}

/// Deterministic analysis of one PE32+ x86-64 image.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedPeAnalysis")]
pub struct PeAnalysis {
    pub identity: BinaryIdentity,
    /// File offset read from the DOS header's `e_lfanew` field.
    pub pe_header_offset: u32,
    pub coff: CoffHeader,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub directories: PeDataDirectories,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImportLibrary>,
    pub export_library_name: Option<String>,
    pub exports: Vec<PeExport>,
    pub runtime_functions: Vec<RuntimeFunction>,
    /// Validated claims derived solely from exact PE metadata.
    pub symbol_graph: SymbolGraph,
}

impl PeAnalysis {
    /// Validate cross-field invariants and the derived symbol graph.
    pub fn validate(&self) -> Result<(), crate::AnalysisError> {
        crate::pe::validate_pe_analysis(self)
    }

    /// Rebuild the validated graph from the parsed metadata.
    ///
    /// Export names carry exact metadata evidence, while their Function/Global
    /// subject classification is conservative. X64 exception records become
    /// metadata boundary claims. Forwarders, empty EAT slots, and executable
    /// exports without runtime-function metadata are not added to the graph.
    pub fn rebuild_symbol_graph(&self) -> Result<SymbolGraph, crate::AnalysisError> {
        crate::pe::build_symbol_graph(
            &self.identity,
            &self.sections,
            &self.exports,
            &self.runtime_functions,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedPeAnalysis {
    identity: BinaryIdentity,
    pe_header_offset: u32,
    coff: CoffHeader,
    entry_point_rva: u32,
    size_of_image: u32,
    size_of_headers: u32,
    section_alignment: u32,
    file_alignment: u32,
    subsystem: u16,
    dll_characteristics: u16,
    directories: PeDataDirectories,
    sections: Vec<PeSection>,
    imports: Vec<PeImportLibrary>,
    export_library_name: Option<String>,
    exports: Vec<PeExport>,
    runtime_functions: Vec<RuntimeFunction>,
    symbol_graph: SymbolGraph,
}

impl TryFrom<UncheckedPeAnalysis> for PeAnalysis {
    type Error = crate::AnalysisError;

    fn try_from(value: UncheckedPeAnalysis) -> Result<Self, Self::Error> {
        let analysis = Self {
            identity: value.identity,
            pe_header_offset: value.pe_header_offset,
            coff: value.coff,
            entry_point_rva: value.entry_point_rva,
            size_of_image: value.size_of_image,
            size_of_headers: value.size_of_headers,
            section_alignment: value.section_alignment,
            file_alignment: value.file_alignment,
            subsystem: value.subsystem,
            dll_characteristics: value.dll_characteristics,
            directories: value.directories,
            sections: value.sections,
            imports: value.imports,
            export_library_name: value.export_library_name,
            exports: value.exports,
            runtime_functions: value.runtime_functions,
            symbol_graph: value.symbol_graph,
        };
        analysis.validate()?;
        Ok(analysis)
    }
}

/// Fields from the 20-byte COFF file header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub symbol_table_offset: u32,
    pub number_of_symbols: u32,
    pub optional_header_size: u16,
    pub characteristics: u16,
}

/// An RVA and size from the PE optional-header data-directory table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

/// Directories consumed by this ingestion stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeDataDirectories {
    pub exports: Option<DataDirectory>,
    pub imports: Option<DataDirectory>,
    pub exceptions: Option<DataDirectory>,
}

/// One 40-byte PE section-table entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeSection {
    /// A printable, escaped representation of the fixed-width section name.
    pub name: String,
    /// The exact eight bytes from the section header.
    pub raw_name: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_offset: u32,
    pub raw_data_size: u32,
    pub characteristics: u32,
}

/// One imported library and its null-terminated thunk table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeImportLibrary {
    pub name: String,
    pub descriptor_rva: u32,
    pub timestamp: u32,
    pub forwarder_chain: u32,
    pub entries: Vec<PeImport>,
}

/// One import lookup/IAT pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeImport {
    pub lookup_rva: u32,
    pub iat_rva: u32,
    pub target: ImportTarget,
}

/// The two encodings allowed in a PE32+ import thunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ImportTarget {
    Name { hint: u16, name: String },
    Ordinal { ordinal: u16 },
}

/// One export-address-table slot. Empty slots are retained with `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeExport {
    pub ordinal: u32,
    pub address_rva: Option<u32>,
    /// All names attached to this ordinal, in name-pointer-table order.
    pub names: Vec<PeExportName>,
    /// A forwarder string when the address points back into the export directory.
    pub forwarded_to: Option<String>,
}

/// An exact export name and its source-table index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeExportName {
    pub name: String,
    pub name_table_index: u32,
}

/// One x64 `RUNTIME_FUNCTION` record from the exception directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFunction {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
    /// Zero-based position in the exception table. This preserves duplicates.
    pub table_index: u32,
}
