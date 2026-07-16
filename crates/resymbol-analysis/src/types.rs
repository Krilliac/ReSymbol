use resymbol_core::{BinaryIdentity, StringEncoding, SymbolGraph};
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
    /// Ordered modern RVA-form delay-load import descriptors.
    ///
    /// Schemas 8 and later serialize this field even when it is empty so the inventory is
    /// an explicit compatibility marker rather than something an older package
    /// can acquire by changing only its envelope version.
    #[serde(default)]
    pub delay_imports: Vec<PeDelayImportLibrary>,
    pub export_library_name: Option<String>,
    pub exports: Vec<PeExport>,
    pub runtime_functions: Vec<RuntimeFunction>,
    /// Size declared by the PE32+ load-configuration structure, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_config_size: Option<u32>,
    /// Checked storage anchors from the PE32+ load-config security prefix.
    ///
    /// Schema 11 serializes this object even when every anchor is absent so
    /// prior packages cannot acquire this recovery result by relabeling.
    #[serde(default)]
    pub load_config_security_anchors: PeLoadConfigSecurityAnchors,
    /// Checked XFG and CastGuard storage anchors from the later PE32+ load-config prefix.
    ///
    /// Schema 12 serializes this object even when every anchor is absent so
    /// prior packages cannot acquire this recovery result by relabeling.
    #[serde(default)]
    pub load_config_xfg_anchors: PeLoadConfigXfgAnchors,
    /// Checked GuardMemcpy pointer-slot anchor from the PE32+ load-config suffix.
    ///
    /// Schema 13 serializes this object even when the anchor is absent so
    /// prior packages cannot acquire this recovery result by relabeling.
    #[serde(default)]
    pub load_config_guard_memcpy_anchor: PeLoadConfigGuardMemcpyAnchor,
    /// Exact `GuardFlags` value when the load configuration is large enough to contain it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_flags: Option<u32>,
    /// RVA of the GuardCF function table after converting its preferred-image VA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_cf_function_table_rva: Option<u32>,
    /// Ordered records from the PE GuardCF function table.
    ///
    /// Schema 9 serializes this inventory even when empty so a legacy package
    /// cannot acquire GuardCF recovery semantics by changing only its envelope.
    #[serde(default)]
    pub guard_cf_functions: Vec<PeGuardCfFunction>,
    /// RVA of the Guard address-taken IAT entry table after converting its preferred-image VA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_address_taken_iat_entry_table_rva: Option<u32>,
    /// Ordered address-taken import slots advertised for CFG export suppression.
    ///
    /// Schema 10 serializes this inventory even when empty so prior packages
    /// cannot acquire this recovery result by changing only their envelope.
    #[serde(default)]
    pub guard_address_taken_iat_entries: Vec<PeGuardAddressTakenIatEntry>,
    /// RVA of the Guard long-jump target table after converting its preferred-image VA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_long_jump_target_table_rva: Option<u32>,
    /// Ordered valid targets from the Guard long-jump table.
    ///
    /// Schema 10 serializes this inventory even when empty.
    #[serde(default)]
    pub guard_long_jump_targets: Vec<PeGuardLongJumpTarget>,
    /// RVA of the Guard EH-continuation table after converting its preferred-image VA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_eh_continuation_table_rva: Option<u32>,
    /// Ordered valid exception-handling continuation targets.
    ///
    /// Schema 10 serializes this inventory even when empty.
    #[serde(default)]
    pub guard_eh_continuation_targets: Vec<PeGuardEhContinuationTarget>,
    /// RVA of the callback pointer array named by the TLS directory, when nonzero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_callback_table_rva: Option<u32>,
    /// Whether the TLS callback array had more entries than the fixed retention cap.
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls_callback_scan_truncated: bool,
    /// Ordered, non-null entries from the PE32+ TLS callback array.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_callbacks: Vec<PeTlsCallback>,
    /// Whether bounded instruction decoding stopped before every eligible candidate was checked.
    #[serde(default, skip_serializing_if = "is_false")]
    pub code_recovery_scan_truncated: bool,
    /// Canonical direct calls decoded from fully file-backed x64 runtime-function ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_calls: Vec<PeDirectCall>,
    /// Canonical one-instruction jump thunks decoded from metadata-backed function candidates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thunks: Vec<PeThunk>,
    /// Whether bounded initialized-data scanning stopped before every eligible byte was checked.
    #[serde(default, skip_serializing_if = "is_false")]
    pub string_recovery_scan_truncated: bool,
    /// Canonical NUL-terminated strings recovered from fully file-backed PE data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<PeRecoveredString>,
    /// Whether bounded instruction decoding could not retain or inspect every data reference.
    #[serde(default, skip_serializing_if = "is_false")]
    pub data_reference_scan_truncated: bool,
    /// Canonical x64 RIP-relative references from runtime-function code to PE data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_references: Vec<PeDataReference>,
    /// Whether RTTI discovery stopped after its fixed read-only-data scan budget.
    #[serde(default, skip_serializing_if = "is_false")]
    pub msvc_rtti_scan_truncated: bool,
    /// Validated MSVC x64 Rev1 RTTI records discovered through vftable back-pointers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub msvc_rtti_vftables: Vec<MsvcRttiVftable>,
    /// Validated claims derived from exact PE metadata and bounded supported instruction encodings.
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
    /// metadata boundary claims; executable local exports and the backed entry
    /// point become function candidates. Bounded control-flow recovery adds
    /// lower-confidence edge and target-entry claims. Forwarders and empty EAT
    /// slots are not added to the graph.
    pub fn rebuild_symbol_graph(&self) -> Result<SymbolGraph, crate::AnalysisError> {
        crate::pe::build_symbol_graph(crate::pe::SymbolGraphInput {
            identity: &self.identity,
            entry_point_rva: self.entry_point_rva,
            sections: &self.sections,
            exports: &self.exports,
            runtime_functions: &self.runtime_functions,
            load_config_rva: self.directories.load_config.map(|directory| directory.rva),
            guard_flags: self.guard_flags,
            guard_cf_function_table_rva: self.guard_cf_function_table_rva,
            guard_cf_functions: &self.guard_cf_functions,
            tls_directory_rva: self.directories.tls.map(|directory| directory.rva),
            tls_callback_table_rva: self.tls_callback_table_rva,
            tls_callbacks: &self.tls_callbacks,
            direct_calls: &self.direct_calls,
            thunks: &self.thunks,
            strings: &self.strings,
            data_references: &self.data_references,
            msvc_rtti_vftables: &self.msvc_rtti_vftables,
        })
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
    #[serde(default)]
    delay_imports: Vec<PeDelayImportLibrary>,
    export_library_name: Option<String>,
    exports: Vec<PeExport>,
    runtime_functions: Vec<RuntimeFunction>,
    #[serde(default)]
    load_config_size: Option<u32>,
    #[serde(default)]
    load_config_security_anchors: PeLoadConfigSecurityAnchors,
    #[serde(default)]
    load_config_xfg_anchors: PeLoadConfigXfgAnchors,
    #[serde(default)]
    load_config_guard_memcpy_anchor: PeLoadConfigGuardMemcpyAnchor,
    #[serde(default)]
    guard_flags: Option<u32>,
    #[serde(default)]
    guard_cf_function_table_rva: Option<u32>,
    #[serde(default)]
    guard_cf_functions: Vec<PeGuardCfFunction>,
    #[serde(default)]
    guard_address_taken_iat_entry_table_rva: Option<u32>,
    #[serde(default)]
    guard_address_taken_iat_entries: Vec<PeGuardAddressTakenIatEntry>,
    #[serde(default)]
    guard_long_jump_target_table_rva: Option<u32>,
    #[serde(default)]
    guard_long_jump_targets: Vec<PeGuardLongJumpTarget>,
    #[serde(default)]
    guard_eh_continuation_table_rva: Option<u32>,
    #[serde(default)]
    guard_eh_continuation_targets: Vec<PeGuardEhContinuationTarget>,
    #[serde(default)]
    tls_callback_table_rva: Option<u32>,
    #[serde(default)]
    tls_callback_scan_truncated: bool,
    #[serde(default)]
    tls_callbacks: Vec<PeTlsCallback>,
    #[serde(default)]
    code_recovery_scan_truncated: bool,
    #[serde(default)]
    direct_calls: Vec<PeDirectCall>,
    #[serde(default)]
    thunks: Vec<PeThunk>,
    #[serde(default)]
    string_recovery_scan_truncated: bool,
    #[serde(default)]
    strings: Vec<PeRecoveredString>,
    #[serde(default)]
    data_reference_scan_truncated: bool,
    #[serde(default)]
    data_references: Vec<PeDataReference>,
    #[serde(default)]
    msvc_rtti_scan_truncated: bool,
    #[serde(default)]
    msvc_rtti_vftables: Vec<MsvcRttiVftable>,
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
            delay_imports: value.delay_imports,
            export_library_name: value.export_library_name,
            exports: value.exports,
            runtime_functions: value.runtime_functions,
            load_config_size: value.load_config_size,
            load_config_security_anchors: value.load_config_security_anchors,
            load_config_xfg_anchors: value.load_config_xfg_anchors,
            load_config_guard_memcpy_anchor: value.load_config_guard_memcpy_anchor,
            guard_flags: value.guard_flags,
            guard_cf_function_table_rva: value.guard_cf_function_table_rva,
            guard_cf_functions: value.guard_cf_functions,
            guard_address_taken_iat_entry_table_rva: value.guard_address_taken_iat_entry_table_rva,
            guard_address_taken_iat_entries: value.guard_address_taken_iat_entries,
            guard_long_jump_target_table_rva: value.guard_long_jump_target_table_rva,
            guard_long_jump_targets: value.guard_long_jump_targets,
            guard_eh_continuation_table_rva: value.guard_eh_continuation_table_rva,
            guard_eh_continuation_targets: value.guard_eh_continuation_targets,
            tls_callback_table_rva: value.tls_callback_table_rva,
            tls_callback_scan_truncated: value.tls_callback_scan_truncated,
            tls_callbacks: value.tls_callbacks,
            code_recovery_scan_truncated: value.code_recovery_scan_truncated,
            direct_calls: value.direct_calls,
            thunks: value.thunks,
            string_recovery_scan_truncated: value.string_recovery_scan_truncated,
            strings: value.strings,
            data_reference_scan_truncated: value.data_reference_scan_truncated,
            data_references: value.data_references,
            msvc_rtti_scan_truncated: value.msvc_rtti_scan_truncated,
            msvc_rtti_vftables: value.msvc_rtti_vftables,
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
    /// PE optional-header data-directory entry 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_config: Option<DataDirectory>,
    /// PE optional-header data-directory entry 9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<DataDirectory>,
    /// PE optional-header data-directory entry 13.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_imports: Option<DataDirectory>,
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

/// Canonical image-loader view of one PE section.
///
/// This stays crate-private so the serialized section-header model remains the
/// public API while every analysis path agrees on which bytes are loaded and
/// which loaded bytes are initialized from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeSectionLayout {
    pub(crate) loaded_size: u32,
    pub(crate) file_backed_size: u32,
}

impl PeSection {
    /// Derive the section spans used by the PE loader and RVA-to-file mapping.
    pub(crate) const fn layout(&self) -> PeSectionLayout {
        let loaded_size = if self.virtual_size == 0 {
            self.raw_data_size
        } else {
            self.virtual_size
        };
        let file_backed_size = if self.raw_data_size < loaded_size {
            self.raw_data_size
        } else {
            loaded_size
        };
        PeSectionLayout {
            loaded_size,
            file_backed_size,
        }
    }
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

/// One modern RVA-form `ImgDelayDescr` and its null-terminated INT/IAT pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeDelayImportLibrary {
    pub name: String,
    pub descriptor_rva: u32,
    /// Exact descriptor attributes. The supported modern form is `dlattrRva` (`1`).
    pub attributes: u32,
    /// RVA of the descriptor's NUL-terminated DLL name.
    pub name_rva: u32,
    /// RVA of the delay-load helper's module-handle storage.
    ///
    /// Ingestion requires a nonzero RVA and eight fully file-backed bytes but
    /// deliberately leaves the stored value and section permissions opaque.
    pub module_handle_rva: u32,
    /// RVA of the delay import address table.
    pub iat_rva: u32,
    /// RVA of the delay import name table.
    pub int_rva: u32,
    /// Optional RVA of the bound delay import address table.
    pub bound_iat_rva: Option<u32>,
    /// Optional RVA of the unload copy of the original delay IAT.
    pub unload_iat_rva: Option<u32>,
    pub timestamp: u32,
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

/// One non-null entry from an x64 PE TLS callback pointer array.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeTlsCallback {
    /// Zero-based position in the callback pointer array.
    pub table_index: u32,
    /// RVA obtained by subtracting the preferred image base from the slot's VA.
    pub callback_rva: u32,
}

/// Checked storage RVAs advertised by the PE32+ load-config security prefix.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeLoadConfigSecurityAnchors {
    /// RVA of the eight-byte Visual C++ `/GS` security-cookie storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_cookie_rva: Option<u32>,
    /// RVA of the eight-byte slot patched with the GuardCF check function pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_cf_check_function_pointer_rva: Option<u32>,
    /// RVA of the eight-byte slot patched with the GuardCF dispatch function pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_cf_dispatch_function_pointer_rva: Option<u32>,
}

impl PeLoadConfigSecurityAnchors {
    /// Whether the load-config prefix advertises no nonzero security anchor.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.security_cookie_rva.is_none()
            && self.guard_cf_check_function_pointer_rva.is_none()
            && self.guard_cf_dispatch_function_pointer_rva.is_none()
    }
}

/// Checked storage RVAs advertised by the PE32+ load-config XFG/CastGuard suffix.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeLoadConfigXfgAnchors {
    /// RVA of the eight-byte slot patched with the XFG check function pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_xfg_check_function_pointer_rva: Option<u32>,
    /// RVA of the eight-byte slot patched with the XFG dispatch function pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_xfg_dispatch_function_pointer_rva: Option<u32>,
    /// RVA of the eight-byte slot patched with the XFG table-dispatch function pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_xfg_table_dispatch_function_pointer_rva: Option<u32>,
    /// RVA of the eight-byte CastGuard OS-determined failure-mode storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cast_guard_os_determined_failure_mode_rva: Option<u32>,
}

impl PeLoadConfigXfgAnchors {
    /// Whether the load-config suffix advertises no nonzero XFG/CastGuard anchor.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.guard_xfg_check_function_pointer_rva.is_none()
            && self.guard_xfg_dispatch_function_pointer_rva.is_none()
            && self.guard_xfg_table_dispatch_function_pointer_rva.is_none()
            && self.cast_guard_os_determined_failure_mode_rva.is_none()
    }
}

/// Checked GuardMemcpy pointer-slot RVA advertised by the PE32+ load-config suffix.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeLoadConfigGuardMemcpyAnchor {
    /// RVA of the eight-byte loader-managed GuardMemcpy function-pointer slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_memcpy_function_pointer_rva: Option<u32>,
}

impl PeLoadConfigGuardMemcpyAnchor {
    /// Whether the load-config suffix advertises no nonzero GuardMemcpy pointer slot.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.guard_memcpy_function_pointer_rva.is_none()
    }
}

/// One record from the PE Guard Control Flow function table (GFIDS).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeGuardCfFunction {
    /// Zero-based position in the strictly sorted GFIDS table.
    pub table_index: u32,
    /// Exact four-byte RVA stored at the start of the record.
    pub rva: u32,
    /// Exact optional metadata bytes selected by the high nibble of `GuardFlags`.
    pub metadata: Vec<u8>,
}

impl PeGuardCfFunction {
    /// Whether the defined `IMAGE_GUARD_FLAG_FID_SUPPRESSED` bit is set.
    #[must_use]
    pub fn is_fid_suppressed(&self) -> bool {
        self.metadata.first().is_some_and(|flags| flags & 0x01 != 0)
    }

    /// Whether the defined `IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED` bit is set.
    #[must_use]
    pub fn is_export_suppressed(&self) -> bool {
        self.metadata.first().is_some_and(|flags| flags & 0x02 != 0)
    }
}

/// One record from the Guard address-taken IAT entry table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeGuardAddressTakenIatEntry {
    /// Zero-based position in the strictly sorted source table.
    pub table_index: u32,
    /// Exact RVA of the parsed import-address-table slot.
    pub iat_rva: u32,
    /// Exact reserved metadata bytes selected by the high nibble of `GuardFlags`.
    pub metadata: Vec<u8>,
}

/// One valid target from the Guard long-jump table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeGuardLongJumpTarget {
    /// Zero-based position in the strictly sorted source table.
    pub table_index: u32,
    /// Exact executable target RVA stored in the record.
    pub target_rva: u32,
    /// Exact reserved metadata bytes selected by the high nibble of `GuardFlags`.
    pub metadata: Vec<u8>,
}

/// One valid target from the Guard EH-continuation table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeGuardEhContinuationTarget {
    /// Zero-based position in the strictly sorted source table.
    pub table_index: u32,
    /// Exact executable continuation RVA stored at the start of the record.
    pub target_rva: u32,
    /// Exact reserved metadata bytes selected by the high nibble of `GuardFlags`.
    pub metadata: Vec<u8>,
}

/// A statically resolved target used by the bounded PE control-flow model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PeControlFlowTarget {
    /// A file-backed executable address in the current image.
    Function { rva: u32 },
    /// An exact slot from the parsed PE import address table.
    ImportIat { iat_rva: u32 },
    /// A file-backed executable address read from one exact read-only pointer slot.
    FunctionPointer { slot_rva: u32, rva: u32 },
}

/// One exact statically resolved call decoded inside an x64 `RUNTIME_FUNCTION` range.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeDirectCall {
    /// Start RVA of the containing runtime-function record.
    pub caller_rva: u32,
    pub call_site_rva: u32,
    pub instruction_size: u8,
    pub target: PeControlFlowTarget,
}

/// A candidate function whose first instruction is an exact unconditional jump.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeThunk {
    pub rva: u32,
    pub instruction_size: u8,
    pub target: PeControlFlowTarget,
}

/// PE analysis name for the core's canonical recovered-string encoding.
pub type PeStringEncoding = StringEncoding;

/// One bounded string literal recovered from fully file-backed PE section data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeRecoveredString {
    pub rva: u32,
    /// Encoded content plus its trailing NUL terminator, in bytes.
    pub byte_size: u32,
    pub encoding: PeStringEncoding,
    /// Canonical UTF-8 representation of the recovered content.
    pub value: String,
}

/// One exact x64 RIP-relative reference to data in the current image.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeDataReference {
    /// Start RVA of the containing runtime-function record.
    pub caller_rva: u32,
    pub instruction_rva: u32,
    pub instruction_size: u8,
    pub target_rva: u32,
}

/// One validated MSVC x64 vftable and its Rev1 RTTI metadata.
///
/// The vftable starts at `rva`; the preceding pointer-sized slot refers to the
/// complete object locator. Virtual function entries remain in source order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsvcRttiVftable {
    pub rva: u32,
    pub complete_object_locator_rva: u32,
    pub type_descriptor_rva: u32,
    pub class_hierarchy_descriptor_rva: u32,
    pub base_class_array_rva: u32,
    pub offset: u32,
    pub constructor_displacement_offset: u32,
    pub decorated_class_name: String,
    pub class_name: String,
    pub hierarchy_attributes: u32,
    pub base_classes: Vec<MsvcRttiBaseClass>,
    pub virtual_function_rvas: Vec<u32>,
}

/// One base-class descriptor from an MSVC RTTI base-class array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsvcRttiBaseClass {
    pub array_index: u32,
    pub descriptor_rva: u32,
    pub type_descriptor_rva: u32,
    pub decorated_name: String,
    pub name: String,
    pub num_contained_bases: u32,
    pub member_displacement: i32,
    pub vbtable_displacement: i32,
    pub displacement_inside_vbtable: i32,
    pub attributes: u32,
    pub class_hierarchy_descriptor_rva: Option<u32>,
}

const fn is_false(value: &bool) -> bool {
    !*value
}
