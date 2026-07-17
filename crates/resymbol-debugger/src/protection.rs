use resymbol_analysis::{AnalysisError, ImportTarget, PeAnalysis, PeSection};
use resymbol_core::BinaryId;
use serde::Serialize;
use thiserror::Error;

use crate::address_space::{
    RelativeAddress, StaticAddressSpace, StaticAddressSpaceError, StaticRegion, StaticRegionKind,
};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const MIN_ENTROPY_SAMPLE_BYTES: usize = 4 * 1024;
const MAX_ENTROPY_SAMPLE_BYTES: usize = 1024 * 1024;
const HIGH_ENTROPY_MILLIBITS: u16 = 7_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionSeverity {
    Notice,
    Warning,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceStrength {
    /// The artifact itself is exact, while its intent still requires review.
    ExactArtifact,
    StrongHeuristic,
    Heuristic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionKind {
    AntiDebugImport,
    PackerSectionName,
    HighEntropyExecutableSection,
    WritableExecutableSection,
    WritableEntryPointSection,
    EntryPointOutsideSection,
    EntryPointNonExecutableSection,
    EntryPointWithoutFileBacking,
    PreEntryTlsCallback,
    TlsCallbackScanTruncated,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProtectionEvidence {
    Import {
        library: String,
        function: String,
        iat_rva: u32,
        delayed: bool,
    },
    Section {
        table_index: u32,
        name: String,
        rva: u32,
        size: u32,
        characteristics: u32,
    },
    EntropySample {
        table_index: u32,
        name: String,
        sample_bytes: u32,
        /// Shannon entropy in thousandths of a bit per byte.
        entropy_millibits_per_byte: u16,
    },
    EntryPoint {
        rva: u32,
        section_index: u32,
        section_name: String,
    },
    EntryPointLocation {
        rva: u32,
        section_index: Option<u32>,
        section_name: Option<String>,
        file_backed: bool,
        executable: bool,
    },
    TlsCallback {
        table_index: u32,
        callback_rva: u32,
    },
    TlsCallbackCoverage {
        retained_callbacks: u32,
        truncated: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectionFinding {
    pub kind: ProtectionKind,
    pub severity: ProtectionSeverity,
    pub strength: EvidenceStrength,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<ProtectionEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectionReport {
    pub binary_id: BinaryId,
    findings: Vec<ProtectionFinding>,
}

impl ProtectionReport {
    #[must_use]
    pub fn findings(&self) -> &[ProtectionFinding] {
        &self.findings
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Whether opening the target should show a modal acknowledgement before
    /// any live-execution workflow is offered.
    #[must_use]
    pub fn requires_acknowledgement(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity >= ProtectionSeverity::Warning)
    }

    #[must_use]
    pub fn highest_severity(&self) -> Option<ProtectionSeverity> {
        self.findings.iter().map(|finding| finding.severity).max()
    }
}

/// Inspect exact PE metadata and bounded raw section prefixes for protection,
/// packing, and anti-debug artifacts. Findings describe evidence, not proof
/// that a path executes or that a named protection product is present.
pub fn scan_pe_protections(
    analysis: &PeAnalysis,
    bytes: &[u8],
) -> Result<ProtectionReport, ProtectionScanError> {
    analysis.validate()?;
    let actual_size =
        u64::try_from(bytes.len()).map_err(|_| ProtectionScanError::BinarySizeConversion {
            actual: bytes.len(),
        })?;
    if actual_size != analysis.identity.size {
        return Err(ProtectionScanError::BinarySizeMismatch {
            expected: analysis.identity.size,
            actual: actual_size,
        });
    }
    let actual_id = BinaryId::digest(bytes);
    if actual_id != analysis.identity.id {
        return Err(ProtectionScanError::BinaryIdentityMismatch {
            expected: analysis.identity.id.clone(),
            actual: actual_id,
        });
    }

    let layout = StaticAddressSpace::from_pe(analysis)?;
    let mut findings = Vec::new();
    scan_imports(analysis, &mut findings);
    scan_sections(analysis, bytes, &layout, &mut findings)?;
    scan_entry_point(analysis, &layout, &mut findings)?;
    scan_tls_callbacks(analysis, &mut findings)?;
    findings.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.title.cmp(&right.title))
            .then_with(|| left.evidence.cmp(&right.evidence))
    });
    findings.dedup();

    Ok(ProtectionReport {
        binary_id: analysis.identity.id.clone(),
        findings,
    })
}

fn scan_imports(analysis: &PeAnalysis, findings: &mut Vec<ProtectionFinding>) {
    for library in &analysis.imports {
        for entry in &library.entries {
            let ImportTarget::Name { name, .. } = &entry.target else {
                continue;
            };
            if let Some((summary, severity, strength)) =
                anti_debug_import_assessment(&library.name, name)
            {
                let title = if severity == ProtectionSeverity::Notice {
                    format!("Review native process-query import: {name}")
                } else {
                    format!("Debugger-observation import: {name}")
                };
                findings.push(ProtectionFinding {
                    kind: ProtectionKind::AntiDebugImport,
                    severity,
                    strength,
                    title,
                    summary: summary.to_owned(),
                    evidence: vec![ProtectionEvidence::Import {
                        library: library.name.clone(),
                        function: name.clone(),
                        iat_rva: entry.iat_rva,
                        delayed: false,
                    }],
                });
            }
        }
    }
    for library in &analysis.delay_imports {
        for entry in &library.entries {
            let ImportTarget::Name { name, .. } = &entry.target else {
                continue;
            };
            if let Some((summary, severity, strength)) =
                anti_debug_import_assessment(&library.name, name)
            {
                let title = if severity == ProtectionSeverity::Notice {
                    format!("Review delayed native process-query import: {name}")
                } else {
                    format!("Delayed debugger-observation import: {name}")
                };
                findings.push(ProtectionFinding {
                    kind: ProtectionKind::AntiDebugImport,
                    severity,
                    strength,
                    title,
                    summary: summary.to_owned(),
                    evidence: vec![ProtectionEvidence::Import {
                        library: library.name.clone(),
                        function: name.clone(),
                        iat_rva: entry.iat_rva,
                        delayed: true,
                    }],
                });
            }
        }
    }
}

fn anti_debug_import_assessment(
    library: &str,
    name: &str,
) -> Option<(&'static str, ProtectionSeverity, EvidenceStrength)> {
    let kernel32 = library.eq_ignore_ascii_case("kernel32.dll")
        && ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate));
    if kernel32 {
        return Some((
            "The import is a direct debugger-observation primitive. Its presence is exact; whether the target invokes it still requires runtime evidence.",
            ProtectionSeverity::Warning,
            EvidenceStrength::ExactArtifact,
        ));
    }
    if !library.eq_ignore_ascii_case("ntdll.dll") {
        return None;
    }
    if name.eq_ignore_ascii_case("RtlQueryProcessDebugInformation") {
        return Some((
            "This native API directly queries process debug information. Its import is exact, but review call sites before concluding that it implements anti-debug behavior.",
            ProtectionSeverity::Warning,
            EvidenceStrength::StrongHeuristic,
        ));
    }
    ["NtQueryInformationProcess", "ZwQueryInformationProcess"]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
        .then_some((
            "This general native process-query API has many legitimate information classes. Treat the import as a review lead unless call-site evidence shows a debugger-specific query.",
            ProtectionSeverity::Notice,
            EvidenceStrength::Heuristic,
        ))
}

fn scan_sections(
    analysis: &PeAnalysis,
    bytes: &[u8],
    layout: &StaticAddressSpace,
    findings: &mut Vec<ProtectionFinding>,
) -> Result<(), ProtectionScanError> {
    let entry_section_index = layout
        .entry_point
        .and_then(|entry| layout.region_at(entry))
        .and_then(section_table_index);
    for (index, section) in analysis.sections.iter().enumerate() {
        let table_index = u32::try_from(index)
            .map_err(|_| ProtectionScanError::SectionIndexConversion { index })?;
        let span = section.loaded_size();
        let evidence = || ProtectionEvidence::Section {
            table_index,
            name: section.name.clone(),
            rva: section.virtual_address,
            size: span,
            characteristics: section.characteristics,
        };

        let packer = packer_section_assessment(section);
        if let Some((family, severity, strength)) = packer {
            findings.push(ProtectionFinding {
                kind: ProtectionKind::PackerSectionName,
                severity,
                strength,
                title: format!("Packer-style section name: {}", section.name),
                summary: format!(
                    "The exact section name matches a convention associated with {family}. Names are easy to spoof, so this is a heuristic rather than packer confirmation."
                ),
                evidence: vec![evidence()],
            });
        }

        let executable = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let writable = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        if executable && writable {
            findings.push(ProtectionFinding {
                kind: ProtectionKind::WritableExecutableSection,
                severity: ProtectionSeverity::Warning,
                strength: EvidenceStrength::ExactArtifact,
                title: format!("Writable executable section: {}", section.name),
                summary: "The PE section declares both write and execute access. This can support unpacking or self-modifying code, but is not proof that either occurs.".to_owned(),
                evidence: vec![evidence()],
            });
        }

        if executable {
            let initialized_size = u64::from(section.file_backed_size());
            if let Some((sample_bytes, entropy)) =
                section_entropy(section, bytes, initialized_size)?
            {
                if entropy >= HIGH_ENTROPY_MILLIBITS {
                    let corroborated = packer.is_some() || writable;
                    findings.push(ProtectionFinding {
                        kind: ProtectionKind::HighEntropyExecutableSection,
                        severity: if corroborated {
                            ProtectionSeverity::Warning
                        } else {
                            ProtectionSeverity::Notice
                        },
                        strength: if corroborated {
                            EvidenceStrength::StrongHeuristic
                        } else {
                            EvidenceStrength::Heuristic
                        },
                        title: format!("High-entropy executable section: {}", section.name),
                        summary: if corroborated {
                            "A bounded executable-section sample has high entropy and another independent section indicator is present. Compression, encryption, or packed code is plausible, but runtime confirmation is still required.".to_owned()
                        } else {
                            "A bounded executable-section sample has high entropy. Legitimate optimized code or embedded data can produce the same signal, so this alone is a review notice rather than a packing warning.".to_owned()
                        },
                        evidence: vec![ProtectionEvidence::EntropySample {
                            table_index,
                            name: section.name.clone(),
                            sample_bytes,
                            entropy_millibits_per_byte: entropy,
                        }],
                    });
                }
            }
        }

        if writable && entry_section_index == Some(table_index) {
            findings.push(ProtectionFinding {
                kind: ProtectionKind::WritableEntryPointSection,
                severity: ProtectionSeverity::High,
                strength: EvidenceStrength::ExactArtifact,
                title: "Entry point is in a writable section".to_owned(),
                summary: "The declared entry point lies in a section that can be modified at runtime. Treat live execution as high risk and prefer a disposable sandbox.".to_owned(),
                evidence: vec![ProtectionEvidence::EntryPoint {
                    rva: analysis.entry_point_rva,
                    section_index: table_index,
                    section_name: section.name.clone(),
                }],
            });
        }
    }
    Ok(())
}

fn scan_entry_point(
    analysis: &PeAnalysis,
    layout: &StaticAddressSpace,
    findings: &mut Vec<ProtectionFinding>,
) -> Result<(), ProtectionScanError> {
    let rva = analysis.entry_point_rva;
    if rva == 0 {
        return Ok(());
    }

    let address = RelativeAddress::new(u64::from(rva));
    let region = layout.region_at(address);
    let Some((section_index, section_name)) = region.and_then(|region| match &region.kind {
        StaticRegionKind::Section {
            table_index, name, ..
        } => Some((*table_index, name)),
        StaticRegionKind::Headers
        | StaticRegionKind::LoadSegment { .. }
        | StaticRegionKind::ImageGap => None,
    }) else {
        let in_header_mapping =
            region.is_some_and(|region| matches!(&region.kind, StaticRegionKind::Headers));
        let file_backed = layout.file_offset_at(address).is_some();
        let executable = region.is_some_and(|region| region.access.executable);
        findings.push(ProtectionFinding {
            kind: ProtectionKind::EntryPointOutsideSection,
            severity: ProtectionSeverity::High,
            strength: EvidenceStrength::ExactArtifact,
            title: if file_backed {
                "Entry point is inside the PE headers".to_owned()
            } else if in_header_mapping {
                "Entry point is inside loader-rounded PE header padding".to_owned()
            } else {
                "Entry point is outside every declared section".to_owned()
            },
            summary: if file_backed {
                "The declared entry point resolves into the PE header range rather than a section. Treat live execution as anomalous and inspect the exact bytes before proceeding.".to_owned()
            } else if in_header_mapping {
                "The declared entry point resolves into loader-rounded padding in the PE header mapping rather than a section. No initializing file byte exists at that address.".to_owned()
            } else {
                "The declared entry point resolves into an unclaimed image range rather than a section. No file-backed instruction stream can be inferred there from the section table.".to_owned()
            },
            evidence: vec![ProtectionEvidence::EntryPointLocation {
                rva,
                section_index: None,
                section_name: None,
                file_backed,
                executable,
            }],
        });
        return Ok(());
    };

    let region = region.expect("section identity came from the current region");
    let executable = region.access.executable;
    let file_backed = region.file_offset_at(address).is_some();
    let location = || ProtectionEvidence::EntryPointLocation {
        rva,
        section_index: Some(section_index),
        section_name: Some(section_name.clone()),
        file_backed,
        executable,
    };

    if !executable {
        findings.push(ProtectionFinding {
            kind: ProtectionKind::EntryPointNonExecutableSection,
            severity: ProtectionSeverity::High,
            strength: EvidenceStrength::ExactArtifact,
            title: "Entry point is in a non-executable section".to_owned(),
            summary: "The section containing the declared entry point does not declare execute access. This is a malformed or intentionally unusual launch layout that requires review before live execution.".to_owned(),
            evidence: vec![location()],
        });
    }
    if !file_backed {
        findings.push(ProtectionFinding {
            kind: ProtectionKind::EntryPointWithoutFileBacking,
            severity: ProtectionSeverity::High,
            strength: EvidenceStrength::ExactArtifact,
            title: "Entry point has no initializing file bytes".to_owned(),
            summary: "The declared entry point has no initializing file bytes: it lies in section zero-fill or loader-rounded mapped padding. TLS or other pre-entry behavior would have to populate executable bytes before control reaches it.".to_owned(),
            evidence: vec![location()],
        });
    }
    Ok(())
}

fn scan_tls_callbacks(
    analysis: &PeAnalysis,
    findings: &mut Vec<ProtectionFinding>,
) -> Result<(), ProtectionScanError> {
    let retained_callbacks = u32::try_from(analysis.tls_callbacks.len()).map_err(|_| {
        ProtectionScanError::TlsCallbackCountConversion {
            count: analysis.tls_callbacks.len(),
        }
    })?;
    if analysis.tls_callback_scan_truncated {
        findings.push(ProtectionFinding {
            kind: ProtectionKind::TlsCallbackScanTruncated,
            severity: ProtectionSeverity::Warning,
            strength: EvidenceStrength::ExactArtifact,
            title: "TLS callback inventory is incomplete".to_owned(),
            summary: "The bounded TLS callback scan reached its retention limit. Additional callbacks may execute before the ordinary entry point, so a live initial-stop plan must not assume this inventory is complete.".to_owned(),
            evidence: vec![ProtectionEvidence::TlsCallbackCoverage {
                retained_callbacks,
                truncated: true,
            }],
        });
    }
    if analysis.tls_callbacks.is_empty() {
        return Ok(());
    }
    findings.push(ProtectionFinding {
        kind: ProtectionKind::PreEntryTlsCallback,
        severity: ProtectionSeverity::Notice,
        strength: EvidenceStrength::ExactArtifact,
        title: format!("{} TLS callback(s) can run before the entry point", analysis.tls_callbacks.len()),
        summary: "TLS callbacks are legitimate PE metadata but can execute before ordinary entry-point breakpoints. Include them in the initial stop plan for live analysis.".to_owned(),
        evidence: analysis
            .tls_callbacks
            .iter()
            .map(|callback| ProtectionEvidence::TlsCallback {
                table_index: callback.table_index,
                callback_rva: callback.callback_rva,
            })
            .collect(),
    });
    Ok(())
}

fn packer_section_assessment(
    section: &PeSection,
) -> Option<(&'static str, ProtectionSeverity, EvidenceStrength)> {
    let end = section
        .raw_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(section.raw_name.len());
    let name = String::from_utf8_lossy(&section.raw_name[..end]).to_ascii_lowercase();
    match name.as_str() {
        "upx0" | "upx1" | "upx2" | ".upx" => Some((
            "UPX",
            ProtectionSeverity::Warning,
            EvidenceStrength::StrongHeuristic,
        )),
        ".aspack" => Some((
            "ASPack-style layouts",
            ProtectionSeverity::Warning,
            EvidenceStrength::StrongHeuristic,
        )),
        ".adata" => Some((
            "ASPack-style layouts",
            ProtectionSeverity::Notice,
            EvidenceStrength::Heuristic,
        )),
        ".mpress1" | ".mpress2" => Some((
            "MPRESS",
            ProtectionSeverity::Warning,
            EvidenceStrength::StrongHeuristic,
        )),
        ".petite" => Some((
            "Petite",
            ProtectionSeverity::Warning,
            EvidenceStrength::StrongHeuristic,
        )),
        _ => None,
    }
}

fn section_entropy(
    section: &PeSection,
    bytes: &[u8],
    initialized_size: u64,
) -> Result<Option<(u32, u16)>, ProtectionScanError> {
    let initialized_size = usize::try_from(initialized_size).map_err(|_| {
        ProtectionScanError::SectionRangeConversion {
            section: section.name.clone(),
        }
    })?;
    if initialized_size < MIN_ENTROPY_SAMPLE_BYTES {
        return Ok(None);
    }
    let offset = usize::try_from(section.raw_data_offset).map_err(|_| {
        ProtectionScanError::SectionRangeConversion {
            section: section.name.clone(),
        }
    })?;
    let sample_size = initialized_size.min(MAX_ENTROPY_SAMPLE_BYTES);
    let end = offset.checked_add(sample_size).ok_or_else(|| {
        ProtectionScanError::SectionRangeOverflow {
            section: section.name.clone(),
        }
    })?;
    let sample =
        bytes
            .get(offset..end)
            .ok_or_else(|| ProtectionScanError::SectionRangeOutsideBinary {
                section: section.name.clone(),
                offset,
                size: sample_size,
                binary_size: bytes.len(),
            })?;
    let sample_bytes =
        u32::try_from(sample_size).map_err(|_| ProtectionScanError::SectionRangeConversion {
            section: section.name.clone(),
        })?;
    Ok(Some((sample_bytes, entropy_millibits(sample))))
}

fn entropy_millibits(bytes: &[u8]) -> u16 {
    if bytes.is_empty() {
        return 0;
    }
    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }
    let length = bytes.len() as f64;
    let entropy = counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum::<f64>();
    (entropy * 1000.0).round().clamp(0.0, 8000.0) as u16
}

fn section_table_index(region: &StaticRegion) -> Option<u32> {
    match &region.kind {
        StaticRegionKind::Section { table_index, .. } => Some(*table_index),
        StaticRegionKind::Headers
        | StaticRegionKind::LoadSegment { .. }
        | StaticRegionKind::ImageGap => None,
    }
}

#[derive(Debug, Error)]
pub enum ProtectionScanError {
    #[error(transparent)]
    InvalidAnalysis(#[from] AnalysisError),
    #[error(transparent)]
    StaticLayout(#[from] StaticAddressSpaceError),
    #[error("binary length {actual} cannot be represented in the portable model")]
    BinarySizeConversion { actual: usize },
    #[error("binary size mismatch: analysis expects {expected} bytes, received {actual}")]
    BinarySizeMismatch { expected: u64, actual: u64 },
    #[error("binary identity mismatch: analysis expects {expected}, received {actual}")]
    BinaryIdentityMismatch {
        expected: BinaryId,
        actual: BinaryId,
    },
    #[error("section-table index {index} cannot be represented in the protection report")]
    SectionIndexConversion { index: usize },
    #[error("raw range for section {section:?} cannot be represented on this host")]
    SectionRangeConversion { section: String },
    #[error("raw range for section {section:?} overflows")]
    SectionRangeOverflow { section: String },
    #[error(
        "raw range for section {section:?} at {offset:#x}+{size:#x} exceeds binary size {binary_size:#x}"
    )]
    SectionRangeOutsideBinary {
        section: String,
        offset: usize,
        size: usize,
        binary_size: usize,
    },
    #[error("TLS callback count {count} cannot be represented in the protection report")]
    TlsCallbackCountConversion { count: usize },
}

#[cfg(test)]
mod tests {
    use resymbol_analysis::{BinaryAnalysis, PeAnalysis, PeSection, analyze_bytes};

    use crate::address_space::{RelativeAddress, StaticAddressSpace};

    use super::{
        EvidenceStrength, HIGH_ENTROPY_MILLIBITS, ProtectionEvidence, ProtectionKind,
        ProtectionSeverity, anti_debug_import_assessment, entropy_millibits,
        packer_section_assessment, scan_entry_point, scan_pe_protections, scan_sections,
    };

    const FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");

    fn fixture_analysis() -> PeAnalysis {
        let BinaryAnalysis::Pe(pe) = analyze_bytes(FIXTURE).expect("fixture analysis") else {
            panic!("fixture must remain PE")
        };
        pe
    }

    fn text_section(virtual_size: u32, raw_data_size: u32) -> PeSection {
        PeSection {
            name: ".text".to_owned(),
            raw_name: *b".text\0\0\0",
            virtual_address: 0x1000,
            virtual_size,
            raw_data_offset: 0x400,
            raw_data_size,
            characteristics: 0xe000_0020,
        }
    }

    #[test]
    fn exact_fixture_scan_is_deterministic_and_identity_bound() {
        let pe = fixture_analysis();
        let first = scan_pe_protections(&pe, FIXTURE).expect("protection scan");
        let second = scan_pe_protections(&pe, FIXTURE).expect("repeat scan");
        assert_eq!(first, second);
        assert_eq!(first.binary_id, pe.identity.id);

        let mut changed = FIXTURE.to_vec();
        changed[0] ^= 1;
        assert!(scan_pe_protections(&pe, &changed).is_err());
    }

    #[test]
    fn entry_point_uses_canonical_loaded_and_file_backed_section_ranges() {
        let mut pe = fixture_analysis();
        pe.size_of_headers = 0x400;
        pe.size_of_image = 0x6000;
        pe.section_alignment = 0x1000;
        pe.file_alignment = 0x200;
        pe.entry_point_rva = 0x1900;
        pe.coff.number_of_sections = 1;
        pe.sections = vec![text_section(0x801, 0xa00)];

        let layout = StaticAddressSpace::from_validated_pe(&pe).expect("canonical static layout");
        assert_eq!(
            layout.file_offset_at(RelativeAddress::new(0x1800)),
            Some(0xc00)
        );
        assert_eq!(layout.file_offset_at(RelativeAddress::new(0x1801)), None);

        let mut entry_findings = Vec::new();
        scan_entry_point(&pe, &layout, &mut entry_findings).expect("entry scan");
        assert!(
            !entry_findings
                .iter()
                .any(|finding| finding.kind == ProtectionKind::EntryPointOutsideSection)
        );
        let finding = entry_findings
            .iter()
            .find(|finding| finding.kind == ProtectionKind::EntryPointWithoutFileBacking)
            .expect("loader padding must require acknowledgement");
        assert!(matches!(
            finding.evidence.as_slice(),
            [ProtectionEvidence::EntryPointLocation {
                rva: 0x1900,
                section_index: Some(0),
                section_name: Some(name),
                file_backed: false,
                executable: true,
            }] if name == ".text"
        ));

        let mut section_findings = Vec::new();
        scan_sections(&pe, FIXTURE, &layout, &mut section_findings).expect("section scan");
        assert!(
            section_findings
                .iter()
                .any(|finding| finding.kind == ProtectionKind::WritableEntryPointSection)
        );

        pe.entry_point_rva = 0x1100;
        pe.sections = vec![text_section(0, 0x200)];
        let layout =
            StaticAddressSpace::from_validated_pe(&pe).expect("zero-virtual-size fallback layout");
        let mut fallback_findings = Vec::new();
        scan_entry_point(&pe, &layout, &mut fallback_findings).expect("fallback entry scan");
        assert!(fallback_findings.iter().all(|finding| !matches!(
            finding.kind,
            ProtectionKind::EntryPointOutsideSection
                | ProtectionKind::EntryPointNonExecutableSection
                | ProtectionKind::EntryPointWithoutFileBacking
        )));

        pe.entry_point_rva = 0x800;
        pe.sections = vec![text_section(0x200, 0x200)];
        let layout =
            StaticAddressSpace::from_validated_pe(&pe).expect("header-padding static layout");
        let mut header_padding_findings = Vec::new();
        scan_entry_point(&pe, &layout, &mut header_padding_findings)
            .expect("header-padding entry scan");
        let finding = header_padding_findings
            .iter()
            .find(|finding| finding.kind == ProtectionKind::EntryPointOutsideSection)
            .expect("header padding must remain outside every section");
        assert_eq!(
            finding.title,
            "Entry point is inside loader-rounded PE header padding"
        );
        assert!(matches!(
            finding.evidence.as_slice(),
            [ProtectionEvidence::EntryPointLocation {
                rva: 0x800,
                section_index: None,
                section_name: None,
                file_backed: false,
                executable: false,
            }]
        ));
    }

    #[test]
    fn entropy_scan_ignores_unmapped_raw_section_padding() {
        let mut pe = fixture_analysis();
        pe.size_of_headers = 0x400;
        pe.size_of_image = 0x3000;
        pe.section_alignment = 0x1000;
        pe.file_alignment = 0x200;
        pe.entry_point_rva = 0;
        pe.coff.number_of_sections = 1;
        pe.sections = vec![text_section(0x1000, 0x10_0000)];

        let layout = StaticAddressSpace::from_validated_pe(&pe).expect("canonical static layout");
        let mut bytes = vec![0_u8; 0x10_0400];
        for (index, byte) in bytes[0x1400..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        assert!(entropy_millibits(&bytes[0x400..]) >= HIGH_ENTROPY_MILLIBITS);

        let mut findings = Vec::new();
        scan_sections(&pe, &bytes, &layout, &mut findings).expect("section scan");
        assert!(
            findings
                .iter()
                .all(|finding| finding.kind != ProtectionKind::HighEntropyExecutableSection),
            "raw alignment bytes outside VirtualSize are not executable content"
        );
    }

    #[test]
    fn entropy_signal_is_bounded_and_requires_a_high_entropy_sample() {
        assert_eq!(entropy_millibits(&vec![0; 4096]), 0);
        let uniform = (0_u8..=255).cycle().take(4096).collect::<Vec<_>>();
        assert!(entropy_millibits(&uniform) >= HIGH_ENTROPY_MILLIBITS);
    }

    #[test]
    fn anti_debug_and_packer_names_are_case_insensitive_but_narrow() {
        assert!(anti_debug_import_assessment("KERNEL32.dll", "isdebuggerpresent").is_some());
        assert!(anti_debug_import_assessment("user32.dll", "IsDebuggerPresent").is_none());
        assert!(anti_debug_import_assessment("kernel32.dll", "CreateFileW").is_none());
        let (_, severity, strength) =
            anti_debug_import_assessment("ntdll.dll", "NtQueryInformationProcess")
                .expect("generic native query assessment");
        assert_eq!(severity, ProtectionSeverity::Notice);
        assert_eq!(strength, EvidenceStrength::Heuristic);

        let section = |name: [u8; 8]| PeSection {
            name: String::from_utf8_lossy(&name)
                .trim_end_matches('\0')
                .to_owned(),
            raw_name: name,
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_data_offset: 0x400,
            raw_data_size: 0x1000,
            characteristics: 0x6000_0020,
        };
        assert_eq!(
            packer_section_assessment(&section(*b"UPX0\0\0\0\0")),
            Some((
                "UPX",
                ProtectionSeverity::Warning,
                EvidenceStrength::StrongHeuristic,
            ))
        );
        assert_eq!(
            packer_section_assessment(&section(*b".adata\0\0")),
            Some((
                "ASPack-style layouts",
                ProtectionSeverity::Notice,
                EvidenceStrength::Heuristic,
            ))
        );
        assert_eq!(packer_section_assessment(&section(*b".text\0\0\0")), None);
    }
}
