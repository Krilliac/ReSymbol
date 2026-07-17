use resymbol_analysis::{AnalysisError, BinaryAnalysis, ElfAnalysis, PeAnalysis};
use resymbol_core::BinaryId;
use serde::Serialize;
use thiserror::Error;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const X64_PAGE_SIZE: u32 = 0x1000;
const MIN_STANDARD_FILE_ALIGNMENT: u32 = 0x200;
const MAX_FILE_ALIGNMENT: u32 = 0x1_0000;

/// An address relative to the beginning of a statically analyzed image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RelativeAddress(u64);

impl RelativeAddress {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One non-empty half-open image-relative range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AddressRange {
    start: RelativeAddress,
    size: u64,
}

impl AddressRange {
    fn checked(start: u64, size: u64) -> Result<Self, StaticAddressSpaceError> {
        if size == 0 {
            return Err(StaticAddressSpaceError::EmptyRegion { start });
        }
        start
            .checked_add(size)
            .ok_or(StaticAddressSpaceError::AddressOverflow { start, size })?;
        Ok(Self {
            start: RelativeAddress::new(start),
            size,
        })
    }

    #[must_use]
    pub const fn start(self) -> RelativeAddress {
        self.start
    }

    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    #[must_use]
    pub const fn end(self) -> u64 {
        self.start.0 + self.size
    }

    #[must_use]
    pub const fn contains(self, address: RelativeAddress) -> bool {
        address.0 >= self.start.0 && address.0 < self.start.0 + self.size
    }
}

/// Static read/write/execute attributes declared for one image range.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MemoryAccess {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl MemoryAccess {
    #[must_use]
    pub const fn is_rwx(self) -> bool {
        self.readable && self.writable && self.executable
    }
}

/// File bytes that initialize the prefix of one mapped image range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FileBacking {
    pub offset: u64,
    pub size: u64,
}

/// Format-specific metadata for one validated static image layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "format", rename_all = "kebab-case")]
pub enum StaticImageLayout {
    Pe {
        section_alignment: u32,
        file_alignment: u32,
    },
    /// Sparse ELF `PT_LOAD` mappings. Virtual gaps are not materialized.
    Elf,
}

impl StaticImageLayout {
    #[must_use]
    pub const fn pe_alignments(self) -> Option<(u32, u32)> {
        match self {
            Self::Pe {
                section_alignment,
                file_alignment,
            } => Some((section_alignment, file_alignment)),
            Self::Elf => None,
        }
    }
}

/// Why a range exists in the static PE image layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StaticRegionKind {
    Headers,
    Section {
        table_index: u32,
        name: String,
        characteristics: u32,
        /// Bytes the section declares as its in-memory content before the
        /// loader rounds the mapping to `SectionAlignment`. When
        /// `VirtualSize` is zero, PE loader-compatible modeling falls back to
        /// `SizeOfRawData`.
        loaded_size: u64,
    },
    /// One sparse ELF `PT_LOAD` mapping. `loaded_size` is the exact
    /// `p_memsz`; file backing, when present, is its `p_filesz` prefix.
    LoadSegment {
        program_header_index: u16,
        flags: u32,
        alignment: u32,
        loaded_size: u64,
    },
    /// An address interval inside `SizeOfImage` that is not claimed by the
    /// declared headers or a section. This is not presented as readable live
    /// memory until a backend reports an actual process mapping.
    ImageGap,
}

/// One exact partition element in a preferred PE image layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaticRegion {
    pub range: AddressRange,
    pub kind: StaticRegionKind,
    pub access: MemoryAccess,
    /// The initialized prefix of this range. Any remainder is either declared
    /// section zero-fill or loader-rounded mapped padding; the accessors below
    /// keep those two cases distinct. Image gaps have no file backing.
    pub file_backing: Option<FileBacking>,
}

impl StaticRegion {
    #[must_use]
    pub fn file_offset_at(&self, address: RelativeAddress) -> Option<u64> {
        let backing = self.file_backing?;
        if !self.range.contains(address) {
            return None;
        }
        let delta = address.get() - self.range.start().get();
        (delta < backing.size).then(|| backing.offset + delta)
    }

    #[must_use]
    pub fn zero_fill_size(&self) -> u64 {
        let loaded_size = match &self.kind {
            StaticRegionKind::Section { loaded_size, .. }
            | StaticRegionKind::LoadSegment { loaded_size, .. } => *loaded_size,
            StaticRegionKind::Headers | StaticRegionKind::ImageGap => return 0,
        };
        loaded_size.saturating_sub(self.file_backing.map_or(0, |backing| backing.size))
    }

    /// Loader-rounded bytes after the declared header or section content.
    ///
    /// These bytes belong to the mapped image partition, but they are not
    /// claimed as file-backed data. In particular, raw file-alignment bytes
    /// beyond a smaller `VirtualSize` are not exposed as initialized memory.
    #[must_use]
    pub fn mapped_padding_size(&self) -> u64 {
        let content_size = match &self.kind {
            StaticRegionKind::Headers => self.file_backing.map_or(0, |backing| backing.size),
            StaticRegionKind::Section { loaded_size, .. } => *loaded_size,
            StaticRegionKind::LoadSegment { loaded_size, .. } => *loaded_size,
            StaticRegionKind::ImageGap => return 0,
        };
        self.range.size().saturating_sub(content_size)
    }
}

/// Validated static image address space.
///
/// PE layouts retain their complete loader-rounded partition. ELF layouts
/// retain only sorted `PT_LOAD` regions so even multi-gigabyte virtual gaps
/// consume no region storage and remain unambiguously unmapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaticAddressSpace {
    pub binary_id: BinaryId,
    pub preferred_image_base: u64,
    pub image_size: u64,
    pub layout: StaticImageLayout,
    pub entry_point: Option<RelativeAddress>,
    regions: Vec<StaticRegion>,
}

impl StaticAddressSpace {
    pub fn from_analysis(analysis: &BinaryAnalysis) -> Result<Self, StaticAddressSpaceError> {
        match analysis {
            BinaryAnalysis::Pe(pe) => Self::from_pe(pe),
            BinaryAnalysis::Elf(elf) => Self::from_elf(elf),
            _ => Err(StaticAddressSpaceError::UnsupportedFormat),
        }
    }

    pub fn from_pe(analysis: &PeAnalysis) -> Result<Self, StaticAddressSpaceError> {
        analysis.validate()?;
        Self::from_validated_pe(analysis)
    }

    pub fn from_elf(analysis: &ElfAnalysis) -> Result<Self, StaticAddressSpaceError> {
        analysis.validate()?;

        let image_size = analysis.image_size;
        let image_base = analysis.identity.image_base;
        image_base.checked_add(image_size).ok_or(
            StaticAddressSpaceError::PreferredImageOverflow {
                base: image_base,
                image_size,
            },
        )?;

        let mut regions = Vec::with_capacity(analysis.load_segments.len());
        let mut cursor = 0_u64;
        for segment in &analysis.load_segments {
            let virtual_address = u64::from(segment.virtual_address);
            let start = virtual_address.checked_sub(image_base).ok_or(
                StaticAddressSpaceError::SegmentBelowImageBase {
                    program_header_index: segment.program_header_index,
                    virtual_address,
                    image_base,
                },
            )?;
            let size = u64::from(segment.memory_size);
            let range = AddressRange::checked(start, size)?;
            let end = range.end();
            if start < cursor {
                return Err(StaticAddressSpaceError::OverlappingRegion { start, cursor });
            }
            if end > image_size {
                return Err(StaticAddressSpaceError::RegionOutsideImage {
                    start,
                    end,
                    image_size,
                });
            }

            let initialized_size = u64::from(segment.file_size);
            let file_offset = u64::from(segment.file_offset);
            let file_end = file_offset.checked_add(initialized_size).ok_or(
                StaticAddressSpaceError::FileBackingOverflow {
                    offset: file_offset,
                    size: initialized_size,
                },
            )?;
            if file_end > analysis.identity.size {
                return Err(StaticAddressSpaceError::FileBackingOutsideBinary {
                    offset: file_offset,
                    size: initialized_size,
                    binary_size: analysis.identity.size,
                });
            }
            let file_backing = (initialized_size != 0).then_some(FileBacking {
                offset: file_offset,
                size: initialized_size,
            });
            regions.push(StaticRegion {
                range,
                kind: StaticRegionKind::LoadSegment {
                    program_header_index: segment.program_header_index,
                    flags: segment.flags,
                    alignment: segment.alignment,
                    loaded_size: size,
                },
                access: MemoryAccess {
                    readable: segment.readable(),
                    writable: segment.writable(),
                    executable: segment.executable(),
                },
                file_backing,
            });
            cursor = end;
        }

        Ok(Self {
            binary_id: analysis.identity.id.clone(),
            preferred_image_base: image_base,
            image_size,
            layout: StaticImageLayout::Elf,
            entry_point: Some(RelativeAddress::new(u64::from(analysis.entry_rva))),
            regions,
        })
    }

    pub(crate) fn from_validated_pe(
        analysis: &PeAnalysis,
    ) -> Result<Self, StaticAddressSpaceError> {
        validate_image_alignment(analysis)?;

        let image_size = u64::from(analysis.size_of_image);
        analysis.identity.image_base.checked_add(image_size).ok_or(
            StaticAddressSpaceError::PreferredImageOverflow {
                base: analysis.identity.image_base,
                image_size,
            },
        )?;
        let header_size = u64::from(analysis.size_of_headers);
        let header_mapped_size = checked_align_up(
            header_size,
            u64::from(analysis.section_alignment),
            "SizeOfHeaders",
        )?;
        if header_mapped_size > image_size {
            return Err(StaticAddressSpaceError::RegionOutsideImage {
                start: 0,
                end: header_mapped_size,
                image_size,
            });
        }

        let mut regions = Vec::with_capacity(analysis.sections.len().saturating_mul(2) + 2);
        regions.push(StaticRegion {
            range: AddressRange::checked(0, header_mapped_size)?,
            kind: StaticRegionKind::Headers,
            access: MemoryAccess {
                readable: true,
                writable: false,
                executable: false,
            },
            file_backing: Some(FileBacking {
                offset: 0,
                size: header_size,
            }),
        });

        let mut sections = analysis.sections.iter().enumerate().collect::<Vec<_>>();
        sections.sort_by_key(|(_, section)| section.virtual_address);
        let mut cursor = header_mapped_size;

        for (table_index, section) in sections {
            let start = u64::from(section.virtual_address);
            let loaded_size = u64::from(section.loaded_size());
            if loaded_size == 0 {
                continue;
            }
            let size = checked_align_up(
                loaded_size,
                u64::from(analysis.section_alignment),
                "section mapped size",
            )?;
            let end = start
                .checked_add(size)
                .ok_or(StaticAddressSpaceError::AddressOverflow { start, size })?;
            if start < cursor {
                return Err(StaticAddressSpaceError::OverlappingRegion { start, cursor });
            }
            if end > image_size {
                return Err(StaticAddressSpaceError::RegionOutsideImage {
                    start,
                    end,
                    image_size,
                });
            }
            if start > cursor {
                regions.push(image_gap(cursor, start - cursor)?);
            }

            let table_index = u32::try_from(table_index).map_err(|_| {
                StaticAddressSpaceError::SectionIndexOverflow { index: table_index }
            })?;
            let initialized_size = u64::from(section.file_backed_size());
            let file_backing = (initialized_size != 0).then_some(FileBacking {
                offset: u64::from(section.raw_data_offset),
                size: initialized_size,
            });
            regions.push(StaticRegion {
                range: AddressRange::checked(start, size)?,
                kind: StaticRegionKind::Section {
                    table_index,
                    name: section.name.clone(),
                    characteristics: section.characteristics,
                    loaded_size,
                },
                access: MemoryAccess {
                    readable: section.characteristics & IMAGE_SCN_MEM_READ != 0,
                    writable: section.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    executable: section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                },
                file_backing,
            });
            cursor = end;
        }

        if cursor < image_size {
            regions.push(image_gap(cursor, image_size - cursor)?);
        }

        let entry_point = (analysis.entry_point_rva != 0)
            .then(|| RelativeAddress::new(u64::from(analysis.entry_point_rva)));
        Ok(Self {
            binary_id: analysis.identity.id.clone(),
            preferred_image_base: analysis.identity.image_base,
            image_size,
            layout: StaticImageLayout::Pe {
                section_alignment: analysis.section_alignment,
                file_alignment: analysis.file_alignment,
            },
            entry_point,
            regions,
        })
    }

    #[must_use]
    pub fn regions(&self) -> &[StaticRegion] {
        &self.regions
    }

    #[must_use]
    pub fn region_at(&self, address: RelativeAddress) -> Option<&StaticRegion> {
        let index = self
            .regions
            .partition_point(|region| region.range.end() <= address.get());
        self.regions
            .get(index)
            .filter(|region| region.range.contains(address))
    }

    #[must_use]
    pub fn preferred_virtual_address(&self, address: RelativeAddress) -> Option<u64> {
        (address.get() < self.image_size)
            .then(|| self.preferred_image_base.checked_add(address.get()))
            .flatten()
    }

    #[must_use]
    pub fn relative_address(&self, preferred_virtual_address: u64) -> Option<RelativeAddress> {
        let rva = preferred_virtual_address.checked_sub(self.preferred_image_base)?;
        (rva < self.image_size).then(|| RelativeAddress::new(rva))
    }

    #[must_use]
    pub fn file_offset_at(&self, address: RelativeAddress) -> Option<u64> {
        self.region_at(address)?.file_offset_at(address)
    }
}

fn validate_image_alignment(analysis: &PeAnalysis) -> Result<(), StaticAddressSpaceError> {
    let section_alignment = analysis.section_alignment;
    let file_alignment = analysis.file_alignment;

    if !section_alignment.is_power_of_two() {
        return Err(StaticAddressSpaceError::InvalidAlignment {
            field: "SectionAlignment",
            value: u64::from(section_alignment),
            requirement: "must be a power of two",
        });
    }
    if !file_alignment.is_power_of_two() {
        return Err(StaticAddressSpaceError::InvalidAlignment {
            field: "FileAlignment",
            value: u64::from(file_alignment),
            requirement: "must be a power of two",
        });
    }
    if section_alignment < file_alignment {
        return Err(StaticAddressSpaceError::InvalidAlignment {
            field: "SectionAlignment",
            value: u64::from(section_alignment),
            requirement: "must be greater than or equal to FileAlignment",
        });
    }
    if !(MIN_STANDARD_FILE_ALIGNMENT..=MAX_FILE_ALIGNMENT).contains(&file_alignment) {
        return Err(StaticAddressSpaceError::InvalidAlignment {
            field: "FileAlignment",
            value: u64::from(file_alignment),
            requirement: "must be between 512 and 65536",
        });
    }
    if section_alignment < X64_PAGE_SIZE && file_alignment != section_alignment {
        return Err(StaticAddressSpaceError::InvalidAlignment {
            field: "FileAlignment",
            value: u64::from(file_alignment),
            requirement: "must equal SectionAlignment for sub-page images",
        });
    }

    require_aligned(
        "SizeOfImage",
        u64::from(analysis.size_of_image),
        u64::from(section_alignment),
    )?;
    require_aligned(
        "SizeOfHeaders",
        u64::from(analysis.size_of_headers),
        u64::from(file_alignment),
    )?;

    for (index, section) in analysis.sections.iter().enumerate() {
        let loaded_size = section.loaded_size();
        if loaded_size != 0 {
            require_section_aligned(
                index,
                "VirtualAddress",
                u64::from(section.virtual_address),
                u64::from(section_alignment),
            )?;
        }
        if section.raw_data_size == 0 {
            continue;
        }
        require_section_aligned(
            index,
            "SizeOfRawData",
            u64::from(section.raw_data_size),
            u64::from(file_alignment),
        )?;
        require_section_aligned(
            index,
            "PointerToRawData",
            u64::from(section.raw_data_offset),
            u64::from(file_alignment),
        )?;
        if section_alignment < X64_PAGE_SIZE && section.raw_data_offset != section.virtual_address {
            return Err(StaticAddressSpaceError::SubPageSectionOffsetMismatch {
                index,
                virtual_address: u64::from(section.virtual_address),
                raw_data_offset: u64::from(section.raw_data_offset),
            });
        }
    }
    Ok(())
}

fn checked_align_up(
    value: u64,
    alignment: u64,
    field: &'static str,
) -> Result<u64, StaticAddressSpaceError> {
    debug_assert_ne!(alignment, 0);
    let remainder = value % alignment;
    if remainder == 0 {
        return Ok(value);
    }
    value
        .checked_add(alignment - remainder)
        .ok_or(StaticAddressSpaceError::AlignmentOverflow {
            field,
            value,
            alignment,
        })
}

fn require_aligned(
    field: &'static str,
    value: u64,
    alignment: u64,
) -> Result<(), StaticAddressSpaceError> {
    if value % alignment == 0 {
        Ok(())
    } else {
        Err(StaticAddressSpaceError::MisalignedImageValue {
            field,
            value,
            alignment,
        })
    }
}

fn require_section_aligned(
    index: usize,
    field: &'static str,
    value: u64,
    alignment: u64,
) -> Result<(), StaticAddressSpaceError> {
    if value % alignment == 0 {
        Ok(())
    } else {
        Err(StaticAddressSpaceError::MisalignedSectionValue {
            index,
            field,
            value,
            alignment,
        })
    }
}

fn image_gap(start: u64, size: u64) -> Result<StaticRegion, StaticAddressSpaceError> {
    Ok(StaticRegion {
        range: AddressRange::checked(start, size)?,
        kind: StaticRegionKind::ImageGap,
        access: MemoryAccess::default(),
        file_backing: None,
    })
}

#[derive(Debug, Error)]
pub enum StaticAddressSpaceError {
    #[error(transparent)]
    InvalidAnalysis(#[from] AnalysisError),
    #[error("the binary format has no static address-space implementation")]
    UnsupportedFormat,
    #[error("static region at RVA {start:#x} is empty")]
    EmptyRegion { start: u64 },
    #[error("static region {start:#x}+{size:#x} overflows the address domain")]
    AddressOverflow { start: u64, size: u64 },
    #[error("preferred image {base:#x}+{image_size:#x} overflows the address domain")]
    PreferredImageOverflow { base: u64, image_size: u64 },
    #[error("invalid PE {field} value {value:#x}: {requirement}")]
    InvalidAlignment {
        field: &'static str,
        value: u64,
        requirement: &'static str,
    },
    #[error("rounding {field} value {value:#x} to {alignment:#x} bytes overflows")]
    AlignmentOverflow {
        field: &'static str,
        value: u64,
        alignment: u64,
    },
    #[error("PE {field} value {value:#x} is not aligned to {alignment:#x} bytes")]
    MisalignedImageValue {
        field: &'static str,
        value: u64,
        alignment: u64,
    },
    #[error("section {index} {field} value {value:#x} is not aligned to {alignment:#x} bytes")]
    MisalignedSectionValue {
        index: usize,
        field: &'static str,
        value: u64,
        alignment: u64,
    },
    #[error(
        "sub-page section {index} maps at RVA {virtual_address:#x} but its raw data begins at {raw_data_offset:#x}"
    )]
    SubPageSectionOffsetMismatch {
        index: usize,
        virtual_address: u64,
        raw_data_offset: u64,
    },
    #[error("static region begins at {start:#x} before the preceding end {cursor:#x}")]
    OverlappingRegion { start: u64, cursor: u64 },
    #[error("static region {start:#x}..{end:#x} is outside SizeOfImage {image_size:#x}")]
    RegionOutsideImage {
        start: u64,
        end: u64,
        image_size: u64,
    },
    #[error("section-table index {index} does not fit the portable model")]
    SectionIndexOverflow { index: usize },
    #[error(
        "ELF PT_LOAD program header {program_header_index} VA {virtual_address:#x} lies below image base {image_base:#x}"
    )]
    SegmentBelowImageBase {
        program_header_index: u16,
        virtual_address: u64,
        image_base: u64,
    },
    #[error("static file backing {offset:#x}+{size:#x} overflows the file-offset domain")]
    FileBackingOverflow { offset: u64, size: u64 },
    #[error("static file backing {offset:#x}+{size:#x} exceeds binary size {binary_size:#x}")]
    FileBackingOutsideBinary {
        offset: u64,
        size: u64,
        binary_size: u64,
    },
}

#[cfg(test)]
mod tests {
    use resymbol_analysis::{BinaryAnalysis, PeAnalysis, PeSection, analyze_bytes};

    use super::{
        FileBacking, RelativeAddress, StaticAddressSpace, StaticAddressSpaceError,
        StaticImageLayout, StaticRegion, StaticRegionKind,
    };

    const FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");

    fn fixture_analysis() -> PeAnalysis {
        let BinaryAnalysis::Pe(pe) = analyze_bytes(FIXTURE).expect("fixture analysis") else {
            panic!("fixture must remain PE")
        };
        pe
    }

    fn layout() -> StaticAddressSpace {
        StaticAddressSpace::from_pe(&fixture_analysis()).expect("validated static layout")
    }

    fn section(
        name: &str,
        virtual_address: u32,
        virtual_size: u32,
        raw_data_offset: u32,
        raw_data_size: u32,
    ) -> PeSection {
        let mut raw_name = [0_u8; 8];
        raw_name[..name.len()].copy_from_slice(name.as_bytes());
        PeSection {
            name: name.to_owned(),
            raw_name,
            virtual_address,
            virtual_size,
            raw_data_offset,
            raw_data_size,
            characteristics: 0x4000_0040,
        }
    }

    fn synthetic_analysis() -> PeAnalysis {
        let mut pe = fixture_analysis();
        pe.identity.image_base = 0x0000_0001_4000_0000;
        pe.size_of_headers = 0x400;
        pe.size_of_image = 0x5000;
        pe.section_alignment = 0x1000;
        pe.file_alignment = 0x200;
        pe.entry_point_rva = 0;
        pe.sections = vec![
            section(".text", 0x1000, 0x801, 0x400, 0xa00),
            section(".bss", 0x2000, 0x601, 0, 0),
            section(".zero", 0x207b, 0, 0xffff_ffff, 0),
            section(".raw", 0x3000, 0, 0xe00, 0x200),
        ];
        pe
    }

    fn synthetic_sparse_elf() -> Vec<u8> {
        const ELF_HEADER_SIZE: usize = 52;
        const PROGRAM_HEADER_SIZE: usize = 32;
        let mut bytes = vec![0_u8; 0x200];
        bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        put_u16(&mut bytes, 16, 2);
        put_u16(&mut bytes, 18, 8);
        put_u32(&mut bytes, 20, 1);
        put_u32(&mut bytes, 24, 0x1200_0040);
        put_u32(&mut bytes, 28, ELF_HEADER_SIZE as u32);
        put_u16(&mut bytes, 40, ELF_HEADER_SIZE as u16);
        put_u16(&mut bytes, 42, PROGRAM_HEADER_SIZE as u16);
        put_u16(&mut bytes, 44, 2);

        put_program_header(
            &mut bytes,
            ELF_HEADER_SIZE,
            TestProgramHeader {
                file_offset: 0,
                virtual_address: 0x1200_0000,
                file_size: 0x100,
                memory_size: 0x200,
                flags: 5,
                alignment: 0x1000,
            },
        );
        put_program_header(
            &mut bytes,
            ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE,
            TestProgramHeader {
                file_offset: 0x180,
                virtual_address: 0xf000_0180,
                file_size: 4,
                memory_size: 0x80,
                flags: 6,
                alignment: 0x10,
            },
        );
        bytes[0x180..0x184].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        bytes
    }

    struct TestProgramHeader {
        file_offset: u32,
        virtual_address: u32,
        file_size: u32,
        memory_size: u32,
        flags: u32,
        alignment: u32,
    }

    fn put_program_header(bytes: &mut [u8], offset: usize, header: TestProgramHeader) {
        put_u32(bytes, offset, 1);
        put_u32(bytes, offset + 4, header.file_offset);
        put_u32(bytes, offset + 8, header.virtual_address);
        put_u32(bytes, offset + 12, header.virtual_address);
        put_u32(bytes, offset + 16, header.file_size);
        put_u32(bytes, offset + 20, header.memory_size);
        put_u32(bytes, offset + 24, header.flags);
        put_u32(bytes, offset + 28, header.alignment);
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn section_region<'a>(layout: &'a StaticAddressSpace, name: &str) -> &'a StaticRegion {
        layout
            .regions()
            .iter()
            .find(|region| {
                matches!(&region.kind, StaticRegionKind::Section { name: actual, .. } if actual == name)
            })
            .expect("named section region")
    }

    #[test]
    fn partitions_the_complete_image_without_overlap_or_holes() {
        let analysis = fixture_analysis();
        let layout = StaticAddressSpace::from_pe(&analysis).expect("fixture layout");
        let mut cursor = 0;
        for region in layout.regions() {
            assert_eq!(region.range.start().get(), cursor);
            assert_ne!(region.range.size(), 0);
            cursor = region.range.end();
            if !matches!(region.kind, StaticRegionKind::ImageGap) {
                assert_eq!(
                    region.range.start().get() % u64::from(analysis.section_alignment),
                    0
                );
                assert_eq!(
                    region.range.end() % u64::from(analysis.section_alignment),
                    0
                );
            }
        }
        assert_eq!(cursor, layout.image_size);
        assert!(matches!(
            layout.regions().first().map(|region| &region.kind),
            Some(StaticRegionKind::Headers)
        ));
    }

    #[test]
    fn maps_preferred_addresses_and_file_backing_without_guessing_gaps() {
        let layout = layout();
        let entry = layout.entry_point.expect("fixture entry point");
        let preferred = layout
            .preferred_virtual_address(entry)
            .expect("preferred entry VA");
        assert_eq!(layout.relative_address(preferred), Some(entry));
        assert!(layout.file_offset_at(entry).is_some());

        let gap = layout
            .regions()
            .iter()
            .find(|region| matches!(region.kind, StaticRegionKind::ImageGap));
        if let Some(gap) = gap {
            assert_eq!(layout.file_offset_at(gap.range.start()), None);
            assert_eq!(gap.zero_fill_size(), 0);
        }
        assert_eq!(
            layout.region_at(RelativeAddress::new(layout.image_size)),
            None
        );
    }

    #[test]
    fn distinguishes_loaded_content_zero_fill_and_loader_padding() {
        let layout =
            StaticAddressSpace::from_validated_pe(&synthetic_analysis()).expect("synthetic layout");
        assert_eq!(
            layout.layout,
            StaticImageLayout::Pe {
                section_alignment: 0x1000,
                file_alignment: 0x200,
            }
        );

        let headers = layout.regions().first().expect("headers");
        assert_eq!(headers.range.size(), 0x1000);
        assert_eq!(
            headers.file_backing,
            Some(FileBacking {
                offset: 0,
                size: 0x400
            })
        );
        assert_eq!(headers.zero_fill_size(), 0);
        assert_eq!(headers.mapped_padding_size(), 0xc00);

        let text = section_region(&layout, ".text");
        assert_eq!(text.range.start().get(), 0x1000);
        assert_eq!(text.range.size(), 0x1000);
        assert_eq!(
            text.file_backing,
            Some(FileBacking {
                offset: 0x400,
                size: 0x801
            })
        );
        assert_eq!(text.zero_fill_size(), 0);
        assert_eq!(text.mapped_padding_size(), 0x7ff);
        assert_eq!(
            layout.file_offset_at(RelativeAddress::new(0x1800)),
            Some(0xc00)
        );
        assert_eq!(layout.file_offset_at(RelativeAddress::new(0x1801)), None);

        let bss = section_region(&layout, ".bss");
        assert_eq!(bss.file_backing, None);
        assert_eq!(bss.zero_fill_size(), 0x601);
        assert_eq!(bss.mapped_padding_size(), 0x9ff);

        let raw_only = section_region(&layout, ".raw");
        assert_eq!(
            raw_only.file_backing,
            Some(FileBacking {
                offset: 0xe00,
                size: 0x200
            })
        );
        assert_eq!(raw_only.zero_fill_size(), 0);
        assert_eq!(raw_only.mapped_padding_size(), 0xe00);
        assert!(!layout.regions().iter().any(
            |region| matches!(&region.kind, StaticRegionKind::Section { name, .. } if name == ".zero")
        ));

        let final_gap = layout.regions().last().expect("trailing image gap");
        assert!(matches!(final_gap.kind, StaticRegionKind::ImageGap));
        assert_eq!(final_gap.range.start().get(), 0x4000);
        assert_eq!(final_gap.range.end(), 0x5000);
    }

    #[test]
    fn supports_sub_page_images_with_matching_file_layout() {
        let mut analysis = synthetic_analysis();
        analysis.section_alignment = 0x200;
        analysis.file_alignment = 0x200;
        analysis.size_of_headers = 0x200;
        analysis.size_of_image = 0x800;
        analysis.sections = vec![
            section(".tiny", 0x200, 0x181, 0x200, 0x200),
            section(".zbss", 0x400, 0x100, 0, 0),
            section(".empty", 7, 0, u32::MAX, 0),
        ];

        let layout = StaticAddressSpace::from_validated_pe(&analysis).expect("small PE layout");
        let tiny = section_region(&layout, ".tiny");
        assert_eq!(tiny.range.size(), 0x200);
        assert_eq!(
            tiny.file_backing,
            Some(FileBacking {
                offset: 0x200,
                size: 0x181
            })
        );
        assert_eq!(tiny.mapped_padding_size(), 0x7f);
        assert_eq!(layout.regions().last().expect("gap").range.end(), 0x800);
    }

    #[test]
    fn retains_sparse_elf_load_segments_without_materializing_large_gaps() {
        let analysis = analyze_bytes(&synthetic_sparse_elf()).expect("synthetic sparse ELF");
        let BinaryAnalysis::Elf(elf) = analysis else {
            panic!("fixture must remain ELF")
        };
        let layout = StaticAddressSpace::from_elf(&elf).expect("sparse ELF layout");

        assert_eq!(layout.layout, StaticImageLayout::Elf);
        assert_eq!(layout.preferred_image_base, 0x1200_0000);
        assert_eq!(layout.regions().len(), 2);
        let first = &layout.regions()[0];
        assert_eq!(first.range.start().get(), 0);
        assert_eq!(first.range.size(), 0x200);
        assert_eq!(first.zero_fill_size(), 0x100);
        assert_eq!(first.mapped_padding_size(), 0);
        assert!(first.access.readable && first.access.executable && !first.access.writable);
        assert!(matches!(
            first.kind,
            StaticRegionKind::LoadSegment {
                program_header_index: 0,
                ..
            }
        ));

        let second = &layout.regions()[1];
        assert_eq!(second.range.start().get(), 0xde00_0180);
        assert_eq!(second.range.size(), 0x80);
        assert_eq!(second.file_backing.map(|backing| backing.size), Some(4));
        assert_eq!(second.zero_fill_size(), 0x7c);
        assert_eq!(layout.region_at(RelativeAddress::new(0x1000)), None);
        assert_eq!(
            layout.region_at(RelativeAddress::new(second.range.start().get())),
            Some(second)
        );
        assert_eq!(layout.entry_point, Some(RelativeAddress::new(0x40)));
    }

    #[test]
    fn rejects_malformed_image_and_section_alignment() {
        let mut analysis = fixture_analysis();
        analysis.file_alignment = 3;
        assert!(matches!(
            StaticAddressSpace::from_pe(&analysis),
            Err(StaticAddressSpaceError::InvalidAnalysis(_))
        ));

        let mut analysis = synthetic_analysis();
        analysis.file_alignment = 0x100;
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&analysis),
            Err(StaticAddressSpaceError::InvalidAlignment {
                field: "FileAlignment",
                ..
            })
        ));

        let mut analysis = synthetic_analysis();
        analysis.size_of_image = 0x4100;
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&analysis),
            Err(StaticAddressSpaceError::MisalignedImageValue {
                field: "SizeOfImage",
                ..
            })
        ));

        let mut analysis = synthetic_analysis();
        analysis.size_of_headers = 0x300;
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&analysis),
            Err(StaticAddressSpaceError::MisalignedImageValue {
                field: "SizeOfHeaders",
                ..
            })
        ));

        let mut analysis = synthetic_analysis();
        analysis.sections[0].virtual_address = 0x1100;
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&analysis),
            Err(StaticAddressSpaceError::MisalignedSectionValue {
                index: 0,
                field: "VirtualAddress",
                ..
            })
        ));

        let mut analysis = synthetic_analysis();
        analysis.sections[0].raw_data_size = 0x901;
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&analysis),
            Err(StaticAddressSpaceError::MisalignedSectionValue {
                index: 0,
                field: "SizeOfRawData",
                ..
            })
        ));

        let mut analysis = synthetic_analysis();
        analysis.sections[0].raw_data_offset = 0x401;
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&analysis),
            Err(StaticAddressSpaceError::MisalignedSectionValue {
                index: 0,
                field: "PointerToRawData",
                ..
            })
        ));

        let mut analysis = synthetic_analysis();
        analysis.section_alignment = 0x800;
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&analysis),
            Err(StaticAddressSpaceError::InvalidAlignment {
                field: "FileAlignment",
                ..
            })
        ));

        let mut analysis = synthetic_analysis();
        analysis.section_alignment = 0x200;
        analysis.file_alignment = 0x200;
        analysis.size_of_headers = 0x200;
        analysis.size_of_image = 0x1000;
        analysis.sections = vec![section(".tiny", 0x200, 0x100, 0x400, 0x200)];
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&analysis),
            Err(StaticAddressSpaceError::SubPageSectionOffsetMismatch { index: 0, .. })
        ));
    }

    #[test]
    fn rejects_loader_rounded_overlap_and_image_overrun() {
        let mut overlap = synthetic_analysis();
        overlap.sections = vec![
            section(".one", 0x1000, 0x1001, 0x400, 0x200),
            section(".two", 0x2000, 0x100, 0x600, 0x200),
        ];
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&overlap),
            Err(StaticAddressSpaceError::OverlappingRegion {
                start: 0x2000,
                cursor: 0x3000,
            })
        ));

        let mut outside = synthetic_analysis();
        outside.size_of_image = 0x4000;
        outside.sections = vec![section(".last", 0x3000, 0x1001, 0x400, 0x200)];
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&outside),
            Err(StaticAddressSpaceError::RegionOutsideImage {
                start: 0x3000,
                end: 0x5000,
                image_size: 0x4000,
            })
        ));
    }

    #[test]
    fn rejects_preferred_address_overflow_before_emitting_regions() {
        let mut analysis = synthetic_analysis();
        analysis.identity.image_base = u64::MAX - 0x1000;
        assert!(matches!(
            StaticAddressSpace::from_validated_pe(&analysis),
            Err(StaticAddressSpaceError::PreferredImageOverflow {
                base,
                image_size: 0x5000,
            }) if base == u64::MAX - 0x1000
        ));
    }
}
