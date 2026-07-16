use std::cmp;

use resymbol_analysis::{AnalysisError, BinaryAnalysis, PeAnalysis};
use resymbol_core::BinaryId;
use serde::Serialize;
use thiserror::Error;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

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

/// Why a range exists in the static PE image layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StaticRegionKind {
    Headers,
    Section {
        table_index: u32,
        name: String,
        characteristics: u32,
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
    /// The initialized prefix of this range. Remaining bytes, if any, are
    /// zero-fill for headers/sections or unbacked for an image gap.
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
        if matches!(&self.kind, StaticRegionKind::ImageGap) {
            return 0;
        }
        self.range
            .size()
            .saturating_sub(self.file_backing.map_or(0, |backing| backing.size))
    }
}

/// Validated, complete partition of one PE preferred image address space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaticAddressSpace {
    pub binary_id: BinaryId,
    pub preferred_image_base: u64,
    pub image_size: u64,
    pub entry_point: Option<RelativeAddress>,
    regions: Vec<StaticRegion>,
}

impl StaticAddressSpace {
    pub fn from_analysis(analysis: &BinaryAnalysis) -> Result<Self, StaticAddressSpaceError> {
        match analysis {
            BinaryAnalysis::Pe(pe) => Self::from_pe(pe),
            _ => Err(StaticAddressSpaceError::UnsupportedFormat),
        }
    }

    pub fn from_pe(analysis: &PeAnalysis) -> Result<Self, StaticAddressSpaceError> {
        analysis.validate()?;

        let image_size = u64::from(analysis.size_of_image);
        analysis.identity.image_base.checked_add(image_size).ok_or(
            StaticAddressSpaceError::PreferredImageOverflow {
                base: analysis.identity.image_base,
                image_size,
            },
        )?;
        let header_size = u64::from(analysis.size_of_headers);
        let mut regions = Vec::with_capacity(analysis.sections.len().saturating_mul(2) + 2);
        regions.push(StaticRegion {
            range: AddressRange::checked(0, header_size)?,
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
        let mut cursor = header_size;

        for (table_index, section) in sections {
            let start = u64::from(section.virtual_address);
            let size = u64::from(cmp::max(section.virtual_size, section.raw_data_size));
            if size == 0 {
                continue;
            }
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
            let file_backing = (section.raw_data_size != 0).then_some(FileBacking {
                offset: u64::from(section.raw_data_offset),
                size: u64::from(section.raw_data_size),
            });
            regions.push(StaticRegion {
                range: AddressRange::checked(start, size)?,
                kind: StaticRegionKind::Section {
                    table_index,
                    name: section.name.clone(),
                    characteristics: section.characteristics,
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
        self.regions
            .iter()
            .find(|region| region.range.contains(address))
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
}

#[cfg(test)]
mod tests {
    use resymbol_analysis::{BinaryAnalysis, analyze_bytes};

    use super::{RelativeAddress, StaticAddressSpace, StaticRegionKind};

    const FIXTURE: &[u8] =
        include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-stripped.exe");

    fn layout() -> StaticAddressSpace {
        let BinaryAnalysis::Pe(pe) = analyze_bytes(FIXTURE).expect("fixture analysis") else {
            panic!("fixture must remain PE")
        };
        StaticAddressSpace::from_pe(&pe).expect("validated static layout")
    }

    #[test]
    fn partitions_the_complete_image_without_overlap_or_holes() {
        let layout = layout();
        let mut cursor = 0;
        for region in layout.regions() {
            assert_eq!(region.range.start().get(), cursor);
            assert_ne!(region.range.size(), 0);
            cursor = region.range.end();
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
}
