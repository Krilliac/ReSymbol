use std::{
    fs::{self, File},
    io::{Read, Take},
    path::Path,
};

use resymbol_core::{BinaryId, BinaryIdentity};
use thiserror::Error;

use crate::{
    bootstrap::{NativeHostBootstrap, PeImageMap, PeImageSection},
    error::HostError,
};

pub(crate) const MAX_READ_BINARY_CALL_BYTES: usize = 1024 * 1024;
const HARD_MAX_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
const DOS_HEADER_SIZE: usize = 64;
const MAX_PE_HEADER_OFFSET: u32 = 16 * 1024 * 1024;
const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const OPTIONAL_HEADER_MIN_SIZE: usize = 112;
const DATA_DIRECTORY_SIZE: usize = 8;
const SECTION_HEADER_SIZE: usize = 40;
const MAX_SECTIONS: usize = 96;
const MAX_DATA_DIRECTORIES: usize = 16;
const MACHINE_AMD64: u16 = 0x8664;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x020b;

#[derive(Debug)]
pub(crate) struct ExactBinaryImage {
    bytes: Vec<u8>,
    size_of_headers: u32,
    size_of_image: u32,
    sections: Vec<crate::bootstrap::PeImageSection>,
}

impl ExactBinaryImage {
    #[cfg(test)]
    pub(crate) fn test_empty() -> Self {
        Self {
            bytes: vec![0; 1],
            size_of_headers: 1,
            size_of_image: 1,
            sections: Vec::new(),
        }
    }

    pub(crate) fn open_verified(
        path: &Path,
        bootstrap: &NativeHostBootstrap,
    ) -> Result<Self, HostError> {
        let expected_size = bootstrap.binary.size;
        if expected_size > HARD_MAX_BINARY_BYTES {
            return Err(HostError::Binary(format!(
                "{} bytes exceed the native host's {HARD_MAX_BINARY_BYTES}-byte binary limit",
                expected_size
            )));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| HostError::io("inspect exact source binary", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HostError::Binary(
                "source binary must be a regular, unlinked file".to_owned(),
            ));
        }
        if metadata.len() != expected_size {
            return Err(HostError::Binary(format!(
                "source size {} does not match expected {expected_size}",
                metadata.len()
            )));
        }

        let capacity = usize::try_from(expected_size)
            .map_err(|_| HostError::Binary("source size does not fit this host".to_owned()))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| {
            HostError::Binary("cannot reserve memory for the exact source binary".to_owned())
        })?;
        let file =
            File::open(path).map_err(|error| HostError::io("open exact source binary", error))?;
        read_exact_bounded(file.take(expected_size.saturating_add(1)), &mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != expected_size {
            return Err(HostError::Binary(
                "source binary changed while it was being read".to_owned(),
            ));
        }
        if BinaryId::digest(&bytes) != bootstrap.binary.id {
            return Err(HostError::Binary(
                "source SHA-256 does not match the analysis identity".to_owned(),
            ));
        }
        verify_exact_pe_metadata(&bytes, &bootstrap.binary, &bootstrap.image)?;
        let after = fs::symlink_metadata(path)
            .map_err(|error| HostError::io("reinspect exact source binary", error))?;
        if after.file_type().is_symlink() || !after.is_file() || after.len() != expected_size {
            return Err(HostError::Binary(
                "source binary changed while it was being verified".to_owned(),
            ));
        }

        Ok(Self {
            bytes,
            size_of_headers: bootstrap.image.size_of_headers,
            size_of_image: bootstrap.image.size_of_image,
            sections: bootstrap.image.sections.clone(),
        })
    }

    pub(crate) fn read_rva(
        &self,
        rva: u64,
        destination: &mut [u8],
    ) -> Result<usize, ImageReadError> {
        if destination.len() > MAX_READ_BINARY_CALL_BYTES {
            return Err(ImageReadError::Limit);
        }
        let rva = u32::try_from(rva).map_err(|_| ImageReadError::OutsideImage)?;
        if rva >= self.size_of_image {
            return Err(ImageReadError::OutsideImage);
        }
        if destination.is_empty() {
            return Ok(0);
        }

        if rva < self.size_of_headers {
            let start = usize::try_from(rva).map_err(|_| ImageReadError::OutsideImage)?;
            let header_remaining = usize::try_from(self.size_of_headers - rva)
                .map_err(|_| ImageReadError::OutsideImage)?;
            return copy_available(&self.bytes, start, header_remaining, destination);
        }

        let Some(section) = self.sections.iter().find(|section| {
            let start = u64::from(section.virtual_address);
            let size = u64::from(section.virtual_size.max(section.raw_data_size));
            (start..start.saturating_add(size)).contains(&u64::from(rva))
        }) else {
            return Ok(0);
        };
        let delta = rva
            .checked_sub(section.virtual_address)
            .ok_or(ImageReadError::OutsideImage)?;
        if delta >= section.raw_data_size {
            return Ok(0);
        }
        let start = u64::from(section.raw_data_offset)
            .checked_add(u64::from(delta))
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(ImageReadError::OutsideImage)?;
        let available = usize::try_from(section.raw_data_size - delta)
            .map_err(|_| ImageReadError::OutsideImage)?;
        copy_available(&self.bytes, start, available, destination)
    }
}

fn verify_exact_pe_metadata(
    bytes: &[u8],
    identity: &BinaryIdentity,
    expected: &PeImageMap,
) -> Result<(), HostError> {
    let parsed = parse_pe_image(bytes)?;
    if parsed.image_base != identity.image_base {
        return invalid_binary("PE image base does not match the analysis identity");
    }
    if parsed.image != *expected {
        return invalid_binary("PE header/section map does not match the exact source bytes");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedPeImage {
    image_base: u64,
    image: PeImageMap,
}

fn parse_pe_image(bytes: &[u8]) -> Result<ParsedPeImage, HostError> {
    if read_bytes(bytes, 0, 2, "DOS signature")? != b"MZ" {
        return invalid_binary("source does not have an MZ signature");
    }
    read_bytes(bytes, 0, DOS_HEADER_SIZE, "DOS header")?;
    let pe_offset_u32 = read_u32(bytes, 0x3c, "DOS e_lfanew")?;
    if !(u32::try_from(DOS_HEADER_SIZE).unwrap_or(u32::MAX)..=MAX_PE_HEADER_OFFSET)
        .contains(&pe_offset_u32)
    {
        return invalid_binary("DOS e_lfanew is outside the supported range");
    }
    let pe_offset = usize::try_from(pe_offset_u32)
        .map_err(|_| HostError::Binary("PE header offset does not fit this host".to_owned()))?;
    if read_bytes(bytes, pe_offset, PE_SIGNATURE_SIZE, "PE signature")? != b"PE\0\0" {
        return invalid_binary("source does not have a PE signature");
    }

    let coff_offset = checked_add(pe_offset, PE_SIGNATURE_SIZE, "COFF header offset")?;
    read_bytes(bytes, coff_offset, COFF_HEADER_SIZE, "COFF header")?;
    if read_u16(bytes, coff_offset, "COFF machine")? != MACHINE_AMD64 {
        return invalid_binary("PE machine is not AMD64");
    }
    let section_count = usize::from(read_u16(bytes, coff_offset + 2, "COFF section count")?);
    if section_count > MAX_SECTIONS {
        return invalid_binary("PE exceeds the 96-section native-host limit");
    }
    let optional_size = usize::from(read_u16(
        bytes,
        coff_offset + 16,
        "COFF optional-header size",
    )?);
    if optional_size < OPTIONAL_HEADER_MIN_SIZE {
        return invalid_binary("PE32+ optional header is too small");
    }
    let optional_offset = checked_add(coff_offset, COFF_HEADER_SIZE, "optional-header offset")?;
    read_bytes(
        bytes,
        optional_offset,
        optional_size,
        "PE32+ optional header",
    )?;
    if read_u16(bytes, optional_offset, "optional-header magic")? != OPTIONAL_MAGIC_PE32_PLUS {
        return invalid_binary("source does not use the PE32+ optional header");
    }

    let image_base = read_u64(bytes, optional_offset + 24, "PE image base")?;
    let section_alignment = read_u32(bytes, optional_offset + 32, "section alignment")?;
    let file_alignment = read_u32(bytes, optional_offset + 36, "file alignment")?;
    if section_alignment == 0 || file_alignment == 0 {
        return invalid_binary("PE section/file alignment must be nonzero");
    }
    let size_of_image = read_u32(bytes, optional_offset + 56, "size of image")?;
    let size_of_headers = read_u32(bytes, optional_offset + 60, "size of headers")?;
    if size_of_headers == 0 || size_of_image == 0 || size_of_headers > size_of_image {
        return invalid_binary("PE header and image sizes are inconsistent");
    }
    let headers_size = usize::try_from(size_of_headers)
        .map_err(|_| HostError::Binary("PE header size does not fit this host".to_owned()))?;
    read_bytes(bytes, 0, headers_size, "declared PE headers")?;

    let directory_count = usize::try_from(read_u32(
        bytes,
        optional_offset + 108,
        "data-directory count",
    )?)
    .map_err(|_| HostError::Binary("PE directory count does not fit this host".to_owned()))?;
    if directory_count > MAX_DATA_DIRECTORIES {
        return invalid_binary("PE exceeds the 16-data-directory native-host limit");
    }
    let required_optional_size = checked_add(
        OPTIONAL_HEADER_MIN_SIZE,
        checked_mul(
            directory_count,
            DATA_DIRECTORY_SIZE,
            "data-directory table size",
        )?,
        "required optional-header size",
    )?;
    if optional_size < required_optional_size {
        return invalid_binary("PE optional header truncates its data-directory table");
    }

    let sections_offset = checked_add(optional_offset, optional_size, "section-table offset")?;
    let section_table_size = checked_mul(section_count, SECTION_HEADER_SIZE, "section-table size")?;
    let section_table_end = checked_add(sections_offset, section_table_size, "section-table end")?;
    if section_table_end > headers_size {
        return invalid_binary("PE section table extends beyond the declared headers");
    }
    read_bytes(
        bytes,
        sections_offset,
        section_table_size,
        "PE section table",
    )?;

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = checked_add(
            sections_offset,
            checked_mul(index, SECTION_HEADER_SIZE, "section-header position")?,
            "section-header offset",
        )?;
        let section = PeImageSection {
            virtual_size: read_u32(bytes, offset + 8, "section virtual size")?,
            virtual_address: read_u32(bytes, offset + 12, "section virtual address")?,
            raw_data_size: read_u32(bytes, offset + 16, "section raw-data size")?,
            raw_data_offset: read_u32(bytes, offset + 20, "section raw-data offset")?,
        };
        validate_parsed_section(bytes, size_of_headers, size_of_image, index, &section)?;
        sections.push(section);
    }
    validate_section_overlaps(&sections)?;

    Ok(ParsedPeImage {
        image_base,
        image: PeImageMap {
            size_of_headers,
            size_of_image,
            sections,
        },
    })
}

fn validate_parsed_section(
    bytes: &[u8],
    size_of_headers: u32,
    size_of_image: u32,
    index: usize,
    section: &PeImageSection,
) -> Result<(), HostError> {
    let virtual_size = section.virtual_size.max(section.raw_data_size);
    let virtual_end = section
        .virtual_address
        .checked_add(virtual_size)
        .ok_or_else(|| HostError::Binary(format!("PE section {index} virtual range overflows")))?;
    if virtual_end > size_of_image
        || (virtual_size != 0 && section.virtual_address < size_of_headers)
    {
        return invalid_binary(format!("PE section {index} has an invalid virtual range"));
    }

    let raw_end = section
        .raw_data_offset
        .checked_add(section.raw_data_size)
        .ok_or_else(|| HostError::Binary(format!("PE section {index} file range overflows")))?;
    if usize::try_from(raw_end).map_or(true, |end| end > bytes.len())
        || (section.raw_data_size != 0 && section.raw_data_offset < size_of_headers)
    {
        return invalid_binary(format!("PE section {index} has an invalid file range"));
    }
    Ok(())
}

fn validate_section_overlaps(sections: &[PeImageSection]) -> Result<(), HostError> {
    for first in 0..sections.len() {
        for second in first + 1..sections.len() {
            let left = &sections[first];
            let right = &sections[second];
            if ranges_overlap(
                left.virtual_address,
                left.virtual_size.max(left.raw_data_size),
                right.virtual_address,
                right.virtual_size.max(right.raw_data_size),
            )? {
                return invalid_binary(format!(
                    "PE sections {first} and {second} overlap in virtual memory"
                ));
            }
            if ranges_overlap(
                left.raw_data_offset,
                left.raw_data_size,
                right.raw_data_offset,
                right.raw_data_size,
            )? {
                return invalid_binary(format!(
                    "PE sections {first} and {second} overlap in the source file"
                ));
            }
        }
    }
    Ok(())
}

fn ranges_overlap(
    left_start: u32,
    left_size: u32,
    right_start: u32,
    right_size: u32,
) -> Result<bool, HostError> {
    if left_size == 0 || right_size == 0 {
        return Ok(false);
    }
    let left_end = left_start
        .checked_add(left_size)
        .ok_or_else(|| HostError::Binary("PE section range overflows".to_owned()))?;
    let right_end = right_start
        .checked_add(right_size)
        .ok_or_else(|| HostError::Binary("PE section range overflows".to_owned()))?;
    Ok(left_start < right_end && right_start < left_end)
}

fn read_bytes<'a>(
    bytes: &'a [u8],
    offset: usize,
    size: usize,
    label: &str,
) -> Result<&'a [u8], HostError> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| HostError::Binary(format!("{label} range overflows")))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| HostError::Binary(format!("source truncates {label}")))
}

fn read_u16(bytes: &[u8], offset: usize, label: &str) -> Result<u16, HostError> {
    let mut value = [0_u8; 2];
    value.copy_from_slice(read_bytes(bytes, offset, 2, label)?);
    Ok(u16::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32, HostError> {
    let mut value = [0_u8; 4];
    value.copy_from_slice(read_bytes(bytes, offset, 4, label)?);
    Ok(u32::from_le_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize, label: &str) -> Result<u64, HostError> {
    let mut value = [0_u8; 8];
    value.copy_from_slice(read_bytes(bytes, offset, 8, label)?);
    Ok(u64::from_le_bytes(value))
}

fn checked_add(left: usize, right: usize, label: &str) -> Result<usize, HostError> {
    left.checked_add(right)
        .ok_or_else(|| HostError::Binary(format!("{label} overflows")))
}

fn checked_mul(left: usize, right: usize, label: &str) -> Result<usize, HostError> {
    left.checked_mul(right)
        .ok_or_else(|| HostError::Binary(format!("{label} overflows")))
}

fn invalid_binary<T>(message: impl Into<String>) -> Result<T, HostError> {
    Err(HostError::Binary(message.into()))
}

fn read_exact_bounded(mut source: Take<File>, destination: &mut Vec<u8>) -> Result<(), HostError> {
    source
        .read_to_end(destination)
        .map_err(|error| HostError::io("read exact source binary", error))?;
    Ok(())
}

fn copy_available(
    source: &[u8],
    start: usize,
    available: usize,
    destination: &mut [u8],
) -> Result<usize, ImageReadError> {
    let source_remaining = source
        .len()
        .checked_sub(start)
        .ok_or(ImageReadError::OutsideImage)?;
    let count = available.min(source_remaining).min(destination.len());
    destination[..count].copy_from_slice(&source[start..start + count]);
    Ok(count)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ImageReadError {
    #[error("RVA lies outside the verified image")]
    OutsideImage,
    #[error("one read exceeds the native callback byte limit")]
    Limit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use resymbol_core::{BinaryFormat, BinaryId};

    fn image() -> ExactBinaryImage {
        ExactBinaryImage {
            bytes: (0_u8..=255).cycle().take(0x500).collect(),
            size_of_headers: 0x100,
            size_of_image: 0x3000,
            sections: vec![crate::bootstrap::PeImageSection {
                virtual_address: 0x1000,
                virtual_size: 0x300,
                raw_data_offset: 0x100,
                raw_data_size: 0x200,
            }],
        }
    }

    fn minimal_pe() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0xf0_u16.to_le_bytes());

        let optional = coff + COFF_HEADER_SIZE;
        bytes[optional..optional + 2].copy_from_slice(&OPTIONAL_MAGIC_PE32_PLUS.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x0001_4000_0000_u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000_u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16_u32.to_le_bytes());

        let section = optional + 0xf0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes
    }

    fn minimal_map() -> PeImageMap {
        PeImageMap {
            size_of_headers: 0x200,
            size_of_image: 0x2000,
            sections: vec![PeImageSection {
                virtual_address: 0x1000,
                virtual_size: 0x100,
                raw_data_offset: 0x200,
                raw_data_size: 0x200,
            }],
        }
    }

    #[test]
    fn rva_reads_stop_at_file_backing_boundaries() {
        let image = image();
        let mut destination = [0_u8; 32];
        assert_eq!(image.read_rva(0xf8, &mut destination).unwrap(), 8);
        assert_eq!(image.read_rva(0x11f8, &mut destination).unwrap(), 8);
        assert_eq!(image.read_rva(0x1200, &mut destination).unwrap(), 0);
        assert!(matches!(
            image.read_rva(0x3000, &mut destination),
            Err(ImageReadError::OutsideImage)
        ));
    }

    #[test]
    fn exact_pe_parser_reconstructs_the_bootstrap_map() {
        let bytes = minimal_pe();
        let parsed = parse_pe_image(&bytes).unwrap();
        assert_eq!(parsed.image_base, 0x0001_4000_0000);
        assert_eq!(parsed.image, minimal_map());
    }

    #[test]
    fn exact_pe_metadata_rejects_stale_identity_or_section_maps() {
        let bytes = minimal_pe();
        let mut identity = BinaryIdentity {
            id: BinaryId::digest(&bytes),
            size: bytes.len() as u64,
            format: BinaryFormat::Pe,
            architecture: "x86_64".to_owned(),
            image_base: 0x0001_4000_0000,
        };
        verify_exact_pe_metadata(&bytes, &identity, &minimal_map()).unwrap();

        identity.image_base += 0x1000;
        assert!(verify_exact_pe_metadata(&bytes, &identity, &minimal_map()).is_err());
        identity.image_base -= 0x1000;
        let mut stale = minimal_map();
        stale.sections[0].raw_data_offset += 1;
        assert!(verify_exact_pe_metadata(&bytes, &identity, &stale).is_err());
    }

    #[test]
    fn exact_pe_parser_rejects_malformed_headers() {
        let mut bytes = minimal_pe();
        bytes[0x80] = b'X';
        assert!(parse_pe_image(&bytes).is_err());
    }
}
