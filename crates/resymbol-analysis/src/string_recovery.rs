use crate::{AnalysisError, PeRecoveredString, PeSection, PeStringEncoding};

const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

pub(crate) const MAX_STRING_SCAN_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_RECOVERED_STRINGS: usize = 16_384;
/// Maximum encoded byte size including the trailing NUL terminator.
pub(crate) const MAX_STRING_ENCODED_BYTES: usize = 4 * 1024;
pub(crate) const MAX_STRING_UTF8_BYTES: usize = 4 * 1024;
pub(crate) const MAX_TOTAL_STRING_UTF8_BYTES: usize = 4 * 1024 * 1024;
const MIN_STRING_CODE_POINTS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StringRecovery {
    pub scan_truncated: bool,
    pub strings: Vec<PeRecoveredString>,
}

#[derive(Debug, Clone, Copy)]
struct RecoveryLimits {
    scan_bytes: u64,
    strings: usize,
    encoded_bytes_per_string: usize,
    utf8_bytes_per_string: usize,
    total_utf8_bytes: usize,
}

impl RecoveryLimits {
    const PRODUCTION: Self = Self {
        scan_bytes: MAX_STRING_SCAN_BYTES,
        strings: MAX_RECOVERED_STRINGS,
        encoded_bytes_per_string: MAX_STRING_ENCODED_BYTES,
        utf8_bytes_per_string: MAX_STRING_UTF8_BYTES,
        total_utf8_bytes: MAX_TOTAL_STRING_UTF8_BYTES,
    };
}

struct Candidate {
    byte_size: usize,
    encoding: PeStringEncoding,
    value: String,
}

enum CandidateAttempt {
    None,
    LimitExceeded,
    Recovered(Candidate),
}

/// Recover a deterministic, bounded set of exact NUL-terminated strings.
///
/// Only complete raw ranges from readable, initialized, non-executable PE
/// sections are considered. The scanner never publishes a truncated literal.
pub(crate) fn recover_strings(bytes: &[u8], sections: &[PeSection]) -> StringRecovery {
    recover_strings_with_limits(bytes, sections, RecoveryLimits::PRODUCTION)
}

fn recover_strings_with_limits(
    bytes: &[u8],
    sections: &[PeSection],
    limits: RecoveryLimits,
) -> StringRecovery {
    let mut ordered_sections = sections.iter().enumerate().collect::<Vec<_>>();
    ordered_sections
        .sort_by_key(|(index, section)| (section.virtual_address, section.raw_data_offset, *index));

    let mut recovery = StringRecovery {
        scan_truncated: false,
        strings: Vec::new(),
    };
    let mut scanned_bytes = 0_u64;
    let mut retained_utf8_bytes = 0_usize;

    for (_, section) in ordered_sections {
        let Some(section_bytes) = eligible_section_bytes(bytes, section) else {
            continue;
        };
        let remaining_scan_bytes = limits.scan_bytes.saturating_sub(scanned_bytes);
        if remaining_scan_bytes == 0 {
            recovery.scan_truncated = true;
            break;
        }
        let scan_length = section_bytes
            .len()
            .min(usize::try_from(remaining_scan_bytes).unwrap_or(usize::MAX));
        let scan_was_limited = scan_length < section_bytes.len();
        let scanned = &section_bytes[..scan_length];
        let Ok(scan_length_u64) = u64::try_from(scan_length) else {
            recovery.scan_truncated = true;
            break;
        };
        let Some(next_scanned_bytes) = scanned_bytes.checked_add(scan_length_u64) else {
            recovery.scan_truncated = true;
            break;
        };
        scanned_bytes = next_scanned_bytes;

        if !scan_section(
            scanned,
            section.virtual_address,
            limits,
            &mut retained_utf8_bytes,
            &mut recovery,
        ) {
            break;
        }
        if scan_was_limited {
            recovery.scan_truncated = true;
            break;
        }
    }

    recovery.strings.sort();
    recovery.strings.dedup();
    recovery
}

fn eligible_section_bytes<'a>(bytes: &'a [u8], section: &PeSection) -> Option<&'a [u8]> {
    let file_backed_size = section.file_backed_size();
    if file_backed_size == 0
        || section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA == 0
        || section.characteristics & IMAGE_SCN_MEM_READ == 0
        || section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    {
        return None;
    }
    section.virtual_address.checked_add(file_backed_size)?;
    let start = usize::try_from(section.raw_data_offset).ok()?;
    let size = usize::try_from(file_backed_size).ok()?;
    let end = start.checked_add(size)?;
    bytes.get(start..end)
}

/// Validate persisted recovered-string records without access to source bytes.
///
/// Exact byte equality is established during analysis. Package validation can
/// still enforce every canonical ordering, encoding, size, and PE-range
/// invariant represented by the persisted model.
pub(crate) fn validate_recovered_strings(
    sections: &[PeSection],
    size_of_image: u32,
    strings: &[PeRecoveredString],
) -> Result<(), AnalysisError> {
    let count = u64::try_from(strings.len())
        .map_err(|_| AnalysisError::IntegerConversion("recovered-string count"))?;
    let count_limit = u64::try_from(MAX_RECOVERED_STRINGS)
        .map_err(|_| AnalysisError::IntegerConversion("recovered-string count limit"))?;
    if count > count_limit {
        return Err(AnalysisError::LimitExceeded {
            kind: "recovered string",
            count,
            limit: count_limit,
        });
    }

    let mut total_utf8_bytes = 0_usize;
    let mut previous: Option<&PeRecoveredString> = None;
    for recovered in strings {
        if let Some(previous) = previous {
            if previous.rva >= recovered.rva {
                return invalid(
                    "recovered strings",
                    "must be strictly sorted by increasing RVA and unique",
                );
            }
            let previous_end = previous
                .rva
                .checked_add(previous.byte_size)
                .ok_or(AnalysisError::ArithmeticOverflow("recovered-string range"))?;
            if previous_end > recovered.rva {
                return invalid("recovered strings", "must not overlap");
            }
        }

        let code_points = recovered.value.chars().count();
        if code_points < MIN_STRING_CODE_POINTS
            || recovered.value.chars().all(char::is_whitespace)
            || recovered.value.chars().any(char::is_control)
        {
            return invalid(
                "recovered string value",
                "must contain at least four code points, including one non-whitespace, and no controls",
            );
        }
        if recovered.value.len() > MAX_STRING_UTF8_BYTES {
            return Err(AnalysisError::LimitExceeded {
                kind: "recovered-string UTF-8 byte",
                count: u64::try_from(recovered.value.len()).map_err(|_| {
                    AnalysisError::IntegerConversion("recovered-string UTF-8 length")
                })?,
                limit: u64::try_from(MAX_STRING_UTF8_BYTES).map_err(|_| {
                    AnalysisError::IntegerConversion("recovered-string UTF-8 limit")
                })?,
            });
        }

        let (encoded_content_bytes, terminator_bytes) = match recovered.encoding {
            PeStringEncoding::Ascii => {
                if !recovered.value.bytes().all(is_ascii_string_byte) {
                    return invalid(
                        "recovered ASCII string",
                        "contains a non-printable or non-ASCII code point",
                    );
                }
                (recovered.value.len(), 1_usize)
            }
            PeStringEncoding::Utf16Le => {
                if recovered.rva % 2 != 0 {
                    return invalid("recovered UTF-16 string RVA", "must be two-byte aligned");
                }
                let units = recovered.value.encode_utf16().count();
                let bytes = units
                    .checked_mul(2)
                    .ok_or(AnalysisError::ArithmeticOverflow(
                        "recovered UTF-16 encoded length",
                    ))?;
                (bytes, 2_usize)
            }
            _ => {
                return invalid(
                    "recovered string encoding",
                    "is not supported by PE string recovery",
                );
            }
        };
        let expected_byte_size = encoded_content_bytes.checked_add(terminator_bytes).ok_or(
            AnalysisError::ArithmeticOverflow("recovered-string encoded size"),
        )?;
        if expected_byte_size > MAX_STRING_ENCODED_BYTES {
            return Err(AnalysisError::LimitExceeded {
                kind: "recovered-string encoded byte",
                count: u64::try_from(expected_byte_size).map_err(|_| {
                    AnalysisError::IntegerConversion("recovered-string encoded length")
                })?,
                limit: u64::try_from(MAX_STRING_ENCODED_BYTES).map_err(|_| {
                    AnalysisError::IntegerConversion("recovered-string encoded limit")
                })?,
            });
        }
        if usize::try_from(recovered.byte_size).ok() != Some(expected_byte_size) {
            return invalid(
                "recovered string byte size",
                "does not equal its encoded content plus NUL terminator",
            );
        }

        let end_rva = recovered.rva.checked_add(recovered.byte_size).ok_or(
            AnalysisError::ArithmeticOverflow("recovered-string image range"),
        )?;
        if recovered.byte_size == 0
            || end_rva > size_of_image
            || !eligible_section_contains(sections, recovered.rva, recovered.byte_size)
        {
            return invalid(
                "recovered string range",
                "is outside the image or not wholly backed by one readable initialized non-executable section",
            );
        }

        total_utf8_bytes = total_utf8_bytes.checked_add(recovered.value.len()).ok_or(
            AnalysisError::ArithmeticOverflow("aggregate recovered-string UTF-8 bytes"),
        )?;
        if total_utf8_bytes > MAX_TOTAL_STRING_UTF8_BYTES {
            return Err(AnalysisError::LimitExceeded {
                kind: "aggregate recovered-string UTF-8 byte",
                count: u64::try_from(total_utf8_bytes).map_err(|_| {
                    AnalysisError::IntegerConversion("aggregate recovered-string UTF-8 length")
                })?,
                limit: u64::try_from(MAX_TOTAL_STRING_UTF8_BYTES).map_err(|_| {
                    AnalysisError::IntegerConversion("aggregate recovered-string UTF-8 limit")
                })?,
            });
        }
        previous = Some(recovered);
    }
    Ok(())
}

fn eligible_section_contains(sections: &[PeSection], rva: u32, size: u32) -> bool {
    let range_start = u64::from(rva);
    let range_end = range_start + u64::from(size);
    sections.iter().any(|section| {
        let section_start = u64::from(section.virtual_address);
        let file_backed_size = section.file_backed_size();
        let section_end = section_start + u64::from(file_backed_size);
        file_backed_size != 0
            && section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
            && section.characteristics & IMAGE_SCN_MEM_READ != 0
            && section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0
            && range_start >= section_start
            && range_end <= section_end
    })
}

fn invalid<T>(field: &'static str, reason: impl Into<String>) -> Result<T, AnalysisError> {
    Err(AnalysisError::InvalidField {
        field,
        reason: reason.into(),
    })
}

fn scan_section(
    bytes: &[u8],
    section_rva: u32,
    limits: RecoveryLimits,
    retained_utf8_bytes: &mut usize,
    recovery: &mut StringRecovery,
) -> bool {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let ascii_attempt = ascii_candidate(bytes, offset, limits);
        let candidate = match ascii_attempt {
            CandidateAttempt::Recovered(candidate) => CandidateAttempt::Recovered(candidate),
            CandidateAttempt::LimitExceeded => {
                recovery.scan_truncated = true;
                utf16_candidate(bytes, section_rva, offset, limits)
            }
            CandidateAttempt::None => utf16_candidate(bytes, section_rva, offset, limits),
        };

        match candidate {
            CandidateAttempt::Recovered(candidate) => {
                if recovery.strings.len() == limits.strings {
                    recovery.scan_truncated = true;
                    return false;
                }
                let Some(next_total) = retained_utf8_bytes.checked_add(candidate.value.len())
                else {
                    recovery.scan_truncated = true;
                    return false;
                };
                if next_total > limits.total_utf8_bytes {
                    recovery.scan_truncated = true;
                    return false;
                }
                let Ok(offset_rva) = u32::try_from(offset) else {
                    recovery.scan_truncated = true;
                    return false;
                };
                let Some(rva) = section_rva.checked_add(offset_rva) else {
                    recovery.scan_truncated = true;
                    return false;
                };
                let Ok(byte_size) = u32::try_from(candidate.byte_size) else {
                    recovery.scan_truncated = true;
                    return false;
                };
                *retained_utf8_bytes = next_total;
                recovery.strings.push(PeRecoveredString {
                    rva,
                    byte_size,
                    encoding: candidate.encoding,
                    value: candidate.value,
                });
                offset = offset.saturating_add(candidate.byte_size);
            }
            CandidateAttempt::LimitExceeded => {
                recovery.scan_truncated = true;
                offset = offset.saturating_add(1);
            }
            CandidateAttempt::None => offset = offset.saturating_add(1),
        }
    }
    true
}

fn ascii_candidate(bytes: &[u8], start: usize, limits: RecoveryLimits) -> CandidateAttempt {
    let Some(first) = bytes.get(start) else {
        return CandidateAttempt::None;
    };
    if !is_ascii_string_byte(*first)
        || start
            .checked_sub(1)
            .and_then(|previous| bytes.get(previous))
            .is_some_and(|byte| is_ascii_string_byte(*byte))
    {
        return CandidateAttempt::None;
    }

    let mut end = start;
    while bytes
        .get(end)
        .is_some_and(|byte| is_ascii_string_byte(*byte))
    {
        end += 1;
    }
    let content_length = end - start;
    if content_length < MIN_STRING_CODE_POINTS
        || bytes[start..end].iter().all(|byte| *byte == b' ')
        || bytes.get(end) != Some(&0)
    {
        return CandidateAttempt::None;
    }
    let Some(byte_size) = content_length.checked_add(1) else {
        return CandidateAttempt::LimitExceeded;
    };
    if byte_size > limits.encoded_bytes_per_string || content_length > limits.utf8_bytes_per_string
    {
        return CandidateAttempt::LimitExceeded;
    }

    CandidateAttempt::Recovered(Candidate {
        byte_size,
        encoding: PeStringEncoding::Ascii,
        value: std::str::from_utf8(&bytes[start..end])
            .expect("printable ASCII is valid UTF-8")
            .to_owned(),
    })
}

fn utf16_candidate(
    bytes: &[u8],
    section_rva: u32,
    start: usize,
    limits: RecoveryLimits,
) -> CandidateAttempt {
    let Ok(start_rva) = u32::try_from(start) else {
        return CandidateAttempt::None;
    };
    let Some(candidate_rva) = section_rva.checked_add(start_rva) else {
        return CandidateAttempt::None;
    };
    if candidate_rva % 2 != 0 || start + 1 >= bytes.len() {
        return CandidateAttempt::None;
    }
    if start >= 2 {
        let previous = read_u16(bytes, start - 2).expect("the previous UTF-16 unit is in bounds");
        if utf16_unit_could_continue(previous) {
            return CandidateAttempt::None;
        }
    }

    let mut position = start;
    let mut encoded_bytes = 0_usize;
    let mut utf8_bytes = 0_usize;
    let mut code_points = 0_usize;
    let mut value = String::new();
    let mut exceeded = false;
    let mut has_non_whitespace = false;

    loop {
        let Some(unit) = read_u16(bytes, position) else {
            return CandidateAttempt::None;
        };
        if unit == 0 {
            break;
        }
        let Some((character, consumed_bytes)) = decode_utf16_scalar(bytes, position, unit) else {
            return CandidateAttempt::None;
        };
        if character.is_control() {
            return CandidateAttempt::None;
        }
        position += consumed_bytes;
        encoded_bytes += consumed_bytes;
        code_points += 1;
        utf8_bytes += character.len_utf8();
        has_non_whitespace |= !character.is_whitespace();
        if encoded_bytes.saturating_add(2) > limits.encoded_bytes_per_string
            || utf8_bytes > limits.utf8_bytes_per_string
        {
            exceeded = true;
        } else {
            value.push(character);
        }
    }

    if code_points < MIN_STRING_CODE_POINTS || !has_non_whitespace {
        return CandidateAttempt::None;
    }
    if exceeded {
        return CandidateAttempt::LimitExceeded;
    }
    CandidateAttempt::Recovered(Candidate {
        byte_size: encoded_bytes + 2,
        encoding: PeStringEncoding::Utf16Le,
        value,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([raw[0], raw[1]]))
}

fn decode_utf16_scalar(bytes: &[u8], position: usize, unit: u16) -> Option<(char, usize)> {
    if (0xd800..=0xdbff).contains(&unit) {
        let low = read_u16(bytes, position.checked_add(2)?)?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return None;
        }
        let scalar = 0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
        return char::from_u32(scalar).map(|character| (character, 4));
    }
    if (0xdc00..=0xdfff).contains(&unit) {
        return None;
    }
    char::from_u32(u32::from(unit)).map(|character| (character, 2))
}

fn utf16_unit_could_continue(unit: u16) -> bool {
    if unit == 0 || (0x0001..=0x001f).contains(&unit) || (0x007f..=0x009f).contains(&unit) {
        return false;
    }
    true
}

const fn is_ascii_string_byte(byte: u8) -> bool {
    byte >= 0x20 && byte <= 0x7e
}

#[cfg(test)]
mod tests {
    use super::*;

    const ELIGIBLE: u32 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | 0x8000_0000;

    fn section(
        virtual_address: u32,
        raw_data_offset: u32,
        raw_data_size: u32,
        characteristics: u32,
    ) -> PeSection {
        PeSection {
            name: ".data".to_owned(),
            raw_name: *b".data\0\0\0",
            virtual_address,
            virtual_size: raw_data_size,
            raw_data_offset,
            raw_data_size,
            characteristics,
        }
    }

    fn append_utf16(bytes: &mut Vec<u8>, value: &str) {
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());
    }

    #[test]
    fn recovers_ascii_and_utf16_from_writable_data_in_rva_order() {
        let mut bytes = vec![0_u8; 32];
        bytes[0..6].copy_from_slice(b"Hello\0");
        append_utf16(&mut bytes, "AΩ中🙂");
        let second_offset = 32_u32;
        let sections = [
            section(0x3000, second_offset, 12, ELIGIBLE),
            section(0x2000, 0, 32, ELIGIBLE),
        ];

        let recovery = recover_strings(&bytes, &sections);

        assert!(!recovery.scan_truncated);
        assert_eq!(
            recovery.strings,
            vec![
                PeRecoveredString {
                    rva: 0x2000,
                    byte_size: 6,
                    encoding: PeStringEncoding::Ascii,
                    value: "Hello".to_owned(),
                },
                PeRecoveredString {
                    rva: 0x3000,
                    byte_size: 12,
                    encoding: PeStringEncoding::Utf16Le,
                    value: "AΩ中🙂".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn rejects_ineligible_or_not_fully_backed_sections() {
        let bytes = b"Valid\0";
        for characteristics in [
            IMAGE_SCN_CNT_INITIALIZED_DATA,
            IMAGE_SCN_MEM_READ,
            ELIGIBLE | IMAGE_SCN_MEM_EXECUTE,
        ] {
            assert!(
                recover_strings(
                    bytes,
                    &[section(0x2000, 0, bytes.len() as u32, characteristics)]
                )
                .strings
                .is_empty()
            );
        }
        assert!(
            recover_strings(bytes, &[section(0x2000, 0, 64, ELIGIBLE)])
                .strings
                .is_empty()
        );
    }

    #[test]
    fn requires_minimum_length_terminators_and_control_free_text() {
        let bytes = b"abc\0Good\0bad\n\0Unterminated";
        let recovery = recover_strings(bytes, &[section(0x2000, 0, bytes.len() as u32, ELIGIBLE)]);
        assert_eq!(recovery.strings.len(), 1);
        assert_eq!(recovery.strings[0].value, "Good");
    }

    #[test]
    fn rejects_ascii_and_utf16_whitespace_only_literals() {
        let mut bytes = b"    \0".to_vec();
        bytes.push(0);
        append_utf16(&mut bytes, "    ");
        let recovery = recover_strings(&bytes, &[section(0x2000, 0, bytes.len() as u32, ELIGIBLE)]);
        assert!(recovery.strings.is_empty());
    }

    #[test]
    fn rejects_odd_utf16_starts_controls_and_unpaired_surrogates() {
        let mut odd = Vec::new();
        append_utf16(&mut odd, "Wide");
        assert!(
            recover_strings(&odd, &[section(0x2001, 0, odd.len() as u32, ELIGIBLE)])
                .strings
                .is_empty()
        );

        let control = [b'A', 0, b'B', 0, b'\n', 0, b'C', 0, 0, 0];
        assert!(
            recover_strings(
                &control,
                &[section(0x2000, 0, control.len() as u32, ELIGIBLE)]
            )
            .strings
            .is_empty()
        );

        let surrogate = [0x00, 0xd8, b'A', 0, b'B', 0, b'C', 0, 0, 0];
        assert!(
            recover_strings(
                &surrogate,
                &[section(0x2000, 0, surrogate.len() as u32, ELIGIBLE)]
            )
            .strings
            .is_empty()
        );
    }

    #[test]
    fn ascii_wins_a_same_start_overlap_deterministically() {
        let bytes = b"ABCDEFGH\0\0";
        let recovery = recover_strings(bytes, &[section(0x2000, 0, bytes.len() as u32, ELIGIBLE)]);
        assert_eq!(recovery.strings.len(), 1);
        assert_eq!(recovery.strings[0].encoding, PeStringEncoding::Ascii);
        assert_eq!(recovery.strings[0].value, "ABCDEFGH");
    }

    #[test]
    fn resource_limits_mark_partial_and_never_publish_literal_prefixes() {
        let bytes = b"Hello\0Good\0Next\0";
        let source = [section(0x2000, 0, bytes.len() as u32, ELIGIBLE)];

        let scan_limited = recover_strings_with_limits(
            bytes,
            &source,
            RecoveryLimits {
                scan_bytes: 5,
                ..RecoveryLimits::PRODUCTION
            },
        );
        assert!(scan_limited.scan_truncated);
        assert!(scan_limited.strings.is_empty());

        let value_limited = recover_strings_with_limits(
            bytes,
            &source,
            RecoveryLimits {
                encoded_bytes_per_string: 5,
                utf8_bytes_per_string: 4,
                ..RecoveryLimits::PRODUCTION
            },
        );
        assert!(value_limited.scan_truncated);
        assert_eq!(
            value_limited
                .strings
                .iter()
                .map(|value| value.value.as_str())
                .collect::<Vec<_>>(),
            ["Good", "Next"]
        );

        let count_limited = recover_strings_with_limits(
            bytes,
            &source,
            RecoveryLimits {
                strings: 1,
                ..RecoveryLimits::PRODUCTION
            },
        );
        assert!(count_limited.scan_truncated);
        assert_eq!(count_limited.strings[0].value, "Hello");

        let aggregate_limited = recover_strings_with_limits(
            bytes,
            &source,
            RecoveryLimits {
                total_utf8_bytes: 5,
                ..RecoveryLimits::PRODUCTION
            },
        );
        assert!(aggregate_limited.scan_truncated);
        assert_eq!(aggregate_limited.strings[0].value, "Hello");
    }

    #[test]
    fn encoded_size_cap_includes_the_terminator_at_the_exact_boundary() {
        let exact_ascii = format!("{}\0", "A".repeat(MAX_STRING_ENCODED_BYTES - 1));
        let ascii_section = [section(0x2000, 0, exact_ascii.len() as u32, ELIGIBLE)];
        let exact = recover_strings(exact_ascii.as_bytes(), &ascii_section);
        assert!(!exact.scan_truncated);
        assert_eq!(exact.strings[0].byte_size, MAX_STRING_ENCODED_BYTES as u32);

        let oversized_ascii = format!("{}\0", "A".repeat(MAX_STRING_ENCODED_BYTES));
        let oversized = recover_strings(
            oversized_ascii.as_bytes(),
            &[section(0x2000, 0, oversized_ascii.len() as u32, ELIGIBLE)],
        );
        assert!(oversized.scan_truncated);
        assert!(oversized.strings.is_empty());

        let exact_utf16_code_points = (MAX_STRING_ENCODED_BYTES - 2) / 2;
        let mut exact_utf16 = Vec::new();
        append_utf16(&mut exact_utf16, &"W".repeat(exact_utf16_code_points));
        let exact = recover_strings(
            &exact_utf16,
            &[section(0x4000, 0, exact_utf16.len() as u32, ELIGIBLE)],
        );
        assert_eq!(exact.strings[0].byte_size, MAX_STRING_ENCODED_BYTES as u32);

        let mut oversized_utf16 = Vec::new();
        append_utf16(
            &mut oversized_utf16,
            &"W".repeat(exact_utf16_code_points + 1),
        );
        let oversized = recover_strings(
            &oversized_utf16,
            &[section(0x4000, 0, oversized_utf16.len() as u32, ELIGIBLE)],
        );
        assert!(oversized.scan_truncated);
        assert!(oversized.strings.is_empty());
    }

    #[test]
    fn persisted_record_validator_enforces_canonical_encoding_and_ranges() {
        let bytes = b"Alpha\0Beta\0";
        let sections = [section(0x2000, 0, bytes.len() as u32, ELIGIBLE)];
        let recovery = recover_strings(bytes, &sections);
        validate_recovered_strings(&sections, 0x3000, &recovery.strings)
            .expect("scanner output is valid");

        let mut unsorted = recovery.strings.clone();
        unsorted.swap(0, 1);
        assert!(validate_recovered_strings(&sections, 0x3000, &unsorted).is_err());

        let mut overlap = recovery.strings.clone();
        overlap[1].rva = overlap[0].rva + 1;
        assert!(validate_recovered_strings(&sections, 0x3000, &overlap).is_err());

        let mut wrong_size = recovery.strings.clone();
        wrong_size[0].byte_size -= 1;
        assert!(validate_recovered_strings(&sections, 0x3000, &wrong_size).is_err());

        let whitespace = [PeRecoveredString {
            rva: 0x2000,
            byte_size: 5,
            encoding: PeStringEncoding::Ascii,
            value: "    ".to_owned(),
        }];
        assert!(validate_recovered_strings(&sections, 0x3000, &whitespace).is_err());

        let misaligned_utf16 = [PeRecoveredString {
            rva: 0x2001,
            byte_size: 10,
            encoding: PeStringEncoding::Utf16Le,
            value: "Wide".to_owned(),
        }];
        assert!(validate_recovered_strings(&sections, 0x3000, &misaligned_utf16).is_err());

        let outside_image = [PeRecoveredString {
            rva: 0x2000,
            byte_size: 6,
            encoding: PeStringEncoding::Ascii,
            value: "Alpha".to_owned(),
        }];
        assert!(validate_recovered_strings(&sections, 0x2005, &outside_image).is_err());

        let executable = [section(
            0x2000,
            0,
            bytes.len() as u32,
            ELIGIBLE | IMAGE_SCN_MEM_EXECUTE,
        )];
        assert!(validate_recovered_strings(&executable, 0x3000, &outside_image).is_err());
    }

    #[test]
    fn production_limits_match_the_public_analysis_contract() {
        assert_eq!(MAX_STRING_SCAN_BYTES, 64 * 1024 * 1024);
        assert_eq!(MAX_RECOVERED_STRINGS, 16_384);
        assert_eq!(MAX_STRING_ENCODED_BYTES, 4 * 1024);
        assert_eq!(MAX_STRING_UTF8_BYTES, 4 * 1024);
        assert_eq!(MAX_TOTAL_STRING_UTF8_BYTES, 4 * 1024 * 1024);
        assert_eq!(MIN_STRING_CODE_POINTS, 4);
    }
}
