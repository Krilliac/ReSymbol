//! Deterministic DWARF debug-companion export for a validated projection.
//!
//! This writer projects the neutral model into a small, self-contained ELF
//! object whose only purpose is to carry recovered debug information. gdb, lldb,
//! Ghidra, and IDA can load the companion alongside the original image because
//! it addresses the image at its preferred base.
//!
//! # What is emitted
//!
//! One `DW_TAG_compile_unit` with `DW_AT_producer` (`ReSymbol <version>`),
//! `DW_AT_language` = `DW_LANG_C`, and `DW_AT_low_pc`/`DW_AT_high_pc` spanning
//! the virtual image. `DW_LANG_C` is a deliberately neutral choice: the neutral
//! projection is language-agnostic, and C is the lingua franca every consumer
//! understands without imposing name-mangling or member-layout assumptions the
//! projection cannot substantiate.
//!
//! * One `DW_TAG_subprogram` per exported function, with `DW_AT_low_pc` =
//!   `image_base + rva`. `DW_AT_high_pc` is emitted, in the DWARF offset form,
//!   only when a function size is known; a missing size is never invented.
//!   `DW_AT_name` carries the exact recovered source spelling when present —
//!   DWARF names are free-form, so no portable-identifier rewrite is applied.
//! * One `DW_TAG_variable` per named exported global, with `DW_AT_name` and a
//!   `DW_AT_location` address expression (`DW_OP_addr image_base + rva`).
//! * One `DW_TAG_class_type` per distinct class the projection names (the union
//!   of named `types` and every class referenced by a function's
//!   `class_memberships`), each with `DW_AT_name`.
//! * `DW_TAG_inheritance` edges reconstructed from co-membership. The neutral
//!   projection never records a structured class->base edge; the only class
//!   relationship it carries is a function's membership in one or more classes.
//!   When a function is attributed to two or more classes, the canonically
//!   first membership is treated as the defining class and each remaining
//!   membership as a base, and one `DW_TAG_inheritance` (with `DW_AT_type`
//!   referencing the base DIE) is emitted per distinct pair. This reconstructs
//!   the existence of a hierarchy, not its verified orientation; the imperfect
//!   membership representation is recorded in the loss report.
//!
//! # What is not emitted
//!
//! No line-number program (`.debug_line`): the projection carries no source
//! lines, so inventing one would be dishonest. No struct members, field types,
//! or type sizes are synthesized — only class names and inheritance edges the
//! projection actually carries. Alternate names, prototypes, provenance,
//! confidence, control-flow relationships, strings, and data references are not
//! representable here and are routed to [`ExportLossReport`] exactly like the
//! sibling writers.

use gimli::write::{
    Address, AttributeValue, DwarfUnit, EndianVec, Expression, Sections, UnitEntryId,
};
use gimli::{Encoding, Format, RunTimeEndian};
use object::write::{Object, SectionKind};
use object::{Architecture, BinaryFormat, Endianness};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use crate::{ExportLossReport, ExportProjection, ExportTarget, ProjectionValidationError};

/// Producer string embedded in `DW_AT_producer`.
const PRODUCER: &str = concat!("ReSymbol ", env!("CARGO_PKG_VERSION"));

/// Fixed compilation-unit name. The exact binary identity is intentionally not
/// embedded (a DWARF CU has no honest place for a content hash), so it is
/// accounted for as projection-metadata loss instead.
const COMPILE_UNIT_NAME: &str = "ReSymbol recovered symbols";

/// Maximum number of debugging-information entries one companion may carry.
///
/// This bounds writer growth before any allocation, mirroring the other
/// writers' pre-allocation gates. The ceiling comfortably exceeds the neutral
/// projection's own entity limits.
pub const MAX_DWARF_DIES: usize = 4_194_304;

/// A rendered DWARF debug companion and its target-loss assessment.
#[derive(Debug, Clone)]
pub struct DwarfArtifact {
    bytes: Vec<u8>,
    loss: ExportLossReport,
}

impl DwarfArtifact {
    /// Serialized ELF companion bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the artifact and return the serialized ELF companion bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Deterministic assessment of the claims this companion could not retain.
    pub const fn loss(&self) -> &ExportLossReport {
        &self.loss
    }
}

/// Failure to render a deterministic DWARF debug companion.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DwarfError {
    #[error("the export projection is invalid: {0}")]
    InvalidProjection(#[from] ProjectionValidationError),
    #[error("the projection describes more than {limit} debugging-information entries")]
    EntryLimitExceeded { limit: usize },
    #[error("cannot encode DWARF sections: {reason}")]
    DwarfEncoding { reason: String },
    #[error("cannot encode the ELF debug companion: {reason}")]
    ElfEncoding { reason: String },
    #[error("a projected address is outside the addressable range of the companion")]
    AddressOutOfRange,
}

/// Endianness, architecture, and address size chosen for the ELF container.
#[derive(Debug, Clone, Copy)]
struct ContainerTarget {
    architecture: Architecture,
    object_endian: Endianness,
    dwarf_endian: RunTimeEndian,
    address_size: u8,
}

/// Render a deterministic DWARF debug companion for `projection`.
///
/// The returned [`DwarfArtifact`] carries a relocatable ELF object holding the
/// `.debug_abbrev`, `.debug_info`, and `.debug_str` sections (plus any other
/// supporting DWARF section gimli emits) alongside the target-loss report. The
/// container's machine, byte order, and address size reflect the projected
/// binary's architecture when it can be determined, and default to little-endian
/// x86-64 otherwise.
pub fn render_dwarf(projection: &ExportProjection) -> Result<DwarfArtifact, DwarfError> {
    // `for_projection` revalidates the projection before assessing loss, so a
    // hostile model is rejected before any DWARF byte is produced.
    let loss = ExportLossReport::for_projection(ExportTarget::Dwarf, projection)?;

    enforce_entry_limit(projection)?;

    let target = container_target(&projection.binary.architecture);
    let image_base = projection.binary.image_base;

    let encoding = Encoding {
        format: Format::Dwarf32,
        version: 5,
        address_size: target.address_size,
    };
    let mut dwarf = DwarfUnit::new(encoding);

    let root = dwarf.unit.root();
    let producer = string_ref(&mut dwarf, PRODUCER);
    let unit_name = string_ref(&mut dwarf, COMPILE_UNIT_NAME);
    {
        let root_die = dwarf.unit.get_mut(root);
        root_die.set(gimli::DW_AT_producer, producer);
        root_die.set(gimli::DW_AT_name, unit_name);
        root_die.set(
            gimli::DW_AT_language,
            AttributeValue::Language(gimli::DW_LANG_C),
        );
        root_die.set(
            gimli::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(image_base)),
        );
        root_die.set(
            gimli::DW_AT_high_pc,
            AttributeValue::Udata(projection.binary.image_size),
        );
    }

    emit_classes(&mut dwarf, root, projection);
    emit_functions(&mut dwarf, root, projection, image_base)?;
    emit_globals(&mut dwarf, root, projection, image_base)?;

    let bytes = serialize(&mut dwarf, target)?;
    Ok(DwarfArtifact { bytes, loss })
}

/// Add `text` to the `.debug_str` table and return a reference attribute.
fn string_ref(dwarf: &mut DwarfUnit, text: &str) -> AttributeValue {
    AttributeValue::StringRef(dwarf.strings.add(text.as_bytes().to_vec()))
}

fn enforce_entry_limit(projection: &ExportProjection) -> Result<(), DwarfError> {
    let membership_total = projection
        .functions
        .iter()
        .try_fold(0_usize, |total, function| {
            total.checked_add(function.class_memberships.len())
        });
    let entries = membership_total
        .and_then(|memberships| memberships.checked_add(projection.functions.len()))
        .and_then(|count| count.checked_add(projection.globals.len()))
        .and_then(|count| count.checked_add(projection.types.len()));
    match entries {
        Some(count) if count <= MAX_DWARF_DIES => Ok(()),
        _ => Err(DwarfError::EntryLimitExceeded {
            limit: MAX_DWARF_DIES,
        }),
    }
}

/// Emit one `DW_TAG_class_type` per distinct named class and the inheritance
/// edges reconstructed from function co-membership.
fn emit_classes(dwarf: &mut DwarfUnit, root: UnitEntryId, projection: &ExportProjection) {
    let mut class_names = BTreeSet::<&str>::new();
    for value in &projection.types {
        if let Some(name) = &value.selected_name {
            class_names.insert(name.source.text.as_str());
        }
    }
    for function in &projection.functions {
        for membership in &function.class_memberships {
            class_names.insert(membership.text.as_str());
        }
    }

    let mut class_dies = BTreeMap::<&str, UnitEntryId>::new();
    for name in class_names {
        let die_id = dwarf.unit.add(root, gimli::DW_TAG_class_type);
        let name_ref = string_ref(dwarf, name);
        dwarf.unit.get_mut(die_id).set(gimli::DW_AT_name, name_ref);
        class_dies.insert(name, die_id);
    }

    // Reconstruct base relationships from co-membership. The first membership in
    // canonical order is the defining class; the rest are bases. Direction is
    // not authoritative (see the module documentation); the pairs are collected
    // into an ordered set so the output is deterministic and duplicate-free.
    let mut inheritance = BTreeSet::<(&str, &str)>::new();
    for function in &projection.functions {
        let mut memberships = function.class_memberships.iter();
        let Some(derived) = memberships.next() else {
            continue;
        };
        for base in memberships {
            if derived.text != base.text {
                inheritance.insert((derived.text.as_str(), base.text.as_str()));
            }
        }
    }

    for (derived, base) in inheritance {
        let (Some(&derived_die), Some(&base_die)) = (class_dies.get(derived), class_dies.get(base))
        else {
            continue;
        };
        let inheritance_die = dwarf.unit.add(derived_die, gimli::DW_TAG_inheritance);
        dwarf
            .unit
            .get_mut(inheritance_die)
            .set(gimli::DW_AT_type, AttributeValue::UnitRef(base_die));
    }
}

/// Emit one `DW_TAG_subprogram` per exported function.
fn emit_functions(
    dwarf: &mut DwarfUnit,
    root: UnitEntryId,
    projection: &ExportProjection,
    image_base: u64,
) -> Result<(), DwarfError> {
    for function in &projection.functions {
        let low_pc = image_base
            .checked_add(function.rva)
            .ok_or(DwarfError::AddressOutOfRange)?;
        let die_id = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
        if let Some(name) = &function.selected_name {
            let name_ref = string_ref(dwarf, &name.source.text);
            dwarf.unit.get_mut(die_id).set(gimli::DW_AT_name, name_ref);
        }
        let die = dwarf.unit.get_mut(die_id);
        die.set(
            gimli::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(low_pc)),
        );
        if let Some(size) = function.size {
            die.set(gimli::DW_AT_high_pc, AttributeValue::Udata(size));
        }
    }
    Ok(())
}

/// Emit one `DW_TAG_variable` per named exported global.
fn emit_globals(
    dwarf: &mut DwarfUnit,
    root: UnitEntryId,
    projection: &ExportProjection,
    image_base: u64,
) -> Result<(), DwarfError> {
    for global in &projection.globals {
        let Some(name) = &global.selected_name else {
            continue;
        };
        let address = image_base
            .checked_add(global.rva)
            .ok_or(DwarfError::AddressOutOfRange)?;
        let die_id = dwarf.unit.add(root, gimli::DW_TAG_variable);
        let name_ref = string_ref(dwarf, &name.source.text);
        let mut location = Expression::new();
        location.op_addr(Address::Constant(address));
        let die = dwarf.unit.get_mut(die_id);
        die.set(gimli::DW_AT_name, name_ref);
        die.set(gimli::DW_AT_location, AttributeValue::Exprloc(location));
    }
    Ok(())
}

/// Serialize the DWARF sections and wrap them in a relocatable ELF container.
fn serialize(dwarf: &mut DwarfUnit, target: ContainerTarget) -> Result<Vec<u8>, DwarfError> {
    let mut sections = Sections::new(EndianVec::new(target.dwarf_endian));
    dwarf
        .write(&mut sections)
        .map_err(|error| DwarfError::DwarfEncoding {
            reason: error.to_string(),
        })?;

    let mut object = Object::new(BinaryFormat::Elf, target.architecture, target.object_endian);
    sections.for_each(
        |id, data: &EndianVec<RunTimeEndian>| -> Result<(), DwarfError> {
            let slice = data.slice();
            if slice.is_empty() {
                return Ok(());
            }
            let section_id = object.add_section(Vec::new(), id.name().into(), SectionKind::Debug);
            object.set_section_data(section_id, slice.to_vec(), 1);
            Ok(())
        },
    )?;

    object.write().map_err(|error| DwarfError::ElfEncoding {
        reason: error.to_string(),
    })
}

/// Map a projected architecture string to an ELF container configuration.
///
/// The neutral projection stores a free-form, format-qualified architecture
/// string (for example `x86_64`, `elf64-x86-64`, `elf32-arm-be`, or
/// `macho64-arm64`). This performs a best-effort classification and defaults to
/// little-endian x86-64 when nothing is recognized, so the companion always has
/// a concrete, documented machine.
fn container_target(architecture: &str) -> ContainerTarget {
    let value = architecture.to_ascii_lowercase();
    let big_endian = value.contains("-be") || value.ends_with("be");
    let object_endian = if big_endian {
        Endianness::Big
    } else {
        Endianness::Little
    };
    let dwarf_endian = if big_endian {
        RunTimeEndian::Big
    } else {
        RunTimeEndian::Little
    };

    let (architecture, address_size) =
        if value.contains("x86-64") || value.contains("x86_64") || value.contains("amd64") {
            (Architecture::X86_64, 8)
        } else if value.contains("aarch64") || value.contains("arm64") {
            (Architecture::Aarch64, 8)
        } else if value.contains("riscv64") || (value.contains("riscv") && value.contains("64")) {
            (Architecture::Riscv64, 8)
        } else if value.contains("riscv") {
            (Architecture::Riscv32, 4)
        } else if value.contains("ppc64") {
            (Architecture::PowerPc64, 8)
        } else if value.contains("arm") {
            (Architecture::Arm, 4)
        } else if value.contains("i386")
            || value.contains("i686")
            || value.contains("x86")
            || value == "x86"
        {
            (Architecture::I386, 4)
        } else {
            // Documented default: a little-endian x86-64 companion.
            (Architecture::X86_64, 8)
        };

    ContainerTarget {
        architecture,
        object_endian,
        dwarf_endian,
        address_size,
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::BTreeMap;

    use gimli::read::UnitOffset;
    use object::{Object, ObjectSection};
    use resymbol_core::BinaryId;

    use super::*;
    use crate::{
        AttributedText, ExportAttribution, ExportBinary, ExportBinaryFormat, ExportFunction,
        ExportGlobal, ExportLossCode, ExportName, ExportProducer, ExportProvenance, ExportType,
    };

    fn attribution(confidence: f64) -> ExportAttribution {
        ExportAttribution {
            confidence,
            provenance: ExportProvenance {
                producer: ExportProducer::Core {
                    component: "resymbol-analysis".to_owned(),
                    version: "0.1.0".to_owned(),
                },
                method: "dwarf-test".to_owned(),
                run_id: None,
            },
        }
    }

    fn named(source: &str, output: &str) -> ExportName {
        ExportName {
            source: AttributedText {
                text: source.to_owned(),
                attribution: attribution(1.0),
            },
            output_name: output.to_owned(),
        }
    }

    fn membership(text: &str, confidence: f64) -> AttributedText {
        AttributedText {
            text: text.to_owned(),
            attribution: attribution(confidence),
        }
    }

    /// A projection with named/unnamed functions, named/unnamed globals, a named
    /// type, and a function co-membership that reconstructs one base class.
    fn projection() -> ExportProjection {
        ExportProjection {
            schema_version: 6,
            binary: ExportBinary {
                id: BinaryId::from_sha256("33".repeat(32)).expect("test digest"),
                file_size: 0x4000,
                format: ExportBinaryFormat::Elf,
                architecture: "x86_64".to_owned(),
                image_base: 0x1_4000_0000,
                image_size: 0x5000,
            },
            functions: vec![
                ExportFunction {
                    rva: 0x1000,
                    entry_attribution: Some(attribution(0.9)),
                    size: Some(0x40),
                    size_attribution: Some(attribution(0.9)),
                    selected_name: Some(named("Widget::update", "Widget__update")),
                    alternate_names: vec![membership("update_impl", 0.5)],
                    prototypes: vec![membership("void Widget::update(void)", 0.7)],
                    // Higher confidence sorts first in canonical order, so the
                    // defining class precedes its base.
                    class_memberships: vec![
                        membership("demo::Derived", 0.9),
                        membership("demo::Base", 0.8),
                    ],
                },
                ExportFunction {
                    rva: 0x1040,
                    entry_attribution: Some(attribution(0.6)),
                    size: None,
                    size_attribution: None,
                    selected_name: None,
                    alternate_names: Vec::new(),
                    prototypes: Vec::new(),
                    class_memberships: Vec::new(),
                },
            ],
            globals: vec![
                ExportGlobal {
                    rva: 0x2000,
                    size: Some(8),
                    size_attribution: Some(attribution(0.8)),
                    selected_name: Some(named("g_config", "g_config")),
                    alternate_names: Vec::new(),
                },
                ExportGlobal {
                    rva: 0x2010,
                    size: None,
                    size_attribution: None,
                    selected_name: None,
                    alternate_names: Vec::new(),
                },
            ],
            types: vec![ExportType {
                key: "type.thing".to_owned(),
                selected_name: Some(named("cls::Thing", "cls__Thing")),
                alternate_names: Vec::new(),
                definitions: vec![membership("struct Thing { int a; };", 0.7)],
            }],
            direct_calls: Vec::new(),
            thunks: Vec::new(),
            strings: Vec::new(),
            data_references: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// One debugging-information entry read back from the produced companion.
    #[derive(Debug)]
    struct ReadEntry {
        tag: gimli::DwTag,
        offset: UnitOffset,
        name: Option<String>,
        low_pc: Option<u64>,
        high_pc: Option<u64>,
        type_ref: Option<UnitOffset>,
    }

    /// Parse the ELF companion, locate the `.debug_*` sections, and read every
    /// DIE from its single compilation unit back with `gimli::read`.
    fn read_entries(bytes: &[u8]) -> Vec<ReadEntry> {
        let file = object::File::parse(bytes).expect("parse ELF companion");
        assert!(
            file.section_by_name(".debug_info").is_some(),
            ".debug_info present"
        );
        assert!(
            file.section_by_name(".debug_abbrev").is_some(),
            ".debug_abbrev present"
        );
        assert!(
            file.section_by_name(".debug_str").is_some(),
            ".debug_str present"
        );
        let endian = if file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        let load = |id: gimli::SectionId| -> Result<Cow<'_, [u8]>, gimli::Error> {
            Ok(match file.section_by_name(id.name()) {
                Some(section) => section
                    .uncompressed_data()
                    .unwrap_or(Cow::Borrowed(&[][..])),
                None => Cow::Borrowed(&[][..]),
            })
        };
        let sections = gimli::DwarfSections::load(load).expect("load DWARF sections");
        let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, endian));

        let mut entries = Vec::new();
        let mut units = dwarf.units();
        while let Some(header) = units.next().expect("unit header") {
            let unit = dwarf.unit(header).expect("unit");
            let mut cursor = unit.entries();
            while let Some((_, entry)) = cursor.next_dfs().expect("next DIE") {
                let name = entry
                    .attr_value(gimli::DW_AT_name)
                    .expect("name attr")
                    .map(|value| {
                        dwarf
                            .attr_string(&unit, value)
                            .expect("resolve name string")
                            .to_string_lossy()
                            .into_owned()
                    });
                let low_pc = match entry.attr_value(gimli::DW_AT_low_pc).expect("low_pc") {
                    Some(gimli::read::AttributeValue::Addr(value)) => Some(value),
                    _ => None,
                };
                let high_pc = match entry.attr_value(gimli::DW_AT_high_pc).expect("high_pc") {
                    Some(gimli::read::AttributeValue::Udata(value)) => Some(value),
                    _ => None,
                };
                let type_ref = match entry.attr_value(gimli::DW_AT_type).expect("type") {
                    Some(gimli::read::AttributeValue::UnitRef(offset)) => Some(offset),
                    _ => None,
                };
                entries.push(ReadEntry {
                    tag: entry.tag(),
                    offset: entry.offset(),
                    name,
                    low_pc,
                    high_pc,
                    type_ref,
                });
            }
        }
        entries
    }

    #[test]
    fn round_trip_recovers_functions_globals_and_class_inheritance() {
        let projection = projection();
        let artifact = render_dwarf(&projection).expect("render DWARF");
        let entries = read_entries(artifact.bytes());

        let base = projection.binary.image_base;

        // Compile unit.
        let unit = entries
            .iter()
            .find(|entry| entry.tag == gimli::DW_TAG_compile_unit)
            .expect("compile unit");
        assert_eq!(unit.name.as_deref(), Some(COMPILE_UNIT_NAME));
        assert_eq!(unit.low_pc, Some(base));
        assert_eq!(unit.high_pc, Some(projection.binary.image_size));

        // Both functions are emitted as subprograms; the named one carries its
        // exact source spelling and its size becomes a high_pc offset.
        let subprograms = entries
            .iter()
            .filter(|entry| entry.tag == gimli::DW_TAG_subprogram)
            .collect::<Vec<_>>();
        assert_eq!(subprograms.len(), 2);
        let named_fn = subprograms
            .iter()
            .find(|entry| entry.name.as_deref() == Some("Widget::update"))
            .expect("named subprogram");
        assert_eq!(named_fn.low_pc, Some(base + 0x1000));
        assert_eq!(named_fn.high_pc, Some(0x40));
        let unnamed_fn = subprograms
            .iter()
            .find(|entry| entry.name.is_none())
            .expect("unnamed subprogram");
        assert_eq!(unnamed_fn.low_pc, Some(base + 0x1040));
        assert_eq!(unnamed_fn.high_pc, None);

        // Only the named global becomes a variable DIE.
        let variables = entries
            .iter()
            .filter(|entry| entry.tag == gimli::DW_TAG_variable)
            .collect::<Vec<_>>();
        assert_eq!(variables.len(), 1);
        assert_eq!(variables[0].name.as_deref(), Some("g_config"));

        // Named type plus both membership classes become class DIEs.
        let classes = entries
            .iter()
            .filter(|entry| entry.tag == gimli::DW_TAG_class_type)
            .map(|entry| (entry.offset, entry.name.clone()))
            .collect::<BTreeMap<_, _>>();
        let class_names = classes.values().flatten().cloned().collect::<Vec<_>>();
        assert!(class_names.contains(&"cls::Thing".to_owned()));
        assert!(class_names.contains(&"demo::Base".to_owned()));
        assert!(class_names.contains(&"demo::Derived".to_owned()));

        // Inheritance points from the defining class to its base class DIE.
        let inheritance = entries
            .iter()
            .find(|entry| entry.tag == gimli::DW_TAG_inheritance)
            .expect("inheritance DIE");
        let base_offset = inheritance.type_ref.expect("inheritance references a base");
        assert_eq!(
            classes.get(&base_offset).and_then(Clone::clone).as_deref(),
            Some("demo::Base")
        );
    }

    #[test]
    fn rendering_is_byte_for_byte_deterministic() {
        let projection = projection();
        let first = render_dwarf(&projection).expect("first render");
        let second = render_dwarf(&projection).expect("second render");
        assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn loss_report_records_claims_dwarf_cannot_represent() {
        let projection = projection();
        let artifact = render_dwarf(&projection).expect("render DWARF");
        let loss = artifact.loss();
        assert!(!loss.is_empty());

        let occurrences = |code: ExportLossCode| {
            loss.items()
                .iter()
                .find(|item| item.code() == code)
                .map_or(0, |item| item.occurrences())
        };
        // The alternate function name and the prototype are dropped; the unnamed
        // global has no variable DIE; class memberships and type definitions are
        // not represented.
        assert_eq!(occurrences(ExportLossCode::AlternateNameOmitted), 1);
        assert_eq!(occurrences(ExportLossCode::PrototypeOmitted), 1);
        assert_eq!(occurrences(ExportLossCode::GlobalOmitted), 1);
        assert_eq!(occurrences(ExportLossCode::ClassMembershipOmitted), 2);
        assert_eq!(occurrences(ExportLossCode::TypeDefinitionOmitted), 1);
        assert!(occurrences(ExportLossCode::AttributionOmitted) > 0);
        // Every function is emitted, so no function is reported as omitted.
        assert_eq!(occurrences(ExportLossCode::FunctionOmitted), 0);
    }

    #[test]
    fn container_target_maps_known_architectures_and_defaults_safely() {
        let x86 = container_target("x86_64");
        assert_eq!(x86.architecture, Architecture::X86_64);
        assert_eq!(x86.object_endian, Endianness::Little);
        assert_eq!(x86.address_size, 8);

        let arm = container_target("elf32-arm-be");
        assert_eq!(arm.architecture, Architecture::Arm);
        assert_eq!(arm.object_endian, Endianness::Big);
        assert_eq!(arm.address_size, 4);

        let aarch64 = container_target("macho64-arm64");
        assert_eq!(aarch64.architecture, Architecture::Aarch64);
        assert_eq!(aarch64.address_size, 8);

        let unknown = container_target("vax-11");
        assert_eq!(unknown.architecture, Architecture::X86_64);
        assert_eq!(unknown.object_endian, Endianness::Little);
        assert_eq!(unknown.address_size, 8);
    }
}
