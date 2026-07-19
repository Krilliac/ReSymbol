//! Architecture-neutral single-instruction decoding.
//!
//! This module introduces a thin decoder abstraction so the higher-level
//! disassembly passes (linear preview, control-flow block sweep) can be driven
//! by more than one instruction decoder. Always-available pure-Rust backends
//! cover x86/x86-64 through `iced-x86` and the frozen PlayStation 2
//! EE/R5900 core-v1 profiles. When the optional `capstone` feature is enabled,
//! a Capstone-based backend covers a broad set of other architectures.
//!
//! The abstraction is deliberately minimal and total: every decode attempt maps
//! to exactly one [`DecodeOutcome`], and no method reads files, maps images, or
//! executes target code.

use thiserror::Error;

mod iced_x86;
pub(crate) use iced_x86::{
    IcedX64Decoder, direct_target as iced_direct_target, flow_kind as iced_flow_kind,
};

mod ps2_ee_r5900;
use ps2_ee_r5900::{Ps2EeR5900LeCoreV1Decoder, Ps2EeR5900LeCoreV1MmiWordShiftV1Decoder};

#[cfg(feature = "capstone")]
mod capstone;

/// A concrete target architecture a decoder can be requested for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    X86,
    X86_64,
    Aarch64,
    Arm,
    ArmThumb,
    Mips32,
    Mips64,
    Riscv32,
    Riscv64,
    PowerPc32,
    PowerPc64,
}

impl TargetArch {
    /// Stable human-readable identifier used in diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86-64",
            Self::Aarch64 => "aarch64",
            Self::Arm => "arm",
            Self::ArmThumb => "arm-thumb",
            Self::Mips32 => "mips32",
            Self::Mips64 => "mips64",
            Self::Riscv32 => "riscv32",
            Self::Riscv64 => "riscv64",
            Self::PowerPc32 => "powerpc32",
            Self::PowerPc64 => "powerpc64",
        }
    }
}

/// An explicit instruction-decoder selection profile.
///
/// Generic profiles preserve the existing architecture factory behavior. A
/// specialized profile names semantics that must never be approximated by a
/// generic architecture backend.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderProfile {
    Generic(TargetArch),
    Ps2EeR5900LeCoreV1,
    Ps2EeR5900LeCoreV1MmiWordShiftV1,
}

impl DecoderProfile {
    /// Stable human-readable identifier used in diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Generic(arch) => arch.name(),
            Self::Ps2EeR5900LeCoreV1 => "ps2-ee-r5900-le-core-v1",
            Self::Ps2EeR5900LeCoreV1MmiWordShiftV1 => "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1",
        }
    }
}

impl std::fmt::Display for DecoderProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Architecture-neutral control-flow classification of one decoded instruction.
///
/// The x86/x86-64 backend maps `iced-x86`'s `FlowControl` onto this enum. Two of
/// `iced-x86`'s categories have no dedicated variant here: its transactional
/// group (`XBEGIN`/`XABORT`/`XEND`) reuses [`FlowKind::Privileged`] and its
/// exception-generating group (`UD0`/`UD1`/`UD2`) reuses [`FlowKind::Invalid`].
/// `iced-x86` never reports either slot for any other instruction, so the x86
/// linear preview reproduces its original `transaction`/`exception` categories
/// exactly (see `impl From<FlowKind> for LinearFlowControlCategory`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    Sequential,
    ConditionalBranch,
    UnconditionalBranch,
    IndirectBranch,
    Call,
    IndirectCall,
    Return,
    Interrupt,
    Privileged,
    Invalid,
}

/// A recognized instruction class deliberately outside the selected decoder
/// profile's supported semantic subset.
///
/// These classes identify an opcode space, not a claim that the word is a
/// valid member of that instruction family.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedInstructionClass {
    Ps2EeMmiEncoding,
    Ps2EeCop0Encoding,
    Ps2EeCop1Encoding,
    Ps2EeCop2Encoding,
    Ps2EeVuMacroEncoding,
    Ps2EeConditionalTrapEncoding,
}

impl UnsupportedInstructionClass {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Ps2EeMmiEncoding => "ps2-ee-mmi-encoding",
            Self::Ps2EeCop0Encoding => "ps2-ee-cop0-encoding",
            Self::Ps2EeCop1Encoding => "ps2-ee-cop1-encoding",
            Self::Ps2EeCop2Encoding => "ps2-ee-cop2-encoding",
            Self::Ps2EeVuMacroEncoding => "ps2-ee-vu-macro-encoding",
            Self::Ps2EeConditionalTrapEncoding => "ps2-ee-conditional-trap-encoding",
        }
    }
}

/// One successfully decoded instruction, described architecture-neutrally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: u64,
    pub length: u8,
    pub text: String,
    pub flow: FlowKind,
    pub direct_target: Option<u64>,
}

/// Total result of a single-instruction decode attempt.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeOutcome {
    Decoded(DecodedInstruction),
    Invalid,
    Truncated { available: usize },
    Unsupported { class: UnsupportedInstructionClass },
}

/// A stateless-per-call single-instruction decoder for one architecture.
pub trait InstructionDecoder {
    /// The architecture this decoder decodes.
    fn arch(&self) -> TargetArch;

    /// The authoritative exact decoder identity.
    ///
    /// Existing generic decoders inherit their broad architecture identity;
    /// specialized decoders override this method with their precise profile.
    fn profile(&self) -> DecoderProfile {
        DecoderProfile::Generic(self.arch())
    }

    /// Decode exactly one instruction from the start of `bytes`, treating the
    /// first byte as located at `address`. Trailing bytes beyond the first
    /// instruction are ignored. Insufficient bytes yield
    /// [`DecodeOutcome::Truncated`]; an undecodable encoding yields
    /// [`DecodeOutcome::Invalid`]. Recognized opcode spaces deliberately
    /// outside the selected profile yield [`DecodeOutcome::Unsupported`].
    fn decode_one(&mut self, bytes: &[u8], address: u64) -> DecodeOutcome;
}

/// No decoder is available for the requested architecture.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UnsupportedArchError {
    #[error(
        "no decoder is available for {arch}; enable the `capstone` feature to decode this architecture"
    )]
    FeatureRequired { arch: &'static str },
    #[error("the Capstone backend could not be initialized for {arch}: {reason}")]
    BackendUnavailable { arch: &'static str, reason: String },
}

/// No decoder is available for the requested explicit profile.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecoderProfileError {
    #[error(transparent)]
    GenericArchitecture(#[from] UnsupportedArchError),
    #[error("decoder profile `{profile}` is declared but no implementation is available")]
    Unavailable { profile: DecoderProfile },
}

/// Construct a boxed decoder for `arch`.
///
/// `X86` and `X86_64` always return the pure-Rust `iced-x86` backend. Every
/// other architecture is served by the Capstone backend when the `capstone`
/// feature is enabled, and otherwise reports [`UnsupportedArchError`].
pub fn decoder_for(arch: TargetArch) -> Result<Box<dyn InstructionDecoder>, UnsupportedArchError> {
    match arch {
        TargetArch::X86 => Ok(Box::new(IcedX64Decoder::new_x86())),
        TargetArch::X86_64 => Ok(Box::new(IcedX64Decoder::new_x86_64())),
        other => decoder_for_non_x86(other),
    }
}

/// Construct a boxed decoder for an explicit selection profile.
///
/// Generic profiles delegate to [`decoder_for`]. The PlayStation 2 Emotion
/// Engine/R5900 profiles return their dedicated pure-Rust decoders without
/// consulting Capstone or any generic MIPS backend.
pub fn decoder_for_profile(
    profile: DecoderProfile,
) -> Result<Box<dyn InstructionDecoder>, DecoderProfileError> {
    match profile {
        DecoderProfile::Generic(arch) => decoder_for(arch).map_err(Into::into),
        DecoderProfile::Ps2EeR5900LeCoreV1 => Ok(Box::new(Ps2EeR5900LeCoreV1Decoder::new())),
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1 => {
            Ok(Box::new(Ps2EeR5900LeCoreV1MmiWordShiftV1Decoder::new()))
        }
    }
}

#[cfg(feature = "capstone")]
fn decoder_for_non_x86(
    arch: TargetArch,
) -> Result<Box<dyn InstructionDecoder>, UnsupportedArchError> {
    capstone::CapstoneDecoder::new(arch)
        .map(|decoder| Box::new(decoder) as Box<dyn InstructionDecoder>)
}

#[cfg(not(feature = "capstone"))]
fn decoder_for_non_x86(
    arch: TargetArch,
) -> Result<Box<dyn InstructionDecoder>, UnsupportedArchError> {
    Err(UnsupportedArchError::FeatureRequired { arch: arch.name() })
}

/// Map an analysis `architecture` identity string to a [`TargetArch`].
///
/// Known mappings use the exact strings produced by the ELF, Mach-O, and PE
/// parsers. Unknown or deliberately unmodeled strings return `None`. In
/// particular, ELF `EM_MIPS` identities intentionally return `None`: the
/// container field does not identify a sufficiently precise ISA profile, so
/// this mapper never infers generic MIPS decoding. Callers may still request a
/// generic MIPS target explicitly.
#[must_use]
pub fn target_arch_for_identity(architecture: &str) -> Option<TargetArch> {
    match architecture {
        // PE (always PE32+ x86-64 in this crate).
        "x86_64" => Some(TargetArch::X86_64),

        // Mach-O canonical strings.
        "macho64-x86-64" => Some(TargetArch::X86_64),
        "macho32-x86" => Some(TargetArch::X86),
        "macho64-arm64" => Some(TargetArch::Aarch64),
        "macho32-arm" => Some(TargetArch::Arm),
        "macho32-ppc" => Some(TargetArch::PowerPc32),
        "macho64-ppc64" => Some(TargetArch::PowerPc64),

        // ELF canonical strings. x86-64 and aarch64 carry no endianness suffix;
        // every other ELF architecture is emitted with a `-le`/`-be` suffix.
        "elf64-x86-64" => Some(TargetArch::X86_64),
        "elf32-x86-le" | "elf32-x86-be" => Some(TargetArch::X86),
        "elf64-aarch64" => Some(TargetArch::Aarch64),
        "elf32-arm-le" | "elf32-arm-be" => Some(TargetArch::Arm),
        "elf32-riscv-le" | "elf32-riscv-be" => Some(TargetArch::Riscv32),
        "elf64-riscv-le" | "elf64-riscv-be" => Some(TargetArch::Riscv64),
        "elf32-ppc-le" | "elf32-ppc-be" => Some(TargetArch::PowerPc32),
        "elf64-ppc64-le" | "elf64-ppc64-be" => Some(TargetArch::PowerPc64),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_strings_map_to_expected_architectures() {
        assert_eq!(target_arch_for_identity("x86_64"), Some(TargetArch::X86_64));
        assert_eq!(
            target_arch_for_identity("elf64-x86-64"),
            Some(TargetArch::X86_64)
        );
        assert_eq!(
            target_arch_for_identity("elf64-aarch64"),
            Some(TargetArch::Aarch64)
        );
        assert_eq!(
            target_arch_for_identity("elf32-arm-le"),
            Some(TargetArch::Arm)
        );
        assert_eq!(
            target_arch_for_identity("elf32-riscv-le"),
            Some(TargetArch::Riscv32)
        );
        assert_eq!(
            target_arch_for_identity("elf64-riscv-le"),
            Some(TargetArch::Riscv64)
        );
        assert_eq!(
            target_arch_for_identity("elf32-ppc-le"),
            Some(TargetArch::PowerPc32)
        );
        assert_eq!(
            target_arch_for_identity("elf64-ppc64-be"),
            Some(TargetArch::PowerPc64)
        );
        assert_eq!(
            target_arch_for_identity("macho64-arm64"),
            Some(TargetArch::Aarch64)
        );
        assert_eq!(
            target_arch_for_identity("macho64-x86-64"),
            Some(TargetArch::X86_64)
        );
        assert_eq!(
            target_arch_for_identity("macho32-arm"),
            Some(TargetArch::Arm)
        );
        assert_eq!(
            target_arch_for_identity("macho64-ppc64"),
            Some(TargetArch::PowerPc64)
        );
    }

    #[test]
    fn em_mips_container_identities_do_not_infer_a_generic_mips_architecture() {
        for architecture in [
            "elf32-em-mips-le",
            "elf32-em-mips-be",
            "elf64-em-mips-le",
            "elf64-em-mips-be",
        ] {
            assert_eq!(target_arch_for_identity(architecture), None);
        }
    }

    #[test]
    fn unknown_identity_strings_are_none() {
        assert_eq!(target_arch_for_identity(""), None);
        assert_eq!(target_arch_for_identity("elf64-em-0x00f3-le"), None);
        assert_eq!(target_arch_for_identity("macho64-cputype-4660"), None);
        assert_eq!(target_arch_for_identity("sparc"), None);
    }

    #[test]
    fn x86_decoders_are_always_available() {
        assert_eq!(
            decoder_for(TargetArch::X86_64)
                .expect("x86-64 decoder")
                .arch(),
            TargetArch::X86_64
        );
        assert_eq!(
            decoder_for(TargetArch::X86).expect("x86 decoder").arch(),
            TargetArch::X86
        );
    }

    #[test]
    fn decoder_profile_names_are_stable() {
        assert_eq!(DecoderProfile::Generic(TargetArch::X86_64).name(), "x86-64");
        assert_eq!(
            DecoderProfile::Ps2EeR5900LeCoreV1.name(),
            "ps2-ee-r5900-le-core-v1"
        );
        assert_eq!(
            DecoderProfile::Ps2EeR5900LeCoreV1.to_string(),
            "ps2-ee-r5900-le-core-v1"
        );
        assert_eq!(
            DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1.name(),
            "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1"
        );
        assert_eq!(
            DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1.to_string(),
            "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1"
        );
    }

    #[test]
    fn specialized_r5900_profile_uses_the_exact_decoder() {
        for profile in [
            DecoderProfile::Ps2EeR5900LeCoreV1,
            DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1,
        ] {
            let decoder = decoder_for_profile(profile).expect("always-available R5900 decoder");

            assert_eq!(decoder.arch(), TargetArch::Mips64);
            assert_eq!(decoder.profile(), profile);
        }
    }

    #[cfg(not(feature = "capstone"))]
    #[test]
    fn non_x86_requires_the_capstone_feature() {
        for arch in [
            TargetArch::Aarch64,
            TargetArch::Arm,
            TargetArch::ArmThumb,
            TargetArch::Mips32,
            TargetArch::Mips64,
            TargetArch::Riscv32,
            TargetArch::Riscv64,
            TargetArch::PowerPc32,
            TargetArch::PowerPc64,
        ] {
            assert!(matches!(
                decoder_for(arch),
                Err(UnsupportedArchError::FeatureRequired { .. })
            ));
        }
    }
}
