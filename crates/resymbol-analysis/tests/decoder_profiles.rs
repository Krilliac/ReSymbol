use resymbol_analysis::{
    DecodeOutcome, DecoderProfile, TargetArch, decoder_for_profile, target_arch_for_identity,
};
#[cfg(not(feature = "capstone"))]
use resymbol_analysis::{DecoderProfileError, UnsupportedArchError};

#[test]
fn public_profile_names_are_exact_and_stable() {
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
    assert_eq!(
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1.name(),
        "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1"
    );
    assert_eq!(
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1.to_string(),
        "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1"
    );
    assert_eq!(
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1.name(),
        "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1-packed-add-v1"
    );
    assert_eq!(
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1.to_string(),
        "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1-packed-add-v1"
    );
    assert_eq!(
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1
            .name(),
        "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1-packed-add-v1-packed-sub-v1"
    );
    assert_eq!(
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1
            .to_string(),
        "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1-packed-add-v1-packed-sub-v1"
    );
    assert_eq!(
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1
            .name(),
        "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1-packed-add-v1-packed-sub-v1-packed-compare-gt-v1"
    );
    assert_eq!(
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1
            .to_string(),
        "ps2-ee-r5900-le-core-v1-mmi-word-shift-v1-packed-logical-v1-packed-add-v1-packed-sub-v1-packed-compare-gt-v1"
    );
}

#[test]
fn public_r5900_profile_returns_the_exact_always_available_decoder() {
    for profile in [
        DecoderProfile::Ps2EeR5900LeCoreV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1,
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1,
    ] {
        let mut decoder = decoder_for_profile(profile).expect("pure-Rust R5900 decoder");

        assert_eq!(decoder.arch(), TargetArch::Mips64);
        assert_eq!(decoder.profile(), profile);
        assert!(matches!(
            decoder.decode_one(&0_u32.to_le_bytes(), 0),
            DecodeOutcome::Decoded(_)
        ));
    }
}

#[test]
fn public_latest_r5900_alias_resolves_before_the_factory_is_used() {
    let exact =
        DecoderProfile::Ps2EeR5900LeCoreV1MmiWordShiftV1PackedLogicalV1PackedAddV1PackedSubV1PackedCompareGtV1;

    assert_eq!(DecoderProfile::PS2_EE_R5900_LATEST, exact);
    let decoder = decoder_for_profile(DecoderProfile::PS2_EE_R5900_LATEST)
        .expect("latest bundled R5900 decoder");
    assert_eq!(decoder.profile(), exact);
    assert_eq!(decoder.profile().name(), exact.name());
}

#[test]
fn public_generic_x86_profile_delegates_to_the_existing_factory() {
    let mut decoder = decoder_for_profile(DecoderProfile::Generic(TargetArch::X86_64))
        .expect("x86-64 decoder is always available");

    assert_eq!(decoder.arch(), TargetArch::X86_64);
    assert_eq!(
        decoder.profile(),
        DecoderProfile::Generic(TargetArch::X86_64)
    );
    assert!(matches!(
        decoder.decode_one(&[0xc3], 0x1000),
        resymbol_analysis::DecodeOutcome::Decoded(_)
    ));
}

#[cfg(not(feature = "capstone"))]
#[test]
fn public_generic_backend_error_is_wrapped_without_relabeling() {
    let result = decoder_for_profile(DecoderProfile::Generic(TargetArch::Aarch64));

    assert!(matches!(
        result,
        Err(DecoderProfileError::GenericArchitecture(
            UnsupportedArchError::FeatureRequired { arch: "aarch64" }
        ))
    ));
}

#[test]
fn public_em_mips_identities_still_never_infer_a_profile_or_generic_architecture() {
    for identity in [
        "elf32-em-mips-le",
        "elf32-em-mips-be",
        "elf64-em-mips-le",
        "elf64-em-mips-be",
    ] {
        assert_eq!(target_arch_for_identity(identity), None);
    }
}
