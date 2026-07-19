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
}

#[test]
fn public_r5900_profile_returns_the_exact_always_available_decoder() {
    let profile = DecoderProfile::Ps2EeR5900LeCoreV1;
    let mut decoder = decoder_for_profile(profile).expect("pure-Rust R5900 decoder");

    assert_eq!(decoder.arch(), TargetArch::Mips64);
    assert_eq!(decoder.profile(), profile);
    assert!(matches!(
        decoder.decode_one(&0_u32.to_le_bytes(), 0),
        DecodeOutcome::Decoded(_)
    ));
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
