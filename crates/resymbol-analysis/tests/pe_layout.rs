#![forbid(unsafe_code)]

use resymbol_analysis::{analyze_pe, inspect_pe_layout};

const EXACT_PE: &[u8] =
    include_bytes!("../../../fixtures/pe-x64-msvc/artifacts/milestone2-symbolized.exe");

#[test]
fn lightweight_layout_matches_the_exact_full_analysis_headers() {
    let layout = inspect_pe_layout(EXACT_PE).expect("strict layout inspection");
    let analysis = analyze_pe(EXACT_PE).expect("full PE analysis");

    assert_eq!(layout.identity(), &analysis.identity);
    assert_eq!(layout.size_of_image(), analysis.size_of_image);
    assert_eq!(layout.size_of_headers(), analysis.size_of_headers);
    assert_eq!(layout.sections(), analysis.sections);
}

#[test]
fn malformed_layout_fails_closed() {
    let mut malformed = EXACT_PE.to_vec();
    malformed[0] = 0;
    assert!(inspect_pe_layout(&malformed).is_err());
}
