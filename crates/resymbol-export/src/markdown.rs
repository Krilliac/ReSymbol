use thiserror::Error;

use crate::{
    AttributedText, ExportAttribution, ExportBinaryFormat, ExportControlFlowTarget, ExportFunction,
    ExportName, ExportProducer, ExportProjection, ExportStringEncoding, ExportSubject,
    ProjectionValidationError, ProjectionWarningCode,
};

const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ROWS_PER_SECTION: usize = 1_024;
const MAX_ROWS_PER_SECTION_LABEL: &str = "1,024";
const MAX_CELL_SOURCE_BYTES: usize = 256;
const TRUNCATION_MARKER: &str = "… [truncated]";

/// Failure to render a bounded GitHub-Flavored Markdown report.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MarkdownError {
    #[error("the export projection is invalid: {0}")]
    InvalidProjection(#[from] ProjectionValidationError),
    #[error("the generated Markdown report exceeds {limit} bytes")]
    OutputLimitExceeded { limit: usize },
}

/// Render a deterministic, presentation-only Markdown report.
///
/// The neutral JSON projection remains the stable machine-readable artifact.
/// This writer validates that projection again, escapes every projected text
/// value, and applies independent row, cell, and aggregate output limits.
pub fn render_markdown(projection: &ExportProjection) -> Result<String, MarkdownError> {
    projection.validate()?;

    let mut report = Report::default();
    report.line("# ReSymbol Analysis Report")?;
    report.line("")?;
    report.line("> Deterministic presentation report. The neutral JSON projection remains the machine-readable interchange format.")?;

    render_identity(&mut report, projection)?;
    render_summary(&mut report, projection)?;
    render_functions(&mut report, projection)?;
    render_globals(&mut report, projection)?;
    render_types(&mut report, projection)?;
    render_strings(&mut report, projection)?;
    render_calls(&mut report, projection)?;
    render_data_references(&mut report, projection)?;
    render_thunks(&mut report, projection)?;
    render_warnings(&mut report, projection)?;

    Ok(report.finish())
}

#[derive(Default)]
struct Report {
    output: String,
}

impl Report {
    fn push(&mut self, text: &str) -> Result<(), MarkdownError> {
        if text.len() > MAX_REPORT_BYTES.saturating_sub(self.output.len()) {
            return Err(MarkdownError::OutputLimitExceeded {
                limit: MAX_REPORT_BYTES,
            });
        }
        self.output.push_str(text);
        Ok(())
    }

    fn line(&mut self, text: &str) -> Result<(), MarkdownError> {
        self.push(text)?;
        self.push("\n")
    }

    fn finish(self) -> String {
        self.output
    }
}

fn render_identity(
    report: &mut Report,
    projection: &ExportProjection,
) -> Result<(), MarkdownError> {
    section(report, "Binary identity")?;
    table_header(report, &["Field", "Value"])?;
    table_row(
        report,
        &["SHA-256".to_owned(), projection.binary.id.to_string()],
    )?;
    table_row(
        report,
        &[
            "Format".to_owned(),
            binary_format(&projection.binary.format),
        ],
    )?;
    table_row(
        report,
        &[
            "Architecture".to_owned(),
            projection.binary.architecture.clone(),
        ],
    )?;
    table_row(
        report,
        &[
            "File size".to_owned(),
            projection.binary.file_size.to_string(),
        ],
    )?;
    table_row(
        report,
        &[
            "Preferred image base".to_owned(),
            hex(projection.binary.image_base),
        ],
    )?;
    table_row(
        report,
        &[
            "Virtual image size".to_owned(),
            hex(projection.binary.image_size),
        ],
    )?;
    row_notice(report, 6, 6)
}

fn render_summary(report: &mut Report, projection: &ExportProjection) -> Result<(), MarkdownError> {
    section(report, "Summary")?;
    table_header(report, &["Item", "Count"])?;
    let rows = [
        ("Projection schema", projection.schema_version.to_string()),
        ("Functions", projection.functions.len().to_string()),
        ("Globals", projection.globals.len().to_string()),
        ("Types", projection.types.len().to_string()),
        ("Strings", projection.strings.len().to_string()),
        ("Direct calls", projection.direct_calls.len().to_string()),
        (
            "Data references",
            projection.data_references.len().to_string(),
        ),
        ("Thunks", projection.thunks.len().to_string()),
        ("Warning groups", projection.warnings.len().to_string()),
    ];
    let total = rows.len();
    for (label, count) in rows {
        table_row(report, &[label.to_owned(), count])?;
    }
    row_notice(report, total, total)
}

fn render_functions(
    report: &mut Report,
    projection: &ExportProjection,
) -> Result<(), MarkdownError> {
    section(report, "Functions")?;
    table_header(
        report,
        &[
            "RVA",
            "Size",
            "Selected name",
            "Confidence",
            "Source",
            "Details",
        ],
    )?;
    for function in projection.functions.iter().take(MAX_ROWS_PER_SECTION) {
        let attribution = function_attribution(function);
        let details = [
            summarize_texts("aliases", &function.alternate_names),
            summarize_texts("prototypes", &function.prototypes),
            summarize_texts("classes", &function.class_memberships),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
        table_row(
            report,
            &[
                hex(function.rva),
                optional_hex(function.size),
                function
                    .selected_name
                    .as_ref()
                    .map_or_else(|| "—".to_owned(), display_name),
                attribution.map_or_else(|| "—".to_owned(), confidence),
                attribution.map_or_else(|| "—".to_owned(), provenance),
                if details.is_empty() {
                    "—".to_owned()
                } else {
                    details
                },
            ],
        )?;
    }
    row_notice(
        report,
        projection.functions.len().min(MAX_ROWS_PER_SECTION),
        projection.functions.len(),
    )
}

fn render_globals(report: &mut Report, projection: &ExportProjection) -> Result<(), MarkdownError> {
    section(report, "Globals")?;
    table_header(
        report,
        &[
            "RVA",
            "Size",
            "Selected name",
            "Confidence",
            "Source",
            "Aliases",
        ],
    )?;
    for global in projection.globals.iter().take(MAX_ROWS_PER_SECTION) {
        let attribution = global
            .selected_name
            .as_ref()
            .map(|name| &name.source.attribution)
            .or(global.size_attribution.as_ref());
        table_row(
            report,
            &[
                hex(global.rva),
                optional_hex(global.size),
                global
                    .selected_name
                    .as_ref()
                    .map_or_else(|| "—".to_owned(), display_name),
                attribution.map_or_else(|| "—".to_owned(), confidence),
                attribution.map_or_else(|| "—".to_owned(), provenance),
                summarize_texts("", &global.alternate_names).unwrap_or_else(|| "—".to_owned()),
            ],
        )?;
    }
    row_notice(
        report,
        projection.globals.len().min(MAX_ROWS_PER_SECTION),
        projection.globals.len(),
    )
}

fn render_types(report: &mut Report, projection: &ExportProjection) -> Result<(), MarkdownError> {
    section(report, "Types")?;
    table_header(
        report,
        &[
            "Key",
            "Selected name",
            "Confidence",
            "Source",
            "Definitions",
            "Aliases",
        ],
    )?;
    for value in projection.types.iter().take(MAX_ROWS_PER_SECTION) {
        let attribution = value
            .selected_name
            .as_ref()
            .map(|name| &name.source.attribution)
            .or_else(|| value.definitions.first().map(|item| &item.attribution));
        table_row(
            report,
            &[
                value.key.clone(),
                value
                    .selected_name
                    .as_ref()
                    .map_or_else(|| "—".to_owned(), display_name),
                attribution.map_or_else(|| "—".to_owned(), confidence),
                attribution.map_or_else(|| "—".to_owned(), provenance),
                summarize_texts("", &value.definitions).unwrap_or_else(|| "—".to_owned()),
                summarize_texts("", &value.alternate_names).unwrap_or_else(|| "—".to_owned()),
            ],
        )?;
    }
    row_notice(
        report,
        projection.types.len().min(MAX_ROWS_PER_SECTION),
        projection.types.len(),
    )
}

fn render_strings(report: &mut Report, projection: &ExportProjection) -> Result<(), MarkdownError> {
    section(report, "Strings")?;
    table_header(
        report,
        &[
            "Encoding",
            "RVA",
            "Byte size",
            "Value",
            "Confidence",
            "Source",
        ],
    )?;
    for string in projection.strings.iter().take(MAX_ROWS_PER_SECTION) {
        table_row(
            report,
            &[
                string_encoding(string.encoding).to_owned(),
                hex(string.rva),
                string.byte_size.to_string(),
                string.value.clone(),
                confidence(&string.attribution),
                provenance(&string.attribution),
            ],
        )?;
    }
    row_notice(
        report,
        projection.strings.len().min(MAX_ROWS_PER_SECTION),
        projection.strings.len(),
    )
}

fn render_calls(report: &mut Report, projection: &ExportProjection) -> Result<(), MarkdownError> {
    section(report, "Direct calls")?;
    table_header(
        report,
        &[
            "Caller RVA",
            "Call-site RVA",
            "Target",
            "Confidence",
            "Source",
        ],
    )?;
    for call in projection.direct_calls.iter().take(MAX_ROWS_PER_SECTION) {
        table_row(
            report,
            &[
                hex(call.caller_rva),
                hex(call.call_site_rva),
                control_flow_target(&call.target),
                confidence(&call.attribution),
                provenance(&call.attribution),
            ],
        )?;
    }
    row_notice(
        report,
        projection.direct_calls.len().min(MAX_ROWS_PER_SECTION),
        projection.direct_calls.len(),
    )
}

fn render_data_references(
    report: &mut Report,
    projection: &ExportProjection,
) -> Result<(), MarkdownError> {
    section(report, "Data references")?;
    table_header(
        report,
        &[
            "Caller RVA",
            "Instruction RVA",
            "Instruction size",
            "Target RVA",
            "Confidence",
            "Source",
        ],
    )?;
    for reference in projection.data_references.iter().take(MAX_ROWS_PER_SECTION) {
        table_row(
            report,
            &[
                hex(reference.caller_rva),
                hex(reference.instruction_rva),
                reference.instruction_size.to_string(),
                hex(reference.target_rva),
                confidence(&reference.attribution),
                provenance(&reference.attribution),
            ],
        )?;
    }
    row_notice(
        report,
        projection.data_references.len().min(MAX_ROWS_PER_SECTION),
        projection.data_references.len(),
    )
}

fn render_thunks(report: &mut Report, projection: &ExportProjection) -> Result<(), MarkdownError> {
    section(report, "Thunks")?;
    table_header(report, &["RVA", "Target", "Confidence", "Source"])?;
    for thunk in projection.thunks.iter().take(MAX_ROWS_PER_SECTION) {
        table_row(
            report,
            &[
                hex(thunk.rva),
                control_flow_target(&thunk.target),
                confidence(&thunk.attribution),
                provenance(&thunk.attribution),
            ],
        )?;
    }
    row_notice(
        report,
        projection.thunks.len().min(MAX_ROWS_PER_SECTION),
        projection.thunks.len(),
    )
}

fn render_warnings(
    report: &mut Report,
    projection: &ExportProjection,
) -> Result<(), MarkdownError> {
    section(report, "Warnings")?;
    table_header(report, &["Code", "Subject", "Occurrences", "Message"])?;
    for warning in projection.warnings.iter().take(MAX_ROWS_PER_SECTION) {
        table_row(
            report,
            &[
                warning_code(warning.code).to_owned(),
                warning
                    .subject
                    .as_ref()
                    .map_or_else(|| "—".to_owned(), subject),
                warning.occurrences.to_string(),
                warning.message.clone(),
            ],
        )?;
    }
    row_notice(
        report,
        projection.warnings.len().min(MAX_ROWS_PER_SECTION),
        projection.warnings.len(),
    )
}

fn section(report: &mut Report, heading: &str) -> Result<(), MarkdownError> {
    report.line("")?;
    report.line(&format!("## {heading}"))?;
    report.line("")
}

fn table_header(report: &mut Report, headers: &[&str]) -> Result<(), MarkdownError> {
    let values = headers
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    table_row(report, &values)?;
    report.push("|")?;
    for _ in headers {
        report.push(" --- |")?;
    }
    report.push("\n")
}

fn table_row(report: &mut Report, values: &[String]) -> Result<(), MarkdownError> {
    report.push("|")?;
    for value in values {
        report.push(" ")?;
        report.push(&escape_cell(value))?;
        report.push(" |")?;
    }
    report.push("\n")
}

fn row_notice(report: &mut Report, shown: usize, total: usize) -> Result<(), MarkdownError> {
    let omitted = total.saturating_sub(shown);
    report.line("")?;
    report.line(&format!(
        "_Showing {shown} of {total} rows; {omitted} omitted by the {MAX_ROWS_PER_SECTION_LABEL}-row report limit._"
    ))
}

fn function_attribution(function: &ExportFunction) -> Option<&ExportAttribution> {
    function
        .selected_name
        .as_ref()
        .map(|name| &name.source.attribution)
        .or(function.entry_attribution.as_ref())
        .or(function.size_attribution.as_ref())
        .or_else(|| function.prototypes.first().map(|item| &item.attribution))
        .or_else(|| {
            function
                .class_memberships
                .first()
                .map(|item| &item.attribution)
        })
}

fn display_name(name: &ExportName) -> String {
    if name.source.text == name.output_name {
        name.source.text.clone()
    } else {
        format!("{} → {}", name.source.text, name.output_name)
    }
}

fn summarize_texts(label: &str, values: &[AttributedText]) -> Option<String> {
    if values.is_empty() {
        return None;
    }
    let mut summary = String::new();
    if !label.is_empty() {
        summary.push_str(label);
        summary.push_str(": ");
    }
    for (index, value) in values.iter().take(3).enumerate() {
        if index != 0 {
            summary.push_str(", ");
        }
        summary.push_str(&truncate_source(&value.text, 80));
    }
    if values.len() > 3 {
        summary.push_str(&format!(" (+{} more)", values.len() - 3));
    }
    Some(summary)
}

fn confidence(attribution: &ExportAttribution) -> String {
    attribution.confidence.to_string()
}

fn provenance(attribution: &ExportAttribution) -> String {
    let producer = match &attribution.provenance.producer {
        ExportProducer::Core { component, version } => format!("core:{component}@{version}"),
        ExportProducer::Plugin { id, version } => format!("plugin:{id}@{version}"),
        ExportProducer::User { reviewer } => reviewer
            .as_ref()
            .map_or_else(|| "user".to_owned(), |reviewer| format!("user:{reviewer}")),
    };
    let mut value = format!("{producer}; method={}", attribution.provenance.method);
    if let Some(run_id) = &attribution.provenance.run_id {
        value.push_str("; run=");
        value.push_str(run_id);
    }
    value
}

fn control_flow_target(target: &ExportControlFlowTarget) -> String {
    match target {
        ExportControlFlowTarget::Function { rva } => format!("function {}", hex(*rva)),
        ExportControlFlowTarget::ImportIat { iat_rva } => format!("import IAT {}", hex(*iat_rva)),
    }
}

fn subject(value: &ExportSubject) -> String {
    match value {
        ExportSubject::Function { rva } => format!("function {}", hex(*rva)),
        ExportSubject::Global { rva } => format!("global {}", hex(*rva)),
        ExportSubject::Type { key } => format!("type {key}"),
    }
}

fn binary_format(value: &ExportBinaryFormat) -> String {
    match value {
        ExportBinaryFormat::Pe => "PE".to_owned(),
        ExportBinaryFormat::Elf => "ELF".to_owned(),
        ExportBinaryFormat::MachO => "Mach-O".to_owned(),
        ExportBinaryFormat::Wasm => "WebAssembly".to_owned(),
        ExportBinaryFormat::Other(value) => value.clone(),
    }
}

const fn string_encoding(value: ExportStringEncoding) -> &'static str {
    match value {
        ExportStringEncoding::Ascii => "ASCII",
        ExportStringEncoding::Utf16Le => "UTF-16LE",
    }
}

const fn warning_code(value: ProjectionWarningCode) -> &'static str {
    match value {
        ProjectionWarningCode::UnsupportedAssertion => "unsupported-assertion",
        ProjectionWarningCode::AssertionSubjectMismatch => "assertion-subject-mismatch",
        ProjectionWarningCode::AddressOutsideImage => "address-outside-image",
        ProjectionWarningCode::InvalidText => "invalid-text",
        ProjectionWarningCode::TextLimitExceeded => "text-limit-exceeded",
        ProjectionWarningCode::InvalidProvenance => "invalid-provenance",
        ProjectionWarningCode::ClassMembershipLimitExceeded => "class-membership-limit-exceeded",
        ProjectionWarningCode::ConflictingSize => "conflicting-size",
        ProjectionWarningCode::AmbiguousSize => "ambiguous-size",
        ProjectionWarningCode::OverlappingFunctionRange => "overlapping-function-range",
        ProjectionWarningCode::AddressKindCollision => "address-kind-collision",
        ProjectionWarningCode::NameRewritten => "name-rewritten",
        ProjectionWarningCode::AmbiguousName => "ambiguous-name",
        ProjectionWarningCode::NameCollision => "name-collision",
    }
}

fn optional_hex(value: Option<u64>) -> String {
    value.map_or_else(|| "—".to_owned(), hex)
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn escape_cell(value: &str) -> String {
    let value = truncate_source(value, MAX_CELL_SOURCE_BYTES);
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '|' => escaped.push_str("\\|"),
            '\\' => escaped.push_str("\\\\"),
            '`' | '*' | '_' | '~' | '[' | ']' | '(' | ')' | '!' => {
                escaped.push('\\');
                escaped.push(character);
            }
            '\n' | '\r' | '\t' => escaped.push(' '),
            value if value.is_control() => escaped.push('�'),
            value => escaped.push(value),
        }
    }
    escaped
}

fn truncate_source(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let prefix_limit = maximum.saturating_sub(TRUNCATION_MARKER.len());
    let mut boundary = prefix_limit.min(value.len());
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut truncated = value[..boundary].to_owned();
    truncated.push_str(TRUNCATION_MARKER);
    truncated
}

#[cfg(test)]
mod tests {
    use resymbol_core::BinaryId;

    use super::*;
    use crate::{ExportBinary, ExportProjection};

    fn empty_projection() -> ExportProjection {
        ExportProjection {
            schema_version: 4,
            binary: ExportBinary {
                id: BinaryId::from_sha256(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .expect("valid digest"),
                file_size: 1,
                format: ExportBinaryFormat::Pe,
                architecture: "x86_64".to_owned(),
                image_base: 0x1_4000_0000,
                image_size: 0x2000,
            },
            functions: Vec::new(),
            globals: Vec::new(),
            types: Vec::new(),
            direct_calls: Vec::new(),
            thunks: Vec::new(),
            strings: Vec::new(),
            data_references: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn empty_report_is_deterministic_and_contains_every_section() {
        let projection = empty_projection();
        let first = render_markdown(&projection).expect("render report");
        let second = render_markdown(&projection).expect("render report again");

        assert_eq!(first, second);
        for heading in [
            "# ReSymbol Analysis Report",
            "## Binary identity",
            "## Summary",
            "## Functions",
            "## Globals",
            "## Types",
            "## Strings",
            "## Direct calls",
            "## Data references",
            "## Thunks",
            "## Warnings",
        ] {
            assert!(first.contains(heading), "missing {heading}");
        }
        assert!(first.contains("_Showing 0 of 0 rows; 0 omitted"));
    }

    #[test]
    fn report_escapes_markdown_and_raw_html() {
        let mut projection = empty_projection();
        projection.binary.architecture = "<script>&entity;|`*_[]()!\\".to_owned();
        let report = render_markdown(&projection).expect("render escaped report");

        assert!(!report.contains("<script>"));
        assert!(report.contains("&lt;script&gt;"));
        assert!(report.contains("&amp;entity;"));
        assert!(report.contains("\\|"));
        assert!(report.contains("\\`\\*\\_"));
    }

    #[test]
    fn cell_truncation_is_utf8_safe_and_explicit() {
        let source = format!("{}終", "é".repeat(200));
        let truncated = truncate_source(&source, MAX_CELL_SOURCE_BYTES);

        assert!(truncated.is_char_boundary(truncated.len()));
        assert!(truncated.ends_with(TRUNCATION_MARKER));
        assert!(truncated.len() <= MAX_CELL_SOURCE_BYTES);
    }

    #[test]
    fn aggregate_writer_fails_before_exceeding_its_limit() {
        let mut report = Report {
            output: "x".repeat(MAX_REPORT_BYTES),
        };
        assert_eq!(
            report.push("y"),
            Err(MarkdownError::OutputLimitExceeded {
                limit: MAX_REPORT_BYTES
            })
        );
        assert_eq!(report.output.len(), MAX_REPORT_BYTES);
    }

    #[test]
    fn confidence_does_not_round_near_certainty_up_to_one() {
        let attribution = ExportAttribution {
            confidence: 0.9999,
            provenance: crate::ExportProvenance {
                producer: ExportProducer::User { reviewer: None },
                method: "review".to_owned(),
                run_id: None,
            },
        };

        assert_eq!(confidence(&attribution), "0.9999");
    }

    #[test]
    fn invalid_projection_is_rejected_before_rendering() {
        let mut projection = empty_projection();
        projection.schema_version = 2;
        assert!(matches!(
            render_markdown(&projection),
            Err(MarkdownError::InvalidProjection(_))
        ));
    }
}
