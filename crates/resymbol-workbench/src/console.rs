//! Typed commands and presentation helpers for the companion console.
//!
//! This module deliberately does not own a terminal, a GUI lifecycle, or an
//! IPC transport. The workbench can keep the console opt-in and move these
//! bounded commands over an external companion-process channel without
//! coupling background input to the egui event loop.

use std::{
    fmt,
    io::{self, BufRead},
    path::PathBuf,
    time::Duration,
};

use serde::{Deserialize, Serialize};

/// Maximum accepted command-line size, in UTF-8 bytes (excluding CR/LF).
pub const MAX_COMMAND_LINE_BYTES: usize = 4096;

/// Maximum size of one formatted result or activity line, in UTF-8 bytes.
pub const MAX_CONSOLE_OUTPUT_BYTES: usize = 4096;

/// Prompt rendered by the companion console.
pub const CONSOLE_PROMPT: &str = "resymbol> ";

/// Short startup text for an explicitly enabled companion console.
pub const CONSOLE_BANNER: &str = concat!(
    "ReSymbol companion console ",
    env!("CARGO_PKG_VERSION"),
    "\n",
    "Type `help` to list commands. Console commands are handled by the workbench.\n"
);

/// User-facing command reference shared by the parser and console host.
pub const HELP_TEXT: &str = "\
Commands:
  help
  status
  open <path>
  tab <overview|functions|types|relationships|graph|address-space|debugger-sandbox|exports>
  focus <0xRVA|decimal>
  theme <graphite|light|ida|classic>
  panel <left|right|bottom> <show|hide|toggle>
  reset-layout
  export <resym|json|markdown|map|pdb|ida-python|ghidra-java> <path>
  quit  (close the workbench)

Paths containing spaces must be enclosed in double quotes. Backslashes in
Windows and UNC paths are preserved; use \\\" for a literal double quote.\n";

/// A validated command sent from the companion console to the GUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", content = "arguments", rename_all = "kebab-case")]
pub enum ConsoleCommand {
    Help,
    Status,
    Open(PathBuf),
    Tab(ConsoleTab),
    Focus(u64),
    Theme(ConsoleTheme),
    Panel {
        panel: ConsolePanel,
        action: ConsolePanelAction,
    },
    ResetLayout,
    Export {
        kind: ConsoleExportKind,
        path: PathBuf,
    },
    Quit,
}

/// Typed helper-to-workbench wire frame.
///
/// This is public only because Cargo binaries consume the package library.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "kebab-case")]
pub enum ConsoleToHostFrame {
    Ready,
    Command(String),
    Fatal(String),
}

/// Main workbench destinations accepted by the `tab` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsoleTab {
    Overview,
    Functions,
    Types,
    Relationships,
    Graph,
    AddressSpace,
    DebuggerSandbox,
    Exports,
}

impl ConsoleTab {
    pub const ALL: [Self; 8] = [
        Self::Overview,
        Self::Functions,
        Self::Types,
        Self::Relationships,
        Self::Graph,
        Self::AddressSpace,
        Self::DebuggerSandbox,
        Self::Exports,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Functions => "functions",
            Self::Types => "types",
            Self::Relationships => "relationships",
            Self::Graph => "graph",
            Self::AddressSpace => "address-space",
            Self::DebuggerSandbox => "debugger-sandbox",
            Self::Exports => "exports",
        }
    }
}

/// Workbench theme names accepted by the `theme` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsoleTheme {
    Graphite,
    Light,
    Ida,
    Classic,
}

impl ConsoleTheme {
    pub const ALL: [Self; 4] = [Self::Graphite, Self::Light, Self::Ida, Self::Classic];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Graphite => "graphite",
            Self::Light => "light",
            Self::Ida => "ida",
            Self::Classic => "classic",
        }
    }
}

/// Dockable workbench regions accepted by the `panel` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsolePanel {
    Left,
    Right,
    Bottom,
}

impl ConsolePanel {
    pub const ALL: [Self; 3] = [Self::Left, Self::Right, Self::Bottom];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
            Self::Bottom => "bottom",
        }
    }
}

/// Visibility changes accepted by the `panel` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsolePanelAction {
    Show,
    Hide,
    Toggle,
}

impl ConsolePanelAction {
    pub const ALL: [Self; 3] = [Self::Show, Self::Hide, Self::Toggle];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Show => "show",
            Self::Hide => "hide",
            Self::Toggle => "toggle",
        }
    }
}

/// Artifact formats accepted by the `export` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsoleExportKind {
    Resym,
    Json,
    Markdown,
    Map,
    Pdb,
    IdaPython,
    GhidraJava,
}

impl ConsoleExportKind {
    pub const ALL: [Self; 7] = [
        Self::Resym,
        Self::Json,
        Self::Markdown,
        Self::Map,
        Self::Pdb,
        Self::IdaPython,
        Self::GhidraJava,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resym => "resym",
            Self::Json => "json",
            Self::Markdown => "markdown",
            Self::Map => "map",
            Self::Pdb => "pdb",
            Self::IdaPython => "ida-python",
            Self::GhidraJava => "ghidra-java",
        }
    }
}

macro_rules! impl_display_as_str {
    ($($type:ty),+ $(,)?) => {
        $(
            impl fmt::Display for $type {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(self.as_str())
                }
            }
        )+
    };
}

impl_display_as_str!(
    ConsoleTab,
    ConsoleTheme,
    ConsolePanel,
    ConsolePanelAction,
    ConsoleExportKind,
);

/// Parse one bounded companion-console line into a typed GUI command.
///
/// The tokenizer follows Windows-friendly quote behavior: ordinary
/// backslashes are preserved, while runs of backslashes immediately before a
/// quote determine whether that quote is structural or literal. The parser
/// never invokes a shell and performs no filesystem access.
pub fn parse_command(input: &str) -> Result<ConsoleCommand, String> {
    let line = strip_one_line_ending(input);
    if line.len() > MAX_COMMAND_LINE_BYTES {
        return Err(format!(
            "command is too long (maximum {MAX_COMMAND_LINE_BYTES} UTF-8 bytes)"
        ));
    }
    if line
        .chars()
        .any(|character| character.is_control() && character != '\t')
    {
        return Err("command contains an unsupported control character".to_owned());
    }

    let tokens = tokenize(line)?;
    let Some(command) = tokens.first() else {
        return Err("command is empty; type `help` for available commands".to_owned());
    };
    let normalized = command.to_ascii_lowercase();

    match normalized.as_str() {
        "help" => {
            expect_arity(&tokens, 0, "help")?;
            Ok(ConsoleCommand::Help)
        }
        "status" => {
            expect_arity(&tokens, 0, "status")?;
            Ok(ConsoleCommand::Status)
        }
        "open" => {
            expect_arity(&tokens, 1, "open <path>")?;
            Ok(ConsoleCommand::Open(parse_path(&tokens[1], "open")?))
        }
        "tab" => {
            expect_arity(
                &tokens,
                1,
                "tab <overview|functions|types|relationships|graph|address-space|debugger-sandbox|exports>",
            )?;
            Ok(ConsoleCommand::Tab(parse_tab(&tokens[1])?))
        }
        "focus" => {
            expect_arity(&tokens, 1, "focus <0xRVA|decimal>")?;
            Ok(ConsoleCommand::Focus(parse_rva(&tokens[1])?))
        }
        "theme" => {
            expect_arity(&tokens, 1, "theme <graphite|light|ida|classic>")?;
            Ok(ConsoleCommand::Theme(parse_theme(&tokens[1])?))
        }
        "panel" => {
            expect_arity(&tokens, 2, "panel <left|right|bottom> <show|hide|toggle>")?;
            Ok(ConsoleCommand::Panel {
                panel: parse_panel(&tokens[1])?,
                action: parse_panel_action(&tokens[2])?,
            })
        }
        "reset-layout" => {
            expect_arity(&tokens, 0, "reset-layout")?;
            Ok(ConsoleCommand::ResetLayout)
        }
        "export" => {
            expect_arity(
                &tokens,
                2,
                "export <resym|json|markdown|map|pdb|ida-python|ghidra-java> <path>",
            )?;
            Ok(ConsoleCommand::Export {
                kind: parse_export_kind(&tokens[1])?,
                path: parse_path(&tokens[2], "export")?,
            })
        }
        "quit" => {
            expect_arity(&tokens, 0, "quit")?;
            Ok(ConsoleCommand::Quit)
        }
        _ => Err(format!(
            "unknown command `{command}`; type `help` for available commands"
        )),
    }
}

/// Format a one-line acknowledgement or error for the console host.
#[must_use]
pub fn format_command_result(success: bool, message: &str) -> String {
    let status = if success { "ok" } else { "error" };
    bounded_single_line(&format!("[{status}] "), message)
}

/// Format a timestamped internal activity line for the live console stream.
#[must_use]
pub fn format_activity(elapsed: Duration, level_str: &str, message: &str) -> String {
    let total_seconds = elapsed.as_secs();
    let hours = total_seconds / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    let level = bounded_fragment(level_str.trim(), 24);
    let level = if level.is_empty() {
        "INFO".to_owned()
    } else {
        level.to_ascii_uppercase()
    };
    let prefix = format!(
        "[{hours:02}:{minutes:02}:{seconds:02}.{:03}] [{level}] ",
        elapsed.subsec_millis(),
    );
    bounded_single_line(&prefix, message)
}

/// Return the bounded startup banner for the companion transport.
#[must_use]
pub fn format_banner() -> String {
    CONSOLE_BANNER.to_owned()
}

/// Return the bounded command reference for the companion transport.
#[must_use]
pub fn format_help() -> String {
    HELP_TEXT.to_owned()
}

/// Return the prompt for the companion transport.
#[must_use]
pub fn format_prompt() -> String {
    CONSOLE_PROMPT.to_owned()
}

/// Read one UTF-8 line without allowing an unterminated input to grow memory
/// beyond `maximum_bytes`.
///
/// The returned line retains its CR/LF terminator when present. Oversized
/// input is drained through the next newline before an `InvalidData` error is
/// returned, so a caller may either recover or close the transport.
#[doc(hidden)]
pub fn read_bounded_line(
    reader: &mut impl BufRead,
    maximum_bytes: usize,
) -> io::Result<Option<String>> {
    let mut bytes = Vec::with_capacity(maximum_bytes.min(256));
    loop {
        let (consumed, ended, oversized) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(None);
                }
                break;
            }
            let consumed = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            let ended = available[consumed - 1] == b'\n';
            let oversized = bytes.len().saturating_add(consumed) > maximum_bytes;
            if !oversized {
                bytes.extend_from_slice(&available[..consumed]);
            }
            (consumed, ended, oversized)
        };
        reader.consume(consumed);
        if oversized {
            if !ended {
                drain_through_newline(reader)?;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line exceeds the {maximum_bytes}-byte transport limit"),
            ));
        }
        if ended {
            break;
        }
    }
    String::from_utf8(bytes).map(Some).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line is not valid UTF-8: {error}"),
        )
    })
}

fn drain_through_newline(reader: &mut impl BufRead) -> io::Result<()> {
    loop {
        let (consumed, ended) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                return Ok(());
            }
            let consumed = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            (consumed, available[consumed - 1] == b'\n')
        };
        reader.consume(consumed);
        if ended {
            return Ok(());
        }
    }
}

fn strip_one_line_ending(input: &str) -> &str {
    input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input)
}

fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let characters: Vec<char> = line.chars().collect();
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut token_started = false;
    let mut in_quotes = false;
    let mut index = 0;

    while index < characters.len() {
        let character = characters[index];
        if !in_quotes && character.is_whitespace() {
            if token_started {
                tokens.push(std::mem::take(&mut token));
                token_started = false;
            }
            index += 1;
            continue;
        }

        if character == '\\' {
            let run_start = index;
            while index < characters.len() && characters[index] == '\\' {
                index += 1;
            }
            let backslash_count = index - run_start;
            token_started = true;

            if index < characters.len() && characters[index] == '"' {
                token.extend(std::iter::repeat_n('\\', backslash_count / 2));
                if backslash_count % 2 == 0 {
                    in_quotes = !in_quotes;
                } else {
                    token.push('"');
                }
                index += 1;
            } else {
                token.extend(std::iter::repeat_n('\\', backslash_count));
            }
            continue;
        }

        if character == '"' {
            token_started = true;
            in_quotes = !in_quotes;
            index += 1;
            continue;
        }

        token_started = true;
        token.push(character);
        index += 1;
    }

    if in_quotes {
        return Err("unterminated double quote".to_owned());
    }
    if token_started {
        tokens.push(token);
    }
    Ok(tokens)
}

fn expect_arity(tokens: &[String], expected: usize, usage: &'static str) -> Result<(), String> {
    let actual = tokens.len().saturating_sub(1);
    if actual == expected {
        Ok(())
    } else {
        Err(format!("usage: {usage}"))
    }
}

fn parse_path(value: &str, command: &'static str) -> Result<PathBuf, String> {
    if value.is_empty() {
        Err(format!("{command} path cannot be empty"))
    } else {
        Ok(PathBuf::from(value))
    }
}

fn parse_tab(value: &str) -> Result<ConsoleTab, String> {
    match value.to_ascii_lowercase().as_str() {
        "overview" => Ok(ConsoleTab::Overview),
        "functions" => Ok(ConsoleTab::Functions),
        "types" => Ok(ConsoleTab::Types),
        "relationships" => Ok(ConsoleTab::Relationships),
        "graph" => Ok(ConsoleTab::Graph),
        "address-space" | "memory-map" => Ok(ConsoleTab::AddressSpace),
        "debugger-sandbox" | "sandbox" | "readiness" => Ok(ConsoleTab::DebuggerSandbox),
        "exports" => Ok(ConsoleTab::Exports),
        _ => Err(format!(
            "invalid tab `{value}`; expected overview, functions, types, relationships, graph, address-space, debugger-sandbox, or exports"
        )),
    }
}

fn parse_rva(value: &str) -> Result<u64, String> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));
    let valid = !digits.is_empty()
        && match radix {
            16 => digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
            _ => digits.bytes().all(|byte| byte.is_ascii_digit()),
        };
    if !valid {
        return Err(format!(
            "invalid RVA `{value}`; expected hexadecimal 0x... or unsigned decimal"
        ));
    }
    u64::from_str_radix(digits, radix).map_err(|_| {
        format!("RVA `{value}` is outside the supported unsigned 64-bit address range")
    })
}

fn parse_theme(value: &str) -> Result<ConsoleTheme, String> {
    match value.to_ascii_lowercase().as_str() {
        "graphite" => Ok(ConsoleTheme::Graphite),
        "light" => Ok(ConsoleTheme::Light),
        "ida" => Ok(ConsoleTheme::Ida),
        "classic" => Ok(ConsoleTheme::Classic),
        _ => Err(format!(
            "invalid theme `{value}`; expected graphite, light, ida, or classic"
        )),
    }
}

fn parse_panel(value: &str) -> Result<ConsolePanel, String> {
    match value.to_ascii_lowercase().as_str() {
        "left" => Ok(ConsolePanel::Left),
        "right" => Ok(ConsolePanel::Right),
        "bottom" => Ok(ConsolePanel::Bottom),
        _ => Err(format!(
            "invalid panel `{value}`; expected left, right, or bottom"
        )),
    }
}

fn parse_panel_action(value: &str) -> Result<ConsolePanelAction, String> {
    match value.to_ascii_lowercase().as_str() {
        "show" => Ok(ConsolePanelAction::Show),
        "hide" => Ok(ConsolePanelAction::Hide),
        "toggle" => Ok(ConsolePanelAction::Toggle),
        _ => Err(format!(
            "invalid panel action `{value}`; expected show, hide, or toggle"
        )),
    }
}

fn parse_export_kind(value: &str) -> Result<ConsoleExportKind, String> {
    match value.to_ascii_lowercase().as_str() {
        "resym" => Ok(ConsoleExportKind::Resym),
        "json" => Ok(ConsoleExportKind::Json),
        "markdown" => Ok(ConsoleExportKind::Markdown),
        "map" => Ok(ConsoleExportKind::Map),
        "pdb" => Ok(ConsoleExportKind::Pdb),
        "ida" | "ida-python" => Ok(ConsoleExportKind::IdaPython),
        "ghidra" | "ghidra-java" => Ok(ConsoleExportKind::GhidraJava),
        _ => Err(format!(
            "invalid export kind `{value}`; expected resym, json, markdown, map, pdb, ida-python, or ghidra-java"
        )),
    }
}

fn bounded_single_line(prefix: &str, message: &str) -> String {
    let mut output = bounded_fragment(prefix, MAX_CONSOLE_OUTPUT_BYTES);
    let remaining = MAX_CONSOLE_OUTPUT_BYTES.saturating_sub(output.len());
    output.push_str(&bounded_fragment(message, remaining));
    output
}

fn bounded_fragment(value: &str, maximum_bytes: usize) -> String {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if output.len() + character.len_utf8() > maximum_bytes {
            break;
        }
        output.push(character);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_every_command_shape() {
        let cases = [
            ("help", ConsoleCommand::Help),
            ("status", ConsoleCommand::Status),
            (
                "open sample.exe",
                ConsoleCommand::Open(PathBuf::from("sample.exe")),
            ),
            ("tab graph", ConsoleCommand::Tab(ConsoleTab::Graph)),
            (
                "tab address-space",
                ConsoleCommand::Tab(ConsoleTab::AddressSpace),
            ),
            (
                "tab memory-map",
                ConsoleCommand::Tab(ConsoleTab::AddressSpace),
            ),
            (
                "tab debugger-sandbox",
                ConsoleCommand::Tab(ConsoleTab::DebuggerSandbox),
            ),
            ("focus 0x401000", ConsoleCommand::Focus(0x401000)),
            (
                "theme classic",
                ConsoleCommand::Theme(ConsoleTheme::Classic),
            ),
            (
                "panel bottom toggle",
                ConsoleCommand::Panel {
                    panel: ConsolePanel::Bottom,
                    action: ConsolePanelAction::Toggle,
                },
            ),
            ("reset-layout", ConsoleCommand::ResetLayout),
            (
                "export markdown report.md",
                ConsoleCommand::Export {
                    kind: ConsoleExportKind::Markdown,
                    path: PathBuf::from("report.md"),
                },
            ),
            (
                "export pdb symbols.pdb",
                ConsoleCommand::Export {
                    kind: ConsoleExportKind::Pdb,
                    path: PathBuf::from("symbols.pdb"),
                },
            ),
            (
                "export ida-python import.py",
                ConsoleCommand::Export {
                    kind: ConsoleExportKind::IdaPython,
                    path: PathBuf::from("import.py"),
                },
            ),
            (
                "export ghidra-java ReSymbolImport_deadbeefcafe.java",
                ConsoleCommand::Export {
                    kind: ConsoleExportKind::GhidraJava,
                    path: PathBuf::from("ReSymbolImport_deadbeefcafe.java"),
                },
            ),
            ("quit", ConsoleCommand::Quit),
        ];

        for (input, expected) in cases {
            assert_eq!(parse_command(input), Ok(expected), "input: {input}");
        }
    }

    #[test]
    fn preserves_quoted_windows_and_unc_paths() {
        assert_eq!(
            parse_command(r#"open "C:\Program Files\ReSymbol\input.exe""#),
            Ok(ConsoleCommand::Open(PathBuf::from(
                r"C:\Program Files\ReSymbol\input.exe"
            )))
        );
        assert_eq!(
            parse_command(r#"export json "\\server\analysis share\result.json""#),
            Ok(ConsoleCommand::Export {
                kind: ConsoleExportKind::Json,
                path: PathBuf::from(r"\\server\analysis share\result.json"),
            })
        );
    }

    #[test]
    fn applies_windows_backslash_rules_before_quotes() {
        assert_eq!(
            parse_command(r#"open "C:\symbols\name \"quoted\".pdb""#),
            Ok(ConsoleCommand::Open(PathBuf::from(
                "C:\\symbols\\name \"quoted\".pdb"
            )))
        );
        assert_eq!(
            parse_command(r#"open "C:\Program Files\ReSymbol\\""#),
            Ok(ConsoleCommand::Open(PathBuf::from(
                "C:\\Program Files\\ReSymbol\\"
            )))
        );
    }

    #[test]
    fn enforces_the_utf8_byte_limit() {
        let mut maximum = String::from("status");
        maximum.push_str(&" ".repeat(MAX_COMMAND_LINE_BYTES - maximum.len()));
        assert_eq!(parse_command(&maximum), Ok(ConsoleCommand::Status));

        let over_limit = "x".repeat(MAX_COMMAND_LINE_BYTES + 1);
        let error = parse_command(&over_limit).expect_err("overlong command must fail");
        assert!(error.contains("maximum 4096 UTF-8 bytes"));

        let multibyte_over_limit = "status ".to_owned() + &"\u{00e9}".repeat(2048);
        assert!(parse_command(&multibyte_over_limit).is_err());
    }

    #[test]
    fn parses_hexadecimal_and_decimal_rvas() {
        assert_eq!(
            parse_command("focus 0XDEADBEEF"),
            Ok(ConsoleCommand::Focus(0xdeadbeef))
        );
        assert_eq!(
            parse_command("focus 4198400"),
            Ok(ConsoleCommand::Focus(4_198_400))
        );
        assert_eq!(parse_command("focus 0"), Ok(ConsoleCommand::Focus(0)));
    }

    #[test]
    fn rejects_invalid_commands_and_arguments() {
        for input in [
            "",
            "unknown",
            "status now",
            "open",
            "open \"\"",
            "tab assembly",
            "focus -1",
            "focus 0x",
            "focus 18446744073709551616",
            "theme neon",
            "panel center show",
            "panel left remove",
            "export yaml output.yml",
            "export json",
            "open \"unterminated",
            "status\nquit",
        ] {
            assert!(
                parse_command(input).is_err(),
                "input should fail: {input:?}"
            );
        }
    }

    #[test]
    fn response_and_activity_formatting_is_stable() {
        assert_eq!(format_command_result(true, "loaded"), "[ok] loaded");
        assert_eq!(format_command_result(false, "failed"), "[error] failed");
        assert_eq!(
            format_activity(
                Duration::from_millis(3_723_004),
                "debug",
                "analysis started"
            ),
            "[01:02:03.004] [DEBUG] analysis started"
        );

        let bounded = format_command_result(true, &"x".repeat(MAX_CONSOLE_OUTPUT_BYTES * 2));
        assert_eq!(bounded.len(), MAX_CONSOLE_OUTPUT_BYTES);
        assert!(!format_activity(Duration::ZERO, "info", "first\nsecond").contains('\n'));
        assert!(format_banner().len() <= MAX_CONSOLE_OUTPUT_BYTES);
        assert!(format_help().len() <= MAX_CONSOLE_OUTPUT_BYTES);
        assert!(format_prompt().len() <= MAX_CONSOLE_OUTPUT_BYTES);
    }

    #[test]
    fn bounded_line_reader_rejects_before_unbounded_growth_and_recovers() {
        let input = format!("{}\nstatus\n", "x".repeat(32));
        let mut reader = Cursor::new(input);
        let error = read_bounded_line(&mut reader, 16).expect_err("oversized line must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            read_bounded_line(&mut reader, 16)
                .expect("next line")
                .as_deref(),
            Some("status\n")
        );
        assert_eq!(read_bounded_line(&mut reader, 16).expect("EOF"), None);
    }

    #[test]
    fn command_types_round_trip_over_json_for_companion_ipc() {
        let command = ConsoleCommand::Export {
            kind: ConsoleExportKind::Map,
            path: PathBuf::from(r"C:\exports\symbols.map"),
        };
        let encoded = serde_json::to_string(&command).expect("serialize command");
        let decoded: ConsoleCommand = serde_json::from_str(&encoded).expect("deserialize command");
        assert_eq!(decoded, command);

        let address_space = ConsoleCommand::Tab(ConsoleTab::AddressSpace);
        let encoded = serde_json::to_string(&address_space).expect("serialize address-space tab");
        let decoded: ConsoleCommand =
            serde_json::from_str(&encoded).expect("deserialize address-space tab");
        assert_eq!(decoded, address_space);

        let readiness = ConsoleCommand::Tab(ConsoleTab::DebuggerSandbox);
        let encoded = serde_json::to_string(&readiness).expect("serialize readiness tab");
        let decoded: ConsoleCommand =
            serde_json::from_str(&encoded).expect("deserialize readiness tab");
        assert_eq!(decoded, readiness);

        let frame = ConsoleToHostFrame::Fatal("startup failed".to_owned());
        let encoded = serde_json::to_string(&frame).expect("serialize frame");
        let decoded: ConsoleToHostFrame =
            serde_json::from_str(&encoded).expect("deserialize frame");
        assert_eq!(decoded, frame);
    }
}
