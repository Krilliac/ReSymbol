//! Disposable native-plugin helper process.
//!
//! This binary is not a general plugin launcher. The trusted ReSymbol parent
//! supplies a strict bootstrap plus plugin-wire hello/request on stdin, and the
//! helper emits only validated plugin-wire output on stdout. Native faults are
//! confined to this process; native code is not thereby OS-sandboxed.

#![deny(unsafe_op_in_unsafe_fn)]

mod abi;
mod bootstrap;
mod callbacks;
mod error;
mod image;
mod loader;
mod output;

use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process,
};

use bootstrap::HostInput;
use error::HostError;
use loader::ExecutionStage;

// Stable process contract consumed by `resymbol-plugin-runtime`. Exit 70 means
// no platform library load was attempted; exit 71 means the loader boundary
// was crossed and native plugin code may have run.
const PRE_LOAD_FAILURE_EXIT_CODE: i32 = 70;
const LOAD_ATTEMPTED_FAILURE_EXIT_CODE: i32 = 71;

// Fixed, versioned stderr contract consumed by `resymbol-plugin-runtime`.
// This marker is deliberately not a diagnostic: the parent removes exactly
// one leading instance before exposing stderr to callers.
pub(crate) const LOAD_ATTEMPTED_MARKER: &[u8] = b"@resymbol-native-host/load-attempted/v1@\n";

fn main() {
    let exit_code = match run() {
        Ok(()) => 0,
        Err(failure) => {
            let diagnostic = bounded_diagnostic(&failure.error.to_string());
            let _ignored = writeln!(io::stderr().lock(), "native host error: {diagnostic}");
            let _ignored = io::stderr().lock().flush();
            failure.exit_code()
        }
    };
    // Dynamic libraries and callback contexts intentionally live until process
    // teardown. Returning through Rust destructors could unload a library whose
    // malformed plugin left a worker thread behind.
    process::exit(exit_code);
}

struct RunFailure {
    error: HostError,
    stage: ExecutionStage,
}

impl RunFailure {
    const fn exit_code(&self) -> i32 {
        match self.stage {
            ExecutionStage::BeforeLoad => PRE_LOAD_FAILURE_EXIT_CODE,
            ExecutionStage::LoadAttempted => LOAD_ATTEMPTED_FAILURE_EXIT_CODE,
        }
    }
}

fn run() -> Result<(), RunFailure> {
    let mut stage = ExecutionStage::BeforeLoad;
    run_at_stage(&mut stage).map_err(|error| RunFailure { error, stage })
}

fn run_at_stage(stage: &mut ExecutionStage) -> Result<(), HostError> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == [OsString::from("--version")] {
        println!("resymbol-native-host {}", env!("CARGO_PKG_VERSION"));
        io::stdout()
            .lock()
            .flush()
            .map_err(|error| HostError::io("flush version output", error))?;
        return Ok(());
    }
    let (plugin_root, binary_path) = parse_arguments(&arguments)?;
    let input = HostInput::read(io::stdin().lock())?;
    let execution = loader::execute(&plugin_root, &binary_path, &input, stage)?;
    let output = output::encode_execution(
        execution,
        input.request.id(),
        input.hello.limits().max_message_bytes,
        input.bootstrap.output_limits.max_stdout_bytes,
    )?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&output)
        .map_err(|error| HostError::io("write native-host stdout", error))?;
    stdout
        .flush()
        .map_err(|error| HostError::io("flush native-host stdout", error))?;
    Ok(())
}

/// Publish the trusted load boundary before any platform loader call.
///
/// The stage changes only after the complete marker has been written and
/// flushed. Therefore an ordinary pre-load rejection cannot acquire the
/// marker or the load-attempted exit code merely by failing to write stderr.
pub(crate) fn mark_load_attempted(stage: &mut ExecutionStage) -> Result<(), HostError> {
    let mut stderr = io::stderr().lock();
    stderr
        .write_all(LOAD_ATTEMPTED_MARKER)
        .map_err(|error| HostError::io("write native load-attempted marker", error))?;
    stderr
        .flush()
        .map_err(|error| HostError::io("flush native load-attempted marker", error))?;
    *stage = ExecutionStage::LoadAttempted;
    Ok(())
}

fn parse_arguments(arguments: &[OsString]) -> Result<(PathBuf, PathBuf), HostError> {
    let [plugin_flag, plugin_root, binary_flag, binary_path] = arguments else {
        return Err(HostError::Arguments(
            "expected --plugin-root <DIRECTORY> --binary <EXACT_BINARY>",
        ));
    };
    if plugin_flag != "--plugin-root" || binary_flag != "--binary" {
        return Err(HostError::Arguments(
            "expected --plugin-root <DIRECTORY> --binary <EXACT_BINARY>",
        ));
    }
    if plugin_root.is_empty() || binary_path.is_empty() {
        return Err(HostError::Arguments(
            "plugin root and exact binary paths must not be empty",
        ));
    }
    Ok((PathBuf::from(plugin_root), PathBuf::from(binary_path)))
}

fn bounded_diagnostic(message: &str) -> String {
    const LIMIT: usize = 4_096;
    const SUFFIX: &str = "...";
    let mut output = String::with_capacity(message.len().min(LIMIT));
    let mut pending_space = false;
    for character in message.chars() {
        if character.is_control() || character.is_whitespace() {
            pending_space = !output.is_empty();
            continue;
        }
        if pending_space && output.len() < LIMIT.saturating_sub(SUFFIX.len()) {
            output.push(' ');
        }
        pending_space = false;
        if output.len() + character.len_utf8() > LIMIT.saturating_sub(SUFFIX.len()) {
            output.push_str(SUFFIX);
            return output;
        }
        output.push(character);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_parser_preserves_os_paths_without_shell_parsing() {
        let arguments = vec![
            OsString::from("--plugin-root"),
            OsString::from("plugins/a directory"),
            OsString::from("--binary"),
            OsString::from("input;still-literal.exe"),
        ];
        let (plugin, binary) = parse_arguments(&arguments).unwrap();
        assert_eq!(plugin, PathBuf::from("plugins/a directory"));
        assert_eq!(binary, PathBuf::from("input;still-literal.exe"));
    }

    #[test]
    fn diagnostics_are_single_line_and_bounded() {
        let diagnostic = bounded_diagnostic(&format!("secret\n{}", "x".repeat(8_192)));
        assert!(!diagnostic.contains('\n'));
        assert!(diagnostic.len() <= 4_096);
        assert!(diagnostic.ends_with("..."));
    }

    #[test]
    fn failure_exit_codes_distinguish_the_platform_load_boundary() {
        let pre_load = RunFailure {
            error: HostError::Arguments("test"),
            stage: ExecutionStage::BeforeLoad,
        };
        let load_attempted = RunFailure {
            error: HostError::Arguments("test"),
            stage: ExecutionStage::LoadAttempted,
        };
        assert_eq!(pre_load.exit_code(), 70);
        assert_eq!(load_attempted.exit_code(), 71);
        assert_ne!(pre_load.exit_code(), load_attempted.exit_code());
    }

    #[test]
    fn load_marker_is_fixed_versioned_and_line_terminated() {
        assert_eq!(
            LOAD_ATTEMPTED_MARKER,
            b"@resymbol-native-host/load-attempted/v1@\n"
        );
        assert_eq!(
            LOAD_ATTEMPTED_MARKER
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
            1
        );
        assert!(LOAD_ATTEMPTED_MARKER.ends_with(b"\n"));
    }
}
