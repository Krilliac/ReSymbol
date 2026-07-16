//! Isolated terminal front-end for the opt-in ReSymbol companion console.

#[cfg(target_os = "windows")]
fn main() {
    if let Err(error) = run() {
        use std::io::Write as _;

        use resymbol_workbench::console::{ConsoleToHostFrame, format_command_result};

        let frame = ConsoleToHostFrame::Fatal(format_command_result(false, &error.to_string()));
        let output = std::io::stdout();
        let mut writer = std::io::BufWriter::new(output.lock());
        let _ = serde_json::to_writer(&mut writer, &frame)
            .and_then(|()| writer.write_all(b"\n").map_err(serde_json::Error::io))
            .and_then(|()| writer.flush().map_err(serde_json::Error::io));
        eprintln!("ReSymbol companion console failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("The ReSymbol companion console is currently available on Windows only.");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        fs::OpenOptions,
        io::{self, BufReader, BufWriter, Write},
        process::{Command, Stdio},
        sync::{Arc, Mutex},
        thread,
    };

    use resymbol_workbench::console::{
        ConsoleToHostFrame, MAX_COMMAND_LINE_BYTES, MAX_CONSOLE_OUTPUT_BYTES, format_banner,
        format_prompt, read_bounded_line,
    };

    const MAX_WIRE_FRAME_BYTES: usize = 32 * 1024;

    let system_root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("SystemRoot is unavailable or is not absolute")?;
    let system32 = system_root.join("System32");
    let code_page_tool = system32.join("chcp.com");
    if !code_page_tool.is_file() {
        return Err(format!(
            "UTF-8 code-page tool is missing at {}",
            code_page_tool.display()
        )
        .into());
    }
    let code_page_status = Command::new(&code_page_tool)
        .arg("65001")
        .current_dir(&system32)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !code_page_status.success() {
        return Err(format!(
            "cannot select UTF-8 console code page (exit status {code_page_status})"
        )
        .into());
    }

    let console_input = OpenOptions::new().read(true).open("CONIN$")?;
    let console_output = OpenOptions::new().write(true).open("CONOUT$")?;
    let console_output = Arc::new(Mutex::new(console_output));

    {
        let mut output = console_output
            .lock()
            .map_err(|_| "companion console output lock was poisoned")?;
        output.write_all(format_banner().as_bytes())?;
        output.write_all(format_prompt().as_bytes())?;
        output.flush()?;
    }

    let parent_output = io::stdout();
    let mut parent_writer = BufWriter::new(parent_output.lock());
    serde_json::to_writer(&mut parent_writer, &ConsoleToHostFrame::Ready)?;
    parent_writer.write_all(b"\n")?;
    parent_writer.flush()?;

    let display_output = Arc::clone(&console_output);
    thread::spawn(move || {
        let parent_input = io::stdin();
        let mut reader = BufReader::new(parent_input.lock());
        loop {
            match read_bounded_line(&mut reader, MAX_WIRE_FRAME_BYTES) {
                Ok(None) => std::process::exit(0),
                Err(_) => std::process::exit(2),
                Ok(Some(frame)) => {
                    let Ok(message) = serde_json::from_str::<String>(frame.trim_end()) else {
                        std::process::exit(2);
                    };
                    if message.len() > MAX_CONSOLE_OUTPUT_BYTES {
                        std::process::exit(2);
                    }
                    let Ok(mut output) = display_output.lock() else {
                        std::process::exit(2);
                    };
                    if output.write_all(b"\r\n").is_err()
                        || output.write_all(message.as_bytes()).is_err()
                        || (!message.ends_with('\n') && output.write_all(b"\r\n").is_err())
                        || output.write_all(format_prompt().as_bytes()).is_err()
                        || output.flush().is_err()
                    {
                        std::process::exit(2);
                    }
                }
            }
        }
    });

    let mut console_reader = BufReader::new(console_input);
    loop {
        let line = match read_bounded_line(&mut console_reader, MAX_COMMAND_LINE_BYTES + 2) {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                let mut output = console_output
                    .lock()
                    .map_err(|_| "companion console output lock was poisoned")?;
                writeln!(output, "\r\n[error] {error}")?;
                output.write_all(format_prompt().as_bytes())?;
                output.flush()?;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            let mut output = console_output
                .lock()
                .map_err(|_| "companion console output lock was poisoned")?;
            output.write_all(format_prompt().as_bytes())?;
            output.flush()?;
            continue;
        }
        if line.len() > MAX_COMMAND_LINE_BYTES {
            let mut output = console_output
                .lock()
                .map_err(|_| "companion console output lock was poisoned")?;
            writeln!(
                output,
                "\r\n[error] command exceeds the {MAX_COMMAND_LINE_BYTES}-byte limit"
            )?;
            output.write_all(format_prompt().as_bytes())?;
            output.flush()?;
            continue;
        }
        serde_json::to_writer(
            &mut parent_writer,
            &ConsoleToHostFrame::Command(line.to_owned()),
        )?;
        parent_writer.write_all(b"\n")?;
        parent_writer.flush()?;
    }
}
