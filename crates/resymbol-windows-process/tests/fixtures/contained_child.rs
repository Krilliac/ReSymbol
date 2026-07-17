#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    fixture::main();
}

#[cfg(windows)]
mod fixture {
    use std::{
        env,
        ffi::{OsStr, OsString},
        fs,
        io::{self, Read as _, Write as _},
        os::windows::process::CommandExt as _,
        path::PathBuf,
        process::{self, Command, Stdio},
        ptr::null,
        thread,
        time::Duration,
    };

    use windows_sys::Win32::{
        Foundation::ERROR_ACCESS_DENIED,
        System::{
            Memory::{
                MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
            },
            Threading::{CREATE_BREAKAWAY_FROM_JOB, SetEvent},
        },
    };

    pub(super) fn main() {
        let code = run().unwrap_or_else(|error| {
            eprintln!("contained-child fixture failed: {error}");
            90
        });
        process::exit(code);
    }

    fn run() -> Result<i32, String> {
        let mut arguments = env::args_os();
        let _program = arguments.next();
        let mode = arguments
            .next()
            .ok_or_else(|| "missing fixture mode".to_owned())?;
        match mode.to_str() {
            Some("semantics") => run_semantics(arguments.collect()),
            Some("leader") => run_leader(arguments.collect()),
            Some("descendant") => run_descendant(arguments.collect()),
            Some("signal-handle") => run_handle_signal(arguments.collect()),
            Some("attempt-breakaway") => run_attempt_breakaway(arguments.collect()),
            Some("probe-active-process-limit") => {
                run_active_process_limit_probe(arguments.collect())
            }
            Some("write-marker") => run_write_marker(arguments.collect()),
            Some("probe-memory-limit") => run_memory_limit_probe(arguments.collect()),
            Some("noop") => Ok(0),
            _ => Err(format!("unknown fixture mode {mode:?}")),
        }
    }

    fn run_semantics(arguments: Vec<OsString>) -> Result<i32, String> {
        let expected = [
            OsString::new(),
            OsString::from("with space"),
            OsString::from("quote\"inside"),
            OsString::from(r"trailing\\"),
            OsString::from("space trailing\\"),
            OsString::from(r#"space trailing\\\\"#),
            OsString::from(r#"slashes\\\"quote"#),
            OsString::from(r#"left""right"#),
            OsString::from("Unicode-雪-λ"),
        ];
        if arguments != expected {
            return Err(format!("argument round-trip mismatch: {arguments:?}"));
        }
        if env::var_os("PATH").is_some() {
            return Err("env_clear leaked PATH into the child".to_owned());
        }
        if env::var_os("RESYMBOL_UNICODE_VALUE") != Some(OsString::from("value-雪-λ")) {
            return Err("Unicode environment value did not round-trip".to_owned());
        }
        let current_directory = env::current_dir().map_err(|error| error.to_string())?;
        if current_directory.file_name() != Some(OsStr::new("resymbol-雪")) {
            return Err(format!(
                "Unicode current directory did not round-trip: {current_directory:?}"
            ));
        }

        let mut input = Vec::new();
        io::stdin()
            .read_to_end(&mut input)
            .map_err(|error| error.to_string())?;
        if input != b"protocol-input" {
            return Err(format!("stdin pipe mismatch: {input:?}"));
        }
        io::stdout()
            .write_all("stdout-雪".as_bytes())
            .map_err(|error| error.to_string())?;
        io::stdout().flush().map_err(|error| error.to_string())?;
        io::stderr()
            .write_all("stderr-λ".as_bytes())
            .map_err(|error| error.to_string())?;
        io::stderr().flush().map_err(|error| error.to_string())?;
        Ok(0)
    }

    fn run_leader(arguments: Vec<OsString>) -> Result<i32, String> {
        let [marker] = arguments.as_slice() else {
            return Err("leader expected one marker path".to_owned());
        };
        let child = Command::new(env::current_exe().map_err(|error| error.to_string())?)
            .arg("descendant")
            .arg(marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("spawn immediate descendant: {error}"))?;
        drop(child);
        Ok(0)
    }

    fn run_descendant(arguments: Vec<OsString>) -> Result<i32, String> {
        let [marker] = arguments.as_slice() else {
            return Err("descendant expected one marker path".to_owned());
        };
        thread::sleep(Duration::from_millis(350));
        fs::write(PathBuf::from(marker), b"escaped")
            .map_err(|error| format!("write descendant survival marker: {error}"))?;
        Ok(0)
    }

    fn run_active_process_limit_probe(arguments: Vec<OsString>) -> Result<i32, String> {
        let [marker] = arguments.as_slice() else {
            return Err("active-process probe expected one marker path".to_owned());
        };
        let marker = PathBuf::from(marker);
        let spawned = Command::new(env::current_exe().map_err(|error| error.to_string())?)
            .arg("write-marker")
            .arg(&marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        match spawned {
            // Microsoft specifies termination plus failed Job association, but
            // not which `Command::spawn` result exposes that implicit-assignment
            // failure. Handle either result; the security property is that the
            // new image never reaches its marker write.
            Err(_) if !marker.exists() => Ok(0),
            Err(error) => Err(format!(
                "grandchild wrote its marker before creation failed: {error}"
            )),
            Ok(mut child) => {
                let status = child
                    .wait()
                    .map_err(|error| format!("wait for denied grandchild: {error}"))?;
                if marker.exists() {
                    return Err(format!(
                        "grandchild executed despite the active-process limit: {status}"
                    ));
                }
                Ok(0)
            }
        }
    }

    fn run_write_marker(arguments: Vec<OsString>) -> Result<i32, String> {
        let [marker] = arguments.as_slice() else {
            return Err("marker writer expected one marker path".to_owned());
        };
        fs::write(PathBuf::from(marker), b"executed")
            .map_err(|error| format!("write active-process marker: {error}"))?;
        Ok(0)
    }

    fn run_memory_limit_probe(arguments: Vec<OsString>) -> Result<i32, String> {
        let [attempted_bytes] = arguments.as_slice() else {
            return Err("memory-limit probe expected one byte-count argument".to_owned());
        };
        let attempted_bytes = attempted_bytes
            .to_str()
            .ok_or_else(|| "memory-limit byte count was not Unicode".to_owned())?
            .parse::<usize>()
            .map_err(|error| format!("parse memory-limit byte count: {error}"))?;

        // First prove that this process can make and release an ordinary commit
        // so an unrelated total allocation failure cannot masquerade as limit
        // enforcement. MEM_COMMIT charges commit for the complete region at the
        // call boundary; touching pages is not required for this Job limit.
        commit_then_release(8 * 1024 * 1024)
            .map_err(|error| format!("baseline memory commit failed: {error}"))?;

        // SAFETY: null requests a system-chosen region, the nonzero size came
        // from the trusted parent test, and the flags describe one read/write
        // reserved-and-committed region. A non-null result is caller-owned.
        let region = unsafe {
            VirtualAlloc(
                null(),
                attempted_bytes,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if region.is_null() {
            return Ok(0);
        }

        // Do not leak a surprising successful allocation while reporting the
        // limit failure. Preserve the stronger diagnostic if release also fails.
        // SAFETY: `region` is exactly the base returned by VirtualAlloc; zero
        // size is required with MEM_RELEASE.
        if unsafe { VirtualFree(region, 0, MEM_RELEASE) } == 0 {
            return Err(format!(
                "committed {attempted_bytes} bytes despite the configured Job limit and then failed to release the region: {}",
                io::Error::last_os_error()
            ));
        }
        Err(format!(
            "committed {attempted_bytes} bytes despite the configured Job limit"
        ))
    }

    fn commit_then_release(bytes: usize) -> Result<(), io::Error> {
        // SAFETY: same allocation contract as the constrained probe above.
        let region =
            unsafe { VirtualAlloc(null(), bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        if region.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `region` is exactly the base returned above and zero size is
        // required when releasing the complete region with MEM_RELEASE.
        if unsafe { VirtualFree(region, 0, MEM_RELEASE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn run_handle_signal(arguments: Vec<OsString>) -> Result<i32, String> {
        let [raw_handle] = arguments.as_slice() else {
            return Err("handle signal expected one numeric handle".to_owned());
        };
        let raw_handle = raw_handle
            .to_str()
            .ok_or_else(|| "handle was not Unicode".to_owned())?
            .parse::<usize>()
            .map_err(|error| format!("parse handle value: {error}"))?;
        // SAFETY: this disposable fixture deliberately attempts SetEvent on an
        // untrusted numeric handle without owning or closing it. The parent checks
        // its still-owned event's state, so child-side handle-slot reuse cannot
        // create a false failure: an alias can signal only the unrelated object.
        let _signal_result = unsafe { SetEvent(raw_handle as *mut _) };
        Ok(0)
    }

    fn run_attempt_breakaway(arguments: Vec<OsString>) -> Result<i32, String> {
        if !arguments.is_empty() {
            return Err("breakaway probe expected no extra arguments".to_owned());
        }
        let result = Command::new(env::current_exe().map_err(|error| error.to_string())?)
            .arg("noop")
            .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match result {
            Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => Ok(0),
            Err(error) => Err(format!(
                "breakaway creation failed for an unexpected reason: {error}"
            )),
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                Err("CREATE_BREAKAWAY_FROM_JOB unexpectedly escaped the containment Job".to_owned())
            }
        }
    }
}
