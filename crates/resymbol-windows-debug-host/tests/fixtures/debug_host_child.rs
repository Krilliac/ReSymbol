#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    fixture::run()
}

#[cfg(windows)]
mod fixture {
    use std::{
        io::{self, BufRead as _, Write as _},
        ptr,
    };

    use windows_sys::Win32::{
        Foundation::{FALSE, FILETIME},
        System::{
            LibraryLoader::GetModuleHandleW,
            Threading::{GetCurrentProcess, GetProcessTimes},
        },
    };

    #[used]
    #[unsafe(link_section = ".text$rsym_debug_host_fixture")]
    static READ_TARGET: [u8; 8] = *b"RSYMHOST";

    pub(super) fn run() -> io::Result<()> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: the current-process pseudo-handle is valid here and every
        // FILETIME output remains writable for the complete call.
        let times_ok = unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        };
        assert_ne!(times_ok, FALSE, "query fixture creation identity");
        let start_key =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);

        // SAFETY: null requests the current executable's borrowed module
        // handle. The fixture deliberately does not close that borrowed value.
        let image_base = unsafe { GetModuleHandleW(ptr::null()) } as usize as u64;
        assert_ne!(image_base, 0, "query fixture main-image base");
        let read_address = ptr::addr_of!(READ_TARGET) as usize as u64;
        println!("{start_key:x} {image_base:x} {read_address:x}");
        io::stdout().flush()?;

        // The parent owns this child. It keeps stdin open through attach, read,
        // event continuation, and detach, then writes one line to release it.
        let mut release = String::new();
        io::stdin().lock().read_line(&mut release)?;
        Ok(())
    }
}
