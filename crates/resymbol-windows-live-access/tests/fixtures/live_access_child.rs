#[cfg(windows)]
use std::{
    io::{self, BufRead as _, Write as _},
    ptr,
};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{FALSE, FILETIME},
    System::{
        LibraryLoader::GetModuleHandleW,
        Threading::{GetCurrentProcess, GetProcessTimes},
    },
};

#[cfg(windows)]
#[used]
#[unsafe(link_section = ".text$rsym_live_fixture")]
static PATCH_TARGET: [u8; 8] = *b"RSYMLIVE";

#[cfg(windows)]
fn main() -> io::Result<()> {
    let address = std::ptr::addr_of!(PATCH_TARGET) as usize;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the current-process pseudo-handle is valid in this process and
    // every FILETIME pointer remains writable for the complete call.
    let times_ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    assert_ne!(times_ok, FALSE, "query fixture process creation time");
    let start_key = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    // SAFETY: null asks for the current process executable. The returned
    // borrowed module handle is deliberately not closed.
    let image_base = unsafe { GetModuleHandleW(ptr::null()) } as usize as u64;
    assert_ne!(image_base, 0, "query fixture main-image base");
    println!("{start_key:x} {image_base:x} {address:x}");
    io::stdout().flush()?;

    // The parent integration test owns this child and retains stdin until it
    // has restored the original bytes. The fixture never reads PATCH_TARGET
    // after publishing its address, so the child itself does not race the
    // external mutation.
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(())
}

#[cfg(not(windows))]
fn main() {}
