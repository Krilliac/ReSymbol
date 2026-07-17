#[cfg(windows)]
use std::io::{self, BufRead as _, Write as _};

#[cfg(windows)]
#[used]
#[unsafe(link_section = ".text$rsym_live_fixture")]
static PATCH_TARGET: [u8; 8] = *b"RSYMLIVE";

#[cfg(windows)]
fn main() -> io::Result<()> {
    let address = std::ptr::addr_of!(PATCH_TARGET) as usize;
    println!("{address:x}");
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
