//! A [`Transport`] over a raw serial line (tty), for speaking RSP to targets
//! reached over a UART — a serial gdbstub, an in-circuit debug probe, or a
//! kernel debugger on a serial console.
//!
//! **This is the only module in the crate that contains `unsafe` code.** It
//! opens the device as an ordinary [`File`] and then, through libc `termios`
//! calls, switches the line into raw mode (no canonical processing, echo, or
//! signal generation) at the requested baud, with `VMIN = 1`/`VTIME = 0` so a
//! read blocks for exactly one byte. Every FFI block carries a `// SAFETY:`
//! justification; the byte-level buffering reuses the safe [`StreamTransport`].

use crate::transport::{StreamTransport, Transport};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;

/// A raw-mode serial transport.
#[derive(Debug)]
pub struct SerialTransport {
    stream: StreamTransport<File>,
}

impl SerialTransport {
    /// Open `path` (e.g. `/dev/ttyS0`) and configure it into raw mode at
    /// `baud`.
    ///
    /// # Errors
    ///
    /// Returns an error if the device cannot be opened, `baud` is not a
    /// supported standard rate, or the `termios` configuration fails.
    pub fn open(path: &str, baud: u32) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        configure_raw(&file, baud)?;
        Ok(Self {
            stream: StreamTransport::new(file),
        })
    }
}

impl Transport for SerialTransport {
    fn read_byte(&mut self) -> io::Result<u8> {
        self.stream.read_byte()
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Configure the tty behind `file` into raw mode at `baud`.
fn configure_raw(file: &File, baud: u32) -> io::Result<()> {
    let fd = file.as_raw_fd();
    let speed = baud_constant(baud)?;

    // SAFETY: `termios` is a plain C struct of integer fields; an all-zero bit
    // pattern is a valid, fully-initialised value that `tcgetattr` overwrites.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };

    // SAFETY: `tcgetattr` fills the `termios` we own through a valid, borrowed
    // file descriptor; it reads no memory from us beyond that struct.
    if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `cfmakeraw` only mutates the `termios` struct we own, clearing the
    // canonical/echo/signal flags to put the line into raw mode.
    unsafe { libc::cfmakeraw(&mut termios) };

    // SAFETY: `cfsetispeed` mutates only the owned `termios`; `speed` is a
    // libc-provided baud constant.
    if unsafe { libc::cfsetispeed(&mut termios, speed) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `cfsetospeed` mutates only the owned `termios`; `speed` is a
    // libc-provided baud constant.
    if unsafe { libc::cfsetospeed(&mut termios, speed) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // Block until at least one byte is available, with no inter-byte timer, so
    // `read_byte` behaves like a blocking socket read.
    termios.c_cc[libc::VMIN] = 1;
    termios.c_cc[libc::VTIME] = 0;

    // SAFETY: `tcsetattr` reads the owned `termios` and installs it on the
    // valid, borrowed file descriptor; it writes no memory back to us.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Map a standard baud rate to its libc `speed_t` constant.
fn baud_constant(baud: u32) -> io::Result<libc::speed_t> {
    let speed = match baud {
        1200 => libc::B1200,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115_200 => libc::B115200,
        230_400 => libc::B230400,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported serial baud rate: {baud}"),
            ));
        }
    };
    Ok(speed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_baud_rates_map_to_constants() {
        assert_eq!(baud_constant(9600).unwrap(), libc::B9600);
        assert_eq!(baud_constant(115_200).unwrap(), libc::B115200);
    }

    #[test]
    fn unsupported_baud_is_rejected() {
        let error = baud_constant(12345).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
