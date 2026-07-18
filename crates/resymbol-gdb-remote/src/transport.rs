//! Byte-oriented transports the RSP server and client run over.
//!
//! The [`Transport`] trait abstracts a full-duplex byte channel: a blocking
//! single-byte read, a write-all, and a flush. [`StreamTransport`] adapts any
//! [`Read`] + [`Write`] stream (with a small read buffer so per-byte reads do
//! not each hit the OS), [`TcpTransport`] and [`TcpServerListener`] provide the
//! socket variants, and [`memory_pair`] builds a connected in-process pair for
//! deterministic tests without real sockets.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex};

/// A full-duplex byte channel for the GDB Remote Serial Protocol.
pub trait Transport {
    /// Read exactly one byte, blocking until one is available.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::UnexpectedEof`] when the peer has closed the
    /// channel, or any underlying I/O error.
    fn read_byte(&mut self) -> io::Result<u8>;

    /// Write every byte of `data`, blocking until all are sent.
    ///
    /// # Errors
    ///
    /// Propagates any underlying I/O error.
    fn write_all(&mut self, data: &[u8]) -> io::Result<()>;

    /// Flush any buffered outbound bytes.
    ///
    /// # Errors
    ///
    /// Propagates any underlying I/O error.
    fn flush(&mut self) -> io::Result<()>;
}

/// The read-buffer size used by [`StreamTransport`].
const READ_BUFFER_BYTES: usize = 4096;

/// A [`Transport`] over any [`Read`] + [`Write`] stream, with a small buffer so
/// single-byte reads coalesce into larger underlying reads.
#[derive(Debug)]
pub struct StreamTransport<S> {
    inner: S,
    buffer: Box<[u8]>,
    position: usize,
    filled: usize,
}

impl<S> StreamTransport<S> {
    /// Wrap `inner` in a buffered transport.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buffer: vec![0u8; READ_BUFFER_BYTES].into_boxed_slice(),
            position: 0,
            filled: 0,
        }
    }

    /// Consume the transport and return the wrapped stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Read + Write> Transport for StreamTransport<S> {
    fn read_byte(&mut self) -> io::Result<u8> {
        if self.position == self.filled {
            self.filled = self.inner.read(&mut self.buffer)?;
            self.position = 0;
            if self.filled == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "transport closed by peer",
                ));
            }
        }
        let byte = self.buffer[self.position];
        self.position += 1;
        Ok(byte)
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.write_all(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A [`Transport`] over a TCP connection.
pub type TcpTransport = StreamTransport<TcpStream>;

impl StreamTransport<TcpStream> {
    /// Connect to a remote RSP endpoint (e.g. a QEMU or kernel gdbstub).
    ///
    /// # Errors
    ///
    /// Propagates connection failures.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        Ok(Self::new(stream))
    }
}

/// A listener that accepts inbound RSP client connections over TCP.
#[derive(Debug)]
pub struct TcpServerListener {
    listener: TcpListener,
}

impl TcpServerListener {
    /// Bind a listening socket at `addr`.
    ///
    /// # Errors
    ///
    /// Propagates bind failures.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr)?,
        })
    }

    /// The address the listener is bound to (useful when binding to port 0).
    ///
    /// # Errors
    ///
    /// Propagates the underlying query failure.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Block until a client connects, returning a ready transport.
    ///
    /// # Errors
    ///
    /// Propagates accept failures.
    pub fn accept(&self) -> io::Result<TcpTransport> {
        let (stream, _peer) = self.listener.accept()?;
        stream.set_nodelay(true)?;
        Ok(StreamTransport::new(stream))
    }
}

/// A shared, blocking byte queue used by the in-process [`MemoryStream`] pair.
#[derive(Debug)]
struct SharedChannel {
    state: Mutex<ChannelState>,
    signal: Condvar,
}

#[derive(Debug)]
struct ChannelState {
    buffer: VecDeque<u8>,
    closed: bool,
}

/// One end of an in-process, full-duplex byte pipe.
///
/// Reads block until data is available or the far end closes (reported as
/// EOF), so a client and server can run on separate threads exactly as they
/// would over a socket. Primarily a testing aid.
#[derive(Debug)]
pub struct MemoryStream {
    inbound: Arc<SharedChannel>,
    outbound: Arc<SharedChannel>,
}

impl Read for MemoryStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut state = self
            .inbound
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if !state.buffer.is_empty() {
                let count = out.len().min(state.buffer.len());
                for slot in out.iter_mut().take(count) {
                    *slot = state.buffer.pop_front().unwrap_or(0);
                }
                return Ok(count);
            }
            if state.closed {
                return Ok(0);
            }
            state = self
                .inbound
                .signal
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

impl Write for MemoryStream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut state = self
            .outbound
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "memory stream peer closed",
            ));
        }
        state.buffer.extend(data.iter().copied());
        self.outbound.signal.notify_all();
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for MemoryStream {
    fn drop(&mut self) {
        if let Ok(mut state) = self.outbound.state.lock() {
            state.closed = true;
        }
        self.outbound.signal.notify_all();
    }
}

/// Build a connected pair of in-process transports.
///
/// Bytes written to one end are read from the other. Dropping either end
/// signals EOF to its peer. Intended for in-process client/server tests.
#[must_use]
pub fn memory_pair() -> (StreamTransport<MemoryStream>, StreamTransport<MemoryStream>) {
    let left = Arc::new(SharedChannel {
        state: Mutex::new(ChannelState {
            buffer: VecDeque::new(),
            closed: false,
        }),
        signal: Condvar::new(),
    });
    let right = Arc::new(SharedChannel {
        state: Mutex::new(ChannelState {
            buffer: VecDeque::new(),
            closed: false,
        }),
        signal: Condvar::new(),
    });
    let a = MemoryStream {
        inbound: Arc::clone(&left),
        outbound: Arc::clone(&right),
    };
    let b = MemoryStream {
        inbound: right,
        outbound: left,
    };
    (StreamTransport::new(a), StreamTransport::new(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_pair_round_trips_bytes() {
        let (mut a, mut b) = memory_pair();
        a.write_all(b"hi").unwrap();
        a.flush().unwrap();
        assert_eq!(b.read_byte().unwrap(), b'h');
        assert_eq!(b.read_byte().unwrap(), b'i');
    }

    #[test]
    fn dropping_one_end_reports_eof() {
        let (a, mut b) = memory_pair();
        drop(a);
        let error = b.read_byte().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn is_full_duplex_across_threads() {
        let (mut a, mut b) = memory_pair();
        let handle = std::thread::spawn(move || {
            assert_eq!(b.read_byte().unwrap(), b'Q');
            b.write_all(b"A").unwrap();
            b.flush().unwrap();
        });
        a.write_all(b"Q").unwrap();
        a.flush().unwrap();
        assert_eq!(a.read_byte().unwrap(), b'A');
        handle.join().unwrap();
    }
}
