//! Bounded named-thread ownership primitive for live debugger services.
//!
//! The factory crosses the thread boundary, not the driver it creates. This
//! allows a future service to construct and retain thread-affine Windows
//! debugger state without wrapping it in shared synchronization.

use std::{
    io,
    sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    thread::{self, JoinHandle},
};

/// Correlation ID issued only after a request enters the bounded queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionServiceRequestId(u64);

impl SessionServiceRequestId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

enum SessionServiceIntent<P> {
    Execute {
        request: SessionServiceRequestId,
        payload: P,
    },
    Shutdown,
}

impl<P> SessionServiceIntent<P> {
    fn into_payload(self) -> P {
        match self {
            Self::Execute { payload, .. } => payload,
            Self::Shutdown => {
                unreachable!("submit only sends execute intents")
            }
        }
    }
}

/// Value-only result correlated to one accepted request.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionServiceResponse<V> {
    request: SessionServiceRequestId,
    value: V,
}

impl<V> SessionServiceResponse<V> {
    #[must_use]
    pub const fn request_id(&self) -> SessionServiceRequestId {
        self.request
    }

    #[must_use]
    pub const fn value(&self) -> &V {
        &self.value
    }

    #[must_use]
    pub fn into_value(self) -> V {
        self.value
    }
}

/// Thread-confined owner behavior.
///
/// Implementations deliberately need not be Send: the Send factory is
/// transferred to the named service thread and constructs the driver there.
pub trait SessionServiceDriver<P, V, C> {
    /// Handles one payload and returns only presentation-safe value evidence.
    fn handle(&mut self, payload: P) -> V;

    /// Releases thread-affine resources and returns must-use cleanup evidence.
    ///
    /// Explicit shutdown returns this value to the caller. Detached Drop still
    /// runs cleanup on the owner thread, but deliberately cannot claim that
    /// cleanup completed.
    fn cleanup(&mut self) -> C;
}

/// Nonblocking request-submission failure.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionServiceSubmitError<P> {
    Busy(P),
    Disconnected(P),
    RequestIdExhausted(P),
}

/// Bounded client endpoint for a driver owned by one named child thread.
///
/// Capacity one bounds queued work; an external operation gate must still
/// enforce a single outstanding UI operation because one request may be
/// executing while another occupies the queue.
pub struct SessionService<P, V, C> {
    requests: Option<SyncSender<SessionServiceIntent<P>>>,
    responses: Option<Receiver<SessionServiceResponse<V>>>,
    next_request: Option<u64>,
    join: Option<JoinHandle<C>>,
}

impl<P, V, C> SessionService<P, V, C>
where
    P: Send + 'static,
    V: Send + 'static,
    C: Send + 'static,
{
    /// Spawns a capacity-one service and constructs its driver on that thread.
    pub fn spawn<D, F>(thread_name: impl Into<String>, factory: F) -> io::Result<Self>
    where
        D: SessionServiceDriver<P, V, C>,
        F: FnOnce() -> D + Send + 'static,
    {
        let (requests, request_receiver) = sync_channel(1);
        let (response_sender, responses) = sync_channel(1);
        let join = thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || run_session_service(request_receiver, response_sender, factory))?;

        Ok(Self {
            requests: Some(requests),
            responses: Some(responses),
            next_request: Some(1),
            join: Some(join),
        })
    }

    /// Attempts to enqueue work without waiting for queue capacity.
    pub fn submit(
        &mut self,
        payload: P,
    ) -> Result<SessionServiceRequestId, SessionServiceSubmitError<P>> {
        let Some(requests) = self.requests.as_ref() else {
            return Err(SessionServiceSubmitError::Disconnected(payload));
        };
        let Some(next_request) = self.next_request else {
            return Err(SessionServiceSubmitError::RequestIdExhausted(payload));
        };

        let request = SessionServiceRequestId(next_request);
        let intent = SessionServiceIntent::Execute { request, payload };

        match requests.try_send(intent) {
            Ok(()) => {
                self.next_request = next_request.checked_add(1);
                Ok(request)
            }
            Err(TrySendError::Full(intent)) => {
                Err(SessionServiceSubmitError::Busy(intent.into_payload()))
            }
            Err(TrySendError::Disconnected(intent)) => Err(
                SessionServiceSubmitError::Disconnected(intent.into_payload()),
            ),
        }
    }

    /// Polls one correlated response without blocking the client thread.
    pub fn try_receive(&self) -> Result<SessionServiceResponse<V>, TryRecvError> {
        let Some(responses) = self.responses.as_ref() else {
            return Err(TryRecvError::Disconnected);
        };
        responses.try_recv()
    }

    /// Signals shutdown, joins the owner thread, and returns cleanup evidence.
    ///
    /// Call this only from an explicit cleanup path. Drop intentionally
    /// signals and detaches instead of making arbitrary UI teardown blocking.
    pub fn shutdown(mut self) -> thread::Result<C> {
        self.signal_shutdown();
        match self.join.take() {
            Some(join) => join.join(),
            None => unreachable!("joined session service cannot be shut down twice"),
        }
    }
}

impl<P, V, C> SessionService<P, V, C> {
    fn signal_shutdown(&mut self) {
        if let Some(requests) = self.requests.take() {
            let _ = requests.try_send(SessionServiceIntent::Shutdown);
            drop(requests);
        }

        // Wake a worker blocked while publishing into the bounded response
        // slot before an explicit shutdown attempts to join it.
        drop(self.responses.take());
    }
}

impl<P, V, C> Drop for SessionService<P, V, C> {
    fn drop(&mut self) {
        self.signal_shutdown();
        // Dropping a JoinHandle detaches. Cleanup evidence must come from an
        // explicit service result or shutdown, never from Drop alone.
        drop(self.join.take());
    }
}

fn run_session_service<P, V, C, D, F>(
    requests: Receiver<SessionServiceIntent<P>>,
    responses: SyncSender<SessionServiceResponse<V>>,
    factory: F,
) -> C
where
    D: SessionServiceDriver<P, V, C>,
    F: FnOnce() -> D,
{
    let mut driver = factory();

    while let Ok(intent) = requests.recv() {
        match intent {
            SessionServiceIntent::Execute { request, payload } => {
                let value = driver.handle(payload);
                if responses
                    .send(SessionServiceResponse { request, value })
                    .is_err()
                {
                    break;
                }
            }
            SessionServiceIntent::Shutdown => break,
        }
    }

    driver.cleanup()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        rc::Rc,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread::{self, ThreadId},
        time::Duration,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    struct EchoDriver {
        cleanup_count: Arc<AtomicUsize>,
    }

    impl SessionServiceDriver<u32, u32, usize> for EchoDriver {
        fn handle(&mut self, payload: u32) -> u32 {
            payload
        }

        fn cleanup(&mut self) -> usize {
            self.cleanup_count.fetch_add(1, Ordering::SeqCst) + 1
        }
    }

    #[test]
    fn factory_and_non_send_driver_run_on_named_child_thread() {
        type Observation = (&'static str, ThreadId, Option<String>);

        struct ThreadProbeDriver {
            observations: Arc<Mutex<Vec<Observation>>>,
            cleanup_count: Arc<AtomicUsize>,
            _thread_confined: Rc<()>,
        }

        impl SessionServiceDriver<u32, u32, usize> for ThreadProbeDriver {
            fn handle(&mut self, payload: u32) -> u32 {
                let current = thread::current();
                self.observations.lock().expect("observations lock").push((
                    "driver",
                    current.id(),
                    current.name().map(str::to_owned),
                ));
                payload + 1
            }

            fn cleanup(&mut self) -> usize {
                self.cleanup_count.fetch_add(1, Ordering::SeqCst) + 1
            }
        }

        let parent_thread = thread::current().id();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let factory_observations = Arc::clone(&observations);
        let cleanup_count = Arc::new(AtomicUsize::new(0));
        let driver_cleanup_count = Arc::clone(&cleanup_count);
        let mut service = SessionService::spawn("resymbol-session-service-test", move || {
            let current = thread::current();
            factory_observations
                .lock()
                .expect("observations lock")
                .push(("factory", current.id(), current.name().map(str::to_owned)));
            ThreadProbeDriver {
                observations: factory_observations,
                cleanup_count: driver_cleanup_count,
                _thread_confined: Rc::new(()),
            }
        })
        .expect("service thread starts");

        let request = service.submit(41).expect("request accepted");
        let response = service
            .responses
            .as_ref()
            .expect("response receiver")
            .recv_timeout(TEST_TIMEOUT)
            .expect("response arrives");
        assert_eq!(response.request_id(), request);
        assert_eq!(response.into_value(), 42);
        service.shutdown().expect("service thread exits");

        let observations = observations.lock().expect("observations lock");
        assert_eq!(observations.len(), 2);
        for (phase, thread_id, thread_name) in observations.iter() {
            assert_ne!(
                *thread_id, parent_thread,
                "{phase} must not run on the client thread"
            );
            assert_eq!(
                thread_name.as_deref(),
                Some("resymbol-session-service-test")
            );
        }
        assert_eq!(cleanup_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn second_submit_is_busy_while_the_single_request_slot_is_full() {
        let cleanup_count = Arc::new(AtomicUsize::new(0));
        let driver_cleanup_count = Arc::clone(&cleanup_count);
        let (factory_entered_sender, factory_entered_receiver) = mpsc::sync_channel(1);
        let (factory_release_sender, factory_release_receiver) = mpsc::sync_channel(1);
        let mut service = SessionService::spawn("resymbol-session-service-busy-test", move || {
            factory_entered_sender
                .send(())
                .expect("announce factory entry");
            factory_release_receiver.recv().expect("release factory");
            EchoDriver {
                cleanup_count: driver_cleanup_count,
            }
        })
        .expect("service thread starts");

        factory_entered_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("factory reaches gate");
        let first = service.submit(1).expect("first request fills queue");
        assert_eq!(service.submit(2), Err(SessionServiceSubmitError::Busy(2)));

        factory_release_sender
            .send(())
            .expect("release service factory");
        let response = service
            .responses
            .as_ref()
            .expect("response receiver")
            .recv_timeout(TEST_TIMEOUT)
            .expect("first response arrives");
        assert_eq!(response.request_id(), first);
        assert_eq!(*response.value(), 1);
        service.shutdown().expect("service thread exits");
        assert_eq!(cleanup_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn response_ids_are_monotonic_and_correlated() {
        let cleanup_count = Arc::new(AtomicUsize::new(0));
        let driver_cleanup_count = Arc::clone(&cleanup_count);
        let mut service =
            SessionService::spawn("resymbol-session-service-id-test", move || EchoDriver {
                cleanup_count: driver_cleanup_count,
            })
            .expect("service thread starts");

        let first_request = service.submit(11).expect("first request accepted");
        let first_response = service
            .responses
            .as_ref()
            .expect("response receiver")
            .recv_timeout(TEST_TIMEOUT)
            .expect("first response arrives");
        let second_request = service.submit(22).expect("second request accepted");
        let second_response = service
            .responses
            .as_ref()
            .expect("response receiver")
            .recv_timeout(TEST_TIMEOUT)
            .expect("second response arrives");

        assert!(first_request < second_request);
        assert_eq!(first_response.request_id(), first_request);
        assert_eq!(first_response.into_value(), 11);
        assert_eq!(second_response.request_id(), second_request);
        assert_eq!(second_response.into_value(), 22);
        service.shutdown().expect("service thread exits");
        assert_eq!(cleanup_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn request_id_exhaustion_is_typed_and_does_not_panic() {
        let cleanup_count = Arc::new(AtomicUsize::new(0));
        let driver_cleanup_count = Arc::clone(&cleanup_count);
        let mut service =
            SessionService::spawn("resymbol-session-service-exhaustion-test", move || {
                EchoDriver {
                    cleanup_count: driver_cleanup_count,
                }
            })
            .expect("service thread starts");
        service.next_request = None;

        assert_eq!(
            service.submit(7),
            Err(SessionServiceSubmitError::RequestIdExhausted(7))
        );
        service.shutdown().expect("service thread exits");
        assert_eq!(cleanup_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cleanup_runs_once_on_explicit_shutdown() {
        let cleanup_count = Arc::new(AtomicUsize::new(0));
        let driver_cleanup_count = Arc::clone(&cleanup_count);
        let service = SessionService::spawn("resymbol-session-service-cleanup-test", move || {
            EchoDriver {
                cleanup_count: driver_cleanup_count,
            }
        })
        .expect("service thread starts");
        let cleanup_evidence = service.shutdown().expect("service thread exits");
        assert_eq!(cleanup_evidence, 1);
        assert_eq!(cleanup_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn shutdown_does_not_deadlock_with_a_full_response_channel() {
        struct BlockingSecondDriver {
            first_started: SyncSender<()>,
            second_started: SyncSender<()>,
            release_second: Receiver<()>,
            cleanup_count: Arc<AtomicUsize>,
        }

        impl SessionServiceDriver<u32, u32, usize> for BlockingSecondDriver {
            fn handle(&mut self, payload: u32) -> u32 {
                match payload {
                    1 => self.first_started.send(()).expect("announce first request"),
                    2 => {
                        self.second_started
                            .send(())
                            .expect("announce second request");
                        self.release_second.recv().expect("release second request");
                    }
                    _ => {}
                }
                payload
            }

            fn cleanup(&mut self) -> usize {
                self.cleanup_count.fetch_add(1, Ordering::SeqCst) + 1
            }
        }

        let (first_started_sender, first_started_receiver) = mpsc::sync_channel(1);
        let (second_started_sender, second_started_receiver) = mpsc::sync_channel(1);
        let (release_second_sender, release_second_receiver) = mpsc::sync_channel(1);
        let cleanup_count = Arc::new(AtomicUsize::new(0));
        let driver_cleanup_count = Arc::clone(&cleanup_count);
        let mut service = SessionService::spawn("resymbol-session-service-full-test", move || {
            BlockingSecondDriver {
                first_started: first_started_sender,
                second_started: second_started_sender,
                release_second: release_second_receiver,
                cleanup_count: driver_cleanup_count,
            }
        })
        .expect("service thread starts");

        service.submit(1).expect("first request accepted");
        first_started_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("first request starts");
        service.submit(2).expect("second request accepted");
        second_started_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("second request starts after first response fills channel");

        let (shutdown_started_sender, shutdown_started_receiver) = mpsc::sync_channel(1);
        let (shutdown_done_sender, shutdown_done_receiver) = mpsc::sync_channel(1);
        let shutdown_thread = thread::spawn(move || {
            shutdown_started_sender.send(()).expect("announce shutdown");
            let result = service.shutdown();
            shutdown_done_sender
                .send(result.is_ok())
                .expect("announce completed shutdown");
        });

        shutdown_started_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("shutdown begins");
        release_second_sender
            .send(())
            .expect("release second response");
        assert!(
            shutdown_done_receiver
                .recv_timeout(TEST_TIMEOUT)
                .expect("full response channel must not deadlock shutdown")
        );
        shutdown_thread.join().expect("shutdown thread exits");
        assert_eq!(cleanup_count.load(Ordering::SeqCst), 1);
    }
}
