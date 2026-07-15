use std::{
    collections::BTreeSet,
    ffi::c_void,
    slice,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

use resymbol_plugin_api::{PluginManifest, PluginPermission};
use serde_json::Value;

use crate::{
    abi::{
        self, ByteView, HostApiV1, LOG_DEBUG, LOG_ERROR, LOG_INFO, LOG_TRACE, LOG_WARN, LogLevel,
        MutByteSpan, STATUS_CANCELLED, STATUS_INTERNAL_ERROR, STATUS_INVALID_ARGUMENT, STATUS_OK,
        STATUS_PERMISSION_DENIED, STATUS_RESOURCE_LIMIT, Status, StringView,
    },
    bootstrap::WireLimits,
    error::HostError,
    image::{ExactBinaryImage, ImageReadError, MAX_READ_BINARY_CALL_BYTES},
    output::{callback_event_budget, encoded_event_line_len},
};

const HARD_MAX_CALLBACK_EVENTS: usize = 4_096;
const MAX_LOG_MESSAGE_BYTES: usize = 64 * 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CallbackPhase {
    Created = 0,
    Initializing = 1,
    Analyzing = 2,
    ShuttingDown = 3,
    Destroyed = 4,
}

#[derive(Debug, Clone)]
pub(crate) enum BufferedEvent {
    Log {
        level: &'static str,
        message: String,
    },
    Claim(Value),
}

#[derive(Debug, Default)]
struct CallbackBuffer {
    events: Vec<BufferedEvent>,
    encoded_bytes: usize,
    failure: Option<String>,
}

impl CallbackBuffer {
    fn fail(&mut self, message: impl Into<String>) {
        if self.failure.is_none() {
            self.failure = Some(message.into());
        }
    }

    fn reserve_event(
        &mut self,
        encoded_bytes: usize,
        max_events: usize,
        max_callback_bytes: usize,
    ) -> Result<(), Status> {
        if self.events.len() >= max_events {
            self.fail(format!(
                "native plugin exceeded the {max_events}-event limit"
            ));
            return Err(STATUS_RESOURCE_LIMIT);
        }
        let Some(total) = self.encoded_bytes.checked_add(encoded_bytes) else {
            self.fail("native plugin callback-byte counter overflowed");
            return Err(STATUS_RESOURCE_LIMIT);
        };
        if total > max_callback_bytes {
            self.fail(format!(
                "native plugin exceeded the {max_callback_bytes}-byte callback limit"
            ));
            return Err(STATUS_RESOURCE_LIMIT);
        }
        self.encoded_bytes = total;
        Ok(())
    }
}

pub(crate) struct CallbackContext {
    image: ExactBinaryImage,
    granted_permissions: BTreeSet<PluginPermission>,
    max_message_bytes: usize,
    max_events: usize,
    max_callback_bytes: usize,
    phase: AtomicU8,
    cancelled: AtomicBool,
    buffer: Mutex<CallbackBuffer>,
}

impl CallbackContext {
    pub(crate) fn new(
        image: ExactBinaryImage,
        granted_permissions: BTreeSet<PluginPermission>,
        limits: &WireLimits,
        max_messages: usize,
        max_stdout_bytes: usize,
    ) -> Self {
        Self {
            image,
            granted_permissions,
            max_message_bytes: limits.max_message_bytes,
            max_events: max_messages.saturating_sub(2).min(HARD_MAX_CALLBACK_EVENTS),
            max_callback_bytes: callback_event_budget(limits.max_message_bytes, max_stdout_bytes),
            phase: AtomicU8::new(CallbackPhase::Created as u8),
            cancelled: AtomicBool::new(false),
            buffer: Mutex::new(CallbackBuffer::default()),
        }
    }

    pub(crate) fn set_phase(&self, phase: CallbackPhase) {
        self.phase.store(phase as u8, Ordering::Release);
        if matches!(
            phase,
            CallbackPhase::ShuttingDown | CallbackPhase::Destroyed
        ) {
            self.cancelled.store(true, Ordering::Release);
        }
    }

    fn phase(&self) -> CallbackPhase {
        match self.phase.load(Ordering::Acquire) {
            0 => CallbackPhase::Created,
            1 => CallbackPhase::Initializing,
            2 => CallbackPhase::Analyzing,
            3 => CallbackPhase::ShuttingDown,
            _ => CallbackPhase::Destroyed,
        }
    }

    fn has_permission(&self, permission: &str) -> bool {
        self.granted_permissions
            .iter()
            .any(|granted| granted.as_str() == permission)
    }

    pub(crate) fn host_api(&mut self) -> HostApiV1 {
        HostApiV1 {
            struct_size: u32::try_from(std::mem::size_of::<HostApiV1>())
                .expect("ABI structure fits u32"),
            abi_version: abi::ABI_VERSION,
            host_context: std::ptr::from_mut(self).cast(),
            log: Some(host_log),
            read_binary: Some(host_read_binary),
            submit_claim: Some(host_submit_claim),
            is_cancelled: Some(host_is_cancelled),
            reserved: [std::ptr::null_mut(); 8],
        }
    }

    pub(crate) fn finish(&self) -> Result<Vec<BufferedEvent>, HostError> {
        let mut buffer = self
            .buffer
            .lock()
            .map_err(|_| HostError::Callback("callback state lock was poisoned".to_owned()))?;
        if let Some(failure) = buffer.failure.take() {
            return Err(HostError::Callback(failure));
        }
        Ok(std::mem::take(&mut buffer.events))
    }

    #[cfg(test)]
    fn record_failure_for_test(&self, message: &str) {
        self.buffer.lock().unwrap().fail(message);
    }
}

unsafe extern "C" fn host_log(host_context: *mut c_void, level: LogLevel, message: StringView) {
    // SAFETY: ReSymbol supplies this context pointer and retains its allocation
    // for the complete helper lifetime.
    let Some(context) = (unsafe { context(host_context) }) else {
        return;
    };
    if context.phase() == CallbackPhase::Destroyed {
        return;
    }
    let level = match level {
        LOG_TRACE => "trace",
        LOG_DEBUG => "debug",
        LOG_INFO => "info",
        LOG_WARN => "warn",
        LOG_ERROR => "error",
        _ => {
            fail_context(context, "native plugin used an invalid log level");
            return;
        }
    };
    // SAFETY: The native callback contract gives the host a borrowed readable
    // view for this call. A bad pointer can terminate only the helper process.
    let message = match unsafe {
        abi::copy_string_view(message, MAX_LOG_MESSAGE_BYTES, "native log message")
    } {
        Ok(message) if !message.chars().any(|character| character == '\0') => message,
        Ok(_) => {
            fail_context(context, "native log message contains an embedded NUL");
            return;
        }
        Err(error) => {
            fail_context(context, error.to_string());
            return;
        }
    };
    let Ok(mut buffer) = context.buffer.lock() else {
        return;
    };
    let event = BufferedEvent::Log { level, message };
    let encoded_bytes = match encoded_event_line_len(&event, context.max_message_bytes) {
        Ok(encoded_bytes) => encoded_bytes,
        Err(error) => {
            buffer.fail(format!(
                "native plugin log exceeds negotiated output limits: {error}"
            ));
            return;
        }
    };
    if buffer
        .reserve_event(
            encoded_bytes,
            context.max_events,
            context.max_callback_bytes,
        )
        .is_ok()
    {
        buffer.events.push(event);
    }
}

unsafe extern "C" fn host_read_binary(
    host_context: *mut c_void,
    rva: u64,
    destination: MutByteSpan,
    bytes_read: *mut u64,
) -> Status {
    // SAFETY: ReSymbol supplies this context pointer and retains its allocation
    // for the complete helper lifetime.
    let Some(context) = (unsafe { context(host_context) }) else {
        return STATUS_INVALID_ARGUMENT;
    };
    if bytes_read.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: `bytes_read` is required by the ABI to point to writable u64
    // storage for this call. A plugin violation is confined to this process.
    unsafe { bytes_read.write(0) };
    if !matches!(
        context.phase(),
        CallbackPhase::Initializing | CallbackPhase::Analyzing
    ) {
        return STATUS_CANCELLED;
    }
    if !context.has_permission(PluginPermission::BINARY_READ) {
        return STATUS_PERMISSION_DENIED;
    }
    let length = match usize::try_from(destination.length) {
        Ok(length) if length <= MAX_READ_BINARY_CALL_BYTES => length,
        _ => return STATUS_RESOURCE_LIMIT,
    };
    if length != 0 && destination.data.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: The plugin contract requires the span to be writable for its
    // declared length; the length has been converted and bounded above.
    let destination = if length == 0 {
        &mut []
    } else {
        // SAFETY: The plugin contract requires the non-null span to be writable
        // for its declared length; the length was bounded above.
        unsafe { slice::from_raw_parts_mut(destination.data, length) }
    };
    match context.image.read_rva(rva, destination) {
        Ok(count) => {
            // SAFETY: `bytes_read` was validated above and remains borrowed for
            // the duration of this synchronous callback.
            unsafe { bytes_read.write(u64::try_from(count).unwrap_or(u64::MAX)) };
            STATUS_OK
        }
        Err(ImageReadError::OutsideImage) => STATUS_INVALID_ARGUMENT,
        Err(ImageReadError::Limit) => STATUS_RESOURCE_LIMIT,
    }
}

unsafe extern "C" fn host_submit_claim(
    host_context: *mut c_void,
    claim_json_utf8: ByteView,
) -> Status {
    // SAFETY: ReSymbol supplies this context pointer and retains its allocation
    // for the complete helper lifetime.
    let Some(context) = (unsafe { context(host_context) }) else {
        return STATUS_INVALID_ARGUMENT;
    };
    if context.phase() != CallbackPhase::Analyzing {
        return STATUS_CANCELLED;
    }
    if !context.has_permission(PluginPermission::CLAIMS_SUBMIT) {
        return STATUS_PERMISSION_DENIED;
    }
    // SAFETY: The native callback contract gives the host a readable view for
    // this call. A bad pointer can terminate only the helper process.
    let bytes = match unsafe {
        abi::copy_byte_view(
            claim_json_utf8,
            context.max_message_bytes,
            "native claim JSON",
        )
    } {
        Ok(bytes) => bytes,
        Err(error) => {
            fail_context(context, error.to_string());
            return STATUS_RESOURCE_LIMIT;
        }
    };
    let claim = match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(claim)) => Value::Object(claim),
        Ok(_) => {
            fail_context(context, "native claim JSON must be an object");
            return STATUS_INVALID_ARGUMENT;
        }
        Err(error) => {
            fail_context(context, format!("invalid native claim JSON: {error}"));
            return STATUS_INVALID_ARGUMENT;
        }
    };
    let Ok(mut buffer) = context.buffer.lock() else {
        return STATUS_INTERNAL_ERROR;
    };
    let event = BufferedEvent::Claim(claim);
    let encoded_bytes = match encoded_event_line_len(&event, context.max_message_bytes) {
        Ok(encoded_bytes) => encoded_bytes,
        Err(error) => {
            buffer.fail(format!(
                "native plugin claim exceeds negotiated output limits: {error}"
            ));
            return STATUS_RESOURCE_LIMIT;
        }
    };
    if let Err(status) = buffer.reserve_event(
        encoded_bytes,
        context.max_events,
        context.max_callback_bytes,
    ) {
        return status;
    }
    buffer.events.push(event);
    STATUS_OK
}

unsafe extern "C" fn host_is_cancelled(host_context: *mut c_void) -> u32 {
    // SAFETY: ReSymbol supplies this context pointer and retains its allocation
    // for the complete helper lifetime.
    let Some(context) = (unsafe { context(host_context) }) else {
        return 1;
    };
    u32::from(context.cancelled.load(Ordering::Acquire))
}

unsafe fn context<'a>(host_context: *mut c_void) -> Option<&'a CallbackContext> {
    if host_context.is_null() {
        return None;
    }
    // SAFETY: `host_context` is created from a boxed CallbackContext and the
    // executable deliberately retains that allocation until process exit.
    Some(unsafe { &*host_context.cast::<CallbackContext>() })
}

fn fail_context(context: &CallbackContext, message: impl Into<String>) {
    if let Ok(mut buffer) = context.buffer.lock() {
        buffer.fail(message);
    }
}

pub(crate) fn validate_grants(
    manifest: &PluginManifest,
    granted: &BTreeSet<PluginPermission>,
) -> Result<(), HostError> {
    for permission in granted {
        if !manifest.permissions.contains(permission) {
            return Err(HostError::Wire(format!(
                "permission `{permission}` was granted but not requested"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        image::ExactBinaryImage,
        output::{NativeExecution, ValidatedDescriptor, encode_execution},
    };
    use serde_json::json;

    fn permission(value: &str) -> PluginPermission {
        PluginPermission::new(value).unwrap()
    }

    fn wire_limits(max_message_bytes: usize) -> WireLimits {
        WireLimits {
            max_message_bytes,
            max_memory_bytes: 1_048_576,
            request_timeout_ms: 30_000,
        }
    }

    fn submit_claim(context: &mut CallbackContext, claim: &[u8]) -> Status {
        let host = context.host_api();
        let submit = host.submit_claim.unwrap();
        // SAFETY: The context and bounded byte slice remain live for this
        // synchronous invocation of the host's own callback.
        unsafe {
            submit(
                host.host_context,
                ByteView {
                    data: claim.as_ptr(),
                    length: claim.len() as u64,
                },
            )
        }
    }

    #[test]
    fn sticky_callback_failures_discard_events() {
        let context = CallbackContext {
            image: ExactBinaryImage::test_empty(),
            granted_permissions: BTreeSet::new(),
            max_message_bytes: 1_024,
            max_events: 1,
            max_callback_bytes: 1_024,
            phase: AtomicU8::new(CallbackPhase::Created as u8),
            cancelled: AtomicBool::new(false),
            buffer: Mutex::new(CallbackBuffer::default()),
        };
        context.record_failure_for_test("bad callback");
        assert!(context.finish().is_err());
    }

    #[test]
    fn claim_callback_is_phase_and_permission_gated() {
        let mut context = CallbackContext {
            image: ExactBinaryImage::test_empty(),
            granted_permissions: BTreeSet::from([permission(PluginPermission::CLAIMS_SUBMIT)]),
            max_message_bytes: 1_024,
            max_events: 1,
            max_callback_bytes: 1_024,
            phase: AtomicU8::new(CallbackPhase::Created as u8),
            cancelled: AtomicBool::new(false),
            buffer: Mutex::new(CallbackBuffer::default()),
        };
        let host = context.host_api();
        let claim = b"{}";
        let submit = host.submit_claim.unwrap();
        // SAFETY: The context and claim view remain live for this synchronous
        // callback, and the function came from the host's own API table.
        let before_analyze = unsafe {
            submit(
                host.host_context,
                ByteView {
                    data: claim.as_ptr(),
                    length: claim.len() as u64,
                },
            )
        };
        assert_eq!(before_analyze, STATUS_CANCELLED);
        context.set_phase(CallbackPhase::Analyzing);
        // SAFETY: Same live context and bounded readable view as above.
        let accepted = unsafe {
            submit(
                host.host_context,
                ByteView {
                    data: claim.as_ptr(),
                    length: claim.len() as u64,
                },
            )
        };
        assert_eq!(accepted, STATUS_OK);
        assert!(matches!(
            context.finish().unwrap().as_slice(),
            [BufferedEvent::Claim(Value::Object(_))]
        ));
    }

    #[test]
    fn binary_callback_sets_count_and_honors_permission() {
        let mut context = CallbackContext {
            image: ExactBinaryImage::test_empty(),
            granted_permissions: BTreeSet::from([permission(PluginPermission::BINARY_READ)]),
            max_message_bytes: 1_024,
            max_events: 1,
            max_callback_bytes: 1_024,
            phase: AtomicU8::new(CallbackPhase::Initializing as u8),
            cancelled: AtomicBool::new(false),
            buffer: Mutex::new(CallbackBuffer::default()),
        };
        let host = context.host_api();
        let read = host.read_binary.unwrap();
        let mut destination = [0xff_u8; 4];
        let mut count = u64::MAX;
        // SAFETY: All output pointers refer to live writable test storage and
        // the function came from the host's own API table.
        let status = unsafe {
            read(
                host.host_context,
                0,
                MutByteSpan {
                    data: destination.as_mut_ptr(),
                    length: destination.len() as u64,
                },
                &mut count,
            )
        };
        assert_eq!(status, STATUS_OK);
        assert_eq!(count, 1);
        assert_eq!(destination[0], 0);
    }

    #[test]
    fn callback_caps_reserve_hello_and_response_messages() {
        let limits = wire_limits(1_024);
        let negotiated = CallbackContext::new(
            ExactBinaryImage::test_empty(),
            BTreeSet::new(),
            &limits,
            3,
            2_048,
        );
        assert_eq!(negotiated.max_events, 1);
        assert_eq!(negotiated.max_callback_bytes, 0);

        let hard_bounded = CallbackContext::new(
            ExactBinaryImage::test_empty(),
            BTreeSet::new(),
            &limits,
            usize::MAX,
            usize::MAX,
        );
        assert_eq!(hard_bounded.max_events, HARD_MAX_CALLBACK_EVENTS);
        assert_eq!(
            hard_bounded.max_callback_bytes,
            callback_event_budget(limits.max_message_bytes, usize::MAX)
        );
    }

    #[test]
    fn accepted_event_cannot_exhaust_reserved_protocol_frames() {
        let max_message_bytes = 1_024;
        let limits = wire_limits(max_message_bytes);
        let claim_value = json!({ "name": "quoted\n\"symbol" });
        let claim = serde_json::to_vec(&claim_value).unwrap();
        let event = BufferedEvent::Claim(claim_value);
        let event_bytes = encoded_event_line_len(&event, max_message_bytes).unwrap();
        let reserved_protocol_bytes = 2 * (max_message_bytes + 1);
        let max_stdout_bytes = reserved_protocol_bytes + event_bytes;

        let mut context = CallbackContext::new(
            ExactBinaryImage::test_empty(),
            BTreeSet::from([permission(PluginPermission::CLAIMS_SUBMIT)]),
            &limits,
            3,
            max_stdout_bytes,
        );
        context.set_phase(CallbackPhase::Analyzing);
        assert_eq!(submit_claim(&mut context, &claim), STATUS_OK);

        let output = encode_execution(
            NativeExecution {
                descriptor: ValidatedDescriptor {
                    id: "dev.example.plugin".to_owned(),
                    name: "Example".to_owned(),
                    version: "1.0.0".to_owned(),
                    capabilities: Vec::new(),
                    requested_permissions: vec![PluginPermission::CLAIMS_SUBMIT.to_owned()],
                },
                events: context.finish().unwrap(),
                rejection: None,
            },
            "request-1",
            max_message_bytes,
            max_stdout_bytes,
        )
        .unwrap();
        assert!(output.len() <= max_stdout_bytes);
    }

    #[test]
    fn aggregate_over_limit_claim_returns_resource_limit_and_is_sticky() {
        let max_message_bytes = 1_024;
        let limits = wire_limits(max_message_bytes);
        let claim_value = json!({ "name": "quoted\n\"symbol" });
        let claim = serde_json::to_vec(&claim_value).unwrap();
        let event_bytes =
            encoded_event_line_len(&BufferedEvent::Claim(claim_value), max_message_bytes).unwrap();
        let reserved_protocol_bytes = 2 * (max_message_bytes + 1);
        let max_stdout_bytes = reserved_protocol_bytes + event_bytes - 1;

        let mut context = CallbackContext::new(
            ExactBinaryImage::test_empty(),
            BTreeSet::from([permission(PluginPermission::CLAIMS_SUBMIT)]),
            &limits,
            3,
            max_stdout_bytes,
        );
        context.set_phase(CallbackPhase::Analyzing);
        assert_eq!(submit_claim(&mut context, &claim), STATUS_RESOURCE_LIMIT);
        assert!(matches!(context.finish(), Err(HostError::Callback(_))));
    }

    #[test]
    fn event_envelope_over_message_limit_is_rejected_before_buffering() {
        let max_message_bytes = 1_024;
        let limits = wire_limits(max_message_bytes);
        let claim = serde_json::to_vec(&json!({ "data": "x".repeat(900) })).unwrap();
        assert!(claim.len() <= max_message_bytes);

        let mut context = CallbackContext::new(
            ExactBinaryImage::test_empty(),
            BTreeSet::from([permission(PluginPermission::CLAIMS_SUBMIT)]),
            &limits,
            3,
            8 * 1_024 * 1_024,
        );
        context.set_phase(CallbackPhase::Analyzing);
        assert_eq!(submit_claim(&mut context, &claim), STATUS_RESOURCE_LIMIT);
        assert!(matches!(context.finish(), Err(HostError::Callback(_))));
    }
}
