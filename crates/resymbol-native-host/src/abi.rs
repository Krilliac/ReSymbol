use std::{ffi::c_void, mem, ptr, slice, str};

use crate::error::HostError;

pub(crate) type Status = i32;
pub(crate) type LogLevel = u32;
pub(crate) type IsolationRequirement = u32;

pub(crate) const STATUS_OK: Status = 0;
pub(crate) const STATUS_INVALID_ARGUMENT: Status = 1;
pub(crate) const STATUS_INCOMPATIBLE_ABI: Status = 2;
pub(crate) const STATUS_INTERNAL_ERROR: Status = 3;
pub(crate) const STATUS_UNAVAILABLE: Status = 4;
pub(crate) const STATUS_PERMISSION_DENIED: Status = 5;
pub(crate) const STATUS_CANCELLED: Status = 6;
pub(crate) const STATUS_RESOURCE_LIMIT: Status = 7;

pub(crate) const LOG_TRACE: LogLevel = 0;
pub(crate) const LOG_DEBUG: LogLevel = 1;
pub(crate) const LOG_INFO: LogLevel = 2;
pub(crate) const LOG_WARN: LogLevel = 3;
pub(crate) const LOG_ERROR: LogLevel = 4;

pub(crate) const ISOLATION_OUT_OF_PROCESS: IsolationRequirement = 1;
pub(crate) const ISOLATION_TRUSTED_IN_PROCESS_ALLOWED: IsolationRequirement = 2;
pub(crate) const ABI_VERSION_MAJOR: u32 = 1;
pub(crate) const ABI_VERSION_MINOR: u32 = 0;
pub(crate) const ABI_VERSION: u32 = (ABI_VERSION_MAJOR << 16) | ABI_VERSION_MINOR;
pub(crate) const ENTRYPOINT_NAME: &[u8] = b"resymbol_plugin_get_api\0";

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct StringView {
    pub(crate) data: *const i8,
    pub(crate) length: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ByteView {
    pub(crate) data: *const u8,
    pub(crate) length: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct MutByteSpan {
    pub(crate) data: *mut u8,
    pub(crate) length: u64,
}

pub(crate) type HostLogFn = unsafe extern "C" fn(*mut c_void, LogLevel, StringView);
pub(crate) type HostReadBinaryFn =
    unsafe extern "C" fn(*mut c_void, u64, MutByteSpan, *mut u64) -> Status;
pub(crate) type HostSubmitClaimFn = unsafe extern "C" fn(*mut c_void, ByteView) -> Status;
pub(crate) type HostIsCancelledFn = unsafe extern "C" fn(*mut c_void) -> u32;

#[repr(C)]
pub(crate) struct HostApiV1 {
    pub(crate) struct_size: u32,
    pub(crate) abi_version: u32,
    pub(crate) host_context: *mut c_void,
    pub(crate) log: Option<HostLogFn>,
    pub(crate) read_binary: Option<HostReadBinaryFn>,
    pub(crate) submit_claim: Option<HostSubmitClaimFn>,
    pub(crate) is_cancelled: Option<HostIsCancelledFn>,
    pub(crate) reserved: [*mut c_void; 8],
}

#[repr(C)]
pub(crate) struct PluginDescriptorV1 {
    pub(crate) struct_size: u32,
    pub(crate) abi_version: u32,
    pub(crate) id: StringView,
    pub(crate) name: StringView,
    pub(crate) version: StringView,
    pub(crate) isolation: IsolationRequirement,
    pub(crate) capabilities_json_utf8: ByteView,
    pub(crate) requested_permissions_json_utf8: ByteView,
    pub(crate) reserved: [*mut c_void; 8],
}

pub(crate) type PluginGetDescriptorFn =
    unsafe extern "C" fn(*mut c_void, *mut PluginDescriptorV1) -> Status;
pub(crate) type PluginInitializeFn = unsafe extern "C" fn(*mut c_void, ByteView) -> Status;
pub(crate) type PluginAnalyzeFn = unsafe extern "C" fn(*mut c_void, ByteView) -> Status;
pub(crate) type PluginHealthCheckFn = unsafe extern "C" fn(*mut c_void) -> Status;
pub(crate) type PluginShutdownFn = unsafe extern "C" fn(*mut c_void);
pub(crate) type PluginDestroyFn = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
pub(crate) struct PluginApiV1 {
    pub(crate) struct_size: u32,
    pub(crate) abi_version: u32,
    pub(crate) plugin_context: *mut c_void,
    pub(crate) get_descriptor: Option<PluginGetDescriptorFn>,
    pub(crate) initialize: Option<PluginInitializeFn>,
    pub(crate) analyze: Option<PluginAnalyzeFn>,
    pub(crate) health_check: Option<PluginHealthCheckFn>,
    pub(crate) shutdown: Option<PluginShutdownFn>,
    pub(crate) destroy: Option<PluginDestroyFn>,
    pub(crate) reserved: [*mut c_void; 8],
}

impl PluginApiV1 {
    pub(crate) fn empty_for_host() -> Self {
        Self {
            struct_size: u32::try_from(mem::size_of::<Self>()).expect("ABI structure fits u32"),
            abi_version: ABI_VERSION,
            plugin_context: ptr::null_mut(),
            get_descriptor: None,
            initialize: None,
            analyze: None,
            health_check: None,
            shutdown: None,
            destroy: None,
            reserved: [ptr::null_mut(); 8],
        }
    }

    pub(crate) fn validate(&self) -> Result<(), HostError> {
        validate_struct_size::<Self>(
            self.struct_size,
            std::mem::offset_of!(Self, destroy) + mem::size_of::<Option<PluginDestroyFn>>(),
            "plugin API",
        )?;
        validate_abi_version(self.abi_version, "plugin API")?;
        if self.get_descriptor.is_none()
            || self.initialize.is_none()
            || self.analyze.is_none()
            || self.health_check.is_none()
            || self.shutdown.is_none()
            || self.destroy.is_none()
        {
            return Err(HostError::Abi(
                "plugin API omits a required lifecycle function".to_owned(),
            ));
        }
        validate_reserved(
            self.struct_size,
            std::mem::offset_of!(Self, reserved),
            &self.reserved,
        )
    }
}

impl PluginDescriptorV1 {
    pub(crate) fn empty_for_host() -> Self {
        Self {
            struct_size: u32::try_from(mem::size_of::<Self>()).expect("ABI structure fits u32"),
            abi_version: ABI_VERSION,
            id: StringView {
                data: ptr::null(),
                length: 0,
            },
            name: StringView {
                data: ptr::null(),
                length: 0,
            },
            version: StringView {
                data: ptr::null(),
                length: 0,
            },
            isolation: 0,
            capabilities_json_utf8: ByteView {
                data: ptr::null(),
                length: 0,
            },
            requested_permissions_json_utf8: ByteView {
                data: ptr::null(),
                length: 0,
            },
            reserved: [ptr::null_mut(); 8],
        }
    }

    pub(crate) fn validate_header(&self) -> Result<(), HostError> {
        validate_struct_size::<Self>(
            self.struct_size,
            std::mem::offset_of!(Self, requested_permissions_json_utf8)
                + mem::size_of::<ByteView>(),
            "plugin descriptor",
        )?;
        validate_abi_version(self.abi_version, "plugin descriptor")?;
        validate_reserved(
            self.struct_size,
            std::mem::offset_of!(Self, reserved),
            &self.reserved,
        )
    }
}

pub(crate) type PluginGetApiFn =
    unsafe extern "C" fn(u32, *const HostApiV1, *mut PluginApiV1) -> Status;

fn validate_struct_size<T>(supplied: u32, minimum: usize, label: &str) -> Result<(), HostError> {
    let supplied = usize::try_from(supplied)
        .map_err(|_| HostError::Abi(format!("{label} size does not fit this host")))?;
    if supplied < minimum || supplied > mem::size_of::<T>() {
        return Err(HostError::Abi(format!(
            "{label} size {supplied} is outside {minimum}..={}",
            mem::size_of::<T>()
        )));
    }
    Ok(())
}

fn validate_abi_version(version: u32, label: &str) -> Result<(), HostError> {
    let major = version >> 16;
    let minor = version & 0xffff;
    if major != ABI_VERSION_MAJOR || minor > ABI_VERSION_MINOR {
        return Err(HostError::Abi(format!(
            "{label} reports unsupported ABI {major}.{minor}"
        )));
    }
    Ok(())
}

fn validate_reserved(
    struct_size: u32,
    reserved_offset: usize,
    reserved: &[*mut c_void; 8],
) -> Result<(), HostError> {
    let supplied = usize::try_from(struct_size).unwrap_or(usize::MAX);
    if supplied <= reserved_offset {
        return Ok(());
    }
    let visible_bytes = supplied.saturating_sub(reserved_offset);
    let visible_slots = visible_bytes
        .div_ceil(mem::size_of::<*mut c_void>())
        .min(reserved.len());
    if reserved[..visible_slots]
        .iter()
        .any(|pointer| !pointer.is_null())
    {
        return Err(HostError::Abi(
            "a reserved ABI field is non-null".to_owned(),
        ));
    }
    Ok(())
}

/// Copy a plugin-owned byte view before the next plugin call.
///
/// # Safety
///
/// The plugin contract requires a non-null, readable allocation of at least
/// `view.length` bytes for every non-empty view. A plugin that violates that
/// requirement may terminate only this helper process.
pub(crate) unsafe fn copy_byte_view(
    view: ByteView,
    limit: usize,
    label: &str,
) -> Result<Vec<u8>, HostError> {
    let length = usize::try_from(view.length)
        .map_err(|_| HostError::Abi(format!("{label} length does not fit this host")))?;
    if length > limit {
        return Err(HostError::Abi(format!(
            "{label} exceeds its {limit}-byte limit"
        )));
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    if view.data.is_null() {
        return Err(HostError::Abi(format!(
            "{label} has a null pointer with nonzero length"
        )));
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(length)
        .map_err(|_| HostError::Abi(format!("cannot reserve memory for {label}")))?;
    // SAFETY: The caller upholds the native ABI's readable-view contract; the
    // length was converted and bounded above before constructing this slice.
    let borrowed = unsafe { slice::from_raw_parts(view.data, length) };
    owned.extend_from_slice(borrowed);
    Ok(owned)
}

/// Copy and decode a plugin-owned UTF-8 string view.
///
/// # Safety
///
/// The same readable-view contract as [`copy_byte_view`] applies.
pub(crate) unsafe fn copy_string_view(
    view: StringView,
    limit: usize,
    label: &str,
) -> Result<String, HostError> {
    // SAFETY: The caller upholds the same readable-view contract forwarded to
    // `copy_byte_view`.
    let bytes = unsafe {
        copy_byte_view(
            ByteView {
                data: view.data.cast(),
                length: view.length,
            },
            limit,
            label,
        )
    }?;
    let text = str::from_utf8(&bytes)
        .map_err(|_| HostError::Abi(format!("{label} is not valid UTF-8")))?;
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_layout_has_stable_pointer_width_shape() {
        assert_eq!(mem::size_of::<StringView>(), mem::size_of::<ByteView>());
        assert_eq!(mem::size_of::<ByteView>(), mem::size_of::<MutByteSpan>());
        if cfg!(target_pointer_width = "64") {
            assert_eq!(mem::size_of::<HostApiV1>(), 112);
            assert_eq!(mem::size_of::<PluginDescriptorV1>(), 160);
            assert_eq!(mem::size_of::<PluginApiV1>(), 128);
        }
    }

    #[test]
    fn api_validation_rejects_missing_callbacks_and_reserved_values() {
        let mut api = PluginApiV1::empty_for_host();
        assert!(api.validate().is_err());
        api.struct_size = 0;
        assert!(api.validate().is_err());
    }

    #[test]
    fn byte_views_are_bounded_before_copying() {
        let bytes = b"hello";
        let view = ByteView {
            data: bytes.as_ptr(),
            length: bytes.len() as u64,
        };
        // SAFETY: `view` points to `bytes` for its declared length.
        assert_eq!(unsafe { copy_byte_view(view, 5, "test") }.unwrap(), bytes);
        // SAFETY: The pointer is not accessed because the length limit fails first.
        assert!(unsafe { copy_byte_view(view, 4, "test") }.is_err());
    }
}
