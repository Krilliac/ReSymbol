//! Minimal Win32 boundary for read-only sandbox capability discovery.

use std::{ffi::c_void, mem, ptr};

use windows_sys::Win32::{
    Foundation::{FreeLibrary, HMODULE},
    System::{
        LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
        Threading::{IsProcessorFeaturePresent, PF_VIRT_FIRMWARE_ENABLED},
    },
};

const WHV_CAPABILITY_CODE_HYPERVISOR_PRESENT: i32 = 0;

/// Result of one stable, read-only operating-system capability query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityObservation {
    /// The queried capability was present at observation time.
    Present,
    /// The query completed and did not observe the capability.
    Absent,
    /// The host did not expose a trustworthy way to complete the query.
    QueryUnavailable,
}

/// Value-only snapshot used by the backend-neutral readiness reducer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxCapabilitySnapshot {
    pub app_container_apis: CapabilityObservation,
    pub firmware_virtualization: CapabilityObservation,
    pub hypervisor: CapabilityObservation,
}

/// Observe the strongest bounded subset available through stable, read-only
/// Windows APIs.
///
/// This checks only API presence and machine capability state. It deliberately
/// does not query or change optional-feature state, policy, provider helpers,
/// VM images, or any runtime containment guarantee.
#[must_use]
pub fn observe_sandbox_capabilities() -> SandboxCapabilitySnapshot {
    SandboxCapabilitySnapshot {
        app_container_apis: observe_app_container_apis(),
        firmware_virtualization: observe_firmware_virtualization(),
        hypervisor: observe_hypervisor(),
    }
}

fn observe_app_container_apis() -> CapabilityObservation {
    let Some(module) = SystemModule::load("userenv.dll") else {
        return CapabilityObservation::QueryUnavailable;
    };
    const REQUIRED_EXPORTS: [&[u8]; 3] = [
        b"CreateAppContainerProfile\0",
        b"DeleteAppContainerProfile\0",
        b"DeriveAppContainerSidFromAppContainerName\0",
    ];
    if REQUIRED_EXPORTS.iter().all(|name| module.has_export(name)) {
        CapabilityObservation::Present
    } else {
        CapabilityObservation::Absent
    }
}

fn observe_firmware_virtualization() -> CapabilityObservation {
    // SAFETY: IsProcessorFeaturePresent accepts a fixed documented feature ID,
    // reads process-independent system capability state, and owns no resources.
    if unsafe { IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) } != 0 {
        CapabilityObservation::Present
    } else {
        CapabilityObservation::Absent
    }
}

fn observe_hypervisor() -> CapabilityObservation {
    let Some(module) = SystemModule::load("winhvplatform.dll") else {
        return CapabilityObservation::QueryUnavailable;
    };
    let Some(raw_query) = module.export(b"WHvGetCapability\0") else {
        return CapabilityObservation::QueryUnavailable;
    };

    type WhvGetCapability = unsafe extern "system" fn(
        capability_code: i32,
        capability_buffer: *mut c_void,
        capability_buffer_size: u32,
        written_size: *mut u32,
    ) -> i32;

    // SAFETY: GetProcAddress returned the documented WHvGetCapability export
    // from the system32 copy of winhvplatform.dll. The declared signature is
    // the stable Win32 ABI for that export.
    let query: WhvGetCapability = unsafe { mem::transmute(raw_query) };
    // Microsoft documents that capability output buffers should be large
    // enough for a 64-bit value, even though HypervisorPresent itself is a
    // Win32 BOOL. Keep the full buffer zeroed and inspect only the BOOL-sized
    // low portion so both four-byte and eight-byte writes are accepted.
    let mut present_buffer = 0_u64;
    let mut written = 0_u32;
    // SAFETY: Both output pointers refer to initialized, correctly sized local
    // values for WHvCapabilityCodeHypervisorPresent and remain valid for the
    // duration of the call.
    let result = unsafe {
        query(
            WHV_CAPABILITY_CODE_HYPERVISOR_PRESENT,
            ptr::addr_of_mut!(present_buffer).cast(),
            mem::size_of_val(&present_buffer) as u32,
            ptr::addr_of_mut!(written),
        )
    };
    let bool_size = mem::size_of::<i32>() as u32;
    let buffer_size = mem::size_of_val(&present_buffer) as u32;
    if result < 0 || written < bool_size || written > buffer_size {
        CapabilityObservation::QueryUnavailable
    } else if present_buffer as u32 != 0 {
        CapabilityObservation::Present
    } else {
        CapabilityObservation::Absent
    }
}

struct SystemModule(HMODULE);

impl SystemModule {
    fn load(name: &str) -> Option<Self> {
        let mut wide = name.encode_utf16().collect::<Vec<_>>();
        wide.push(0);
        // SAFETY: `wide` is NUL-terminated and remains alive for the call. The
        // SYSTEM32-only search flag prevents PATH/current-directory resolution.
        let module =
            unsafe { LoadLibraryExW(wide.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        (!module.is_null()).then_some(Self(module))
    }

    fn export(&self, name: &'static [u8]) -> Option<unsafe extern "system" fn() -> isize> {
        debug_assert_eq!(name.last(), Some(&0));
        // SAFETY: `self.0` remains loaded and `name` is a static NUL-terminated
        // ASCII export name.
        unsafe { GetProcAddress(self.0, name.as_ptr()) }
    }

    fn has_export(&self, name: &'static [u8]) -> bool {
        self.export(name).is_some()
    }
}

impl Drop for SystemModule {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null module handle returned by exactly one
        // successful LoadLibraryExW call and is released exactly once here.
        let _ = unsafe { FreeLibrary(self.0) };
    }
}
