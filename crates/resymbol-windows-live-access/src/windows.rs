use std::{
    cell::Cell,
    ffi::c_void,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Seek},
    marker::PhantomData,
    mem::size_of,
    os::windows::{
        fs::{FileExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    path::{Path, PathBuf},
};

use resymbol_core::BinaryId;
use resymbol_debugger::protocol::{
    LiveTargetBinding, LiveTargetBindingError, MemoryAddress, ProcessIdentity, ProcessStartKey,
};
use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{
        ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER, FALSE, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{FILE_SHARE_READ, SYNCHRONIZE},
    System::{
        Diagnostics::{
            Debug::{FlushInstructionCache, ReadProcessMemory, WriteProcessMemory},
            ToolHelp::{
                CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, TH32CS_SNAPMODULE,
                TH32CS_SNAPMODULE32,
            },
        },
        Memory::{
            MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
            PAGE_PROTECTION_FLAGS, VirtualProtectEx, VirtualQueryEx,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        Threading::{
            GetProcessId, GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, QueryFullProcessImageNameW,
            WaitForSingleObject,
        },
    },
};

use crate::{
    AccessRequestError, OpenLiveProcessRequest, validate_read_size, validate_write_request,
};

const MODULE_SNAPSHOT_ATTEMPTS: usize = 8;
const MAX_MAIN_IMAGE_REGIONS: usize = 4_096;
const INITIAL_IMAGE_PATH_CHARS: usize = 260;
const MAX_IMAGE_PATH_CHARS: usize = 32_768;
const DOS_HEADER_BYTES: usize = 64;
const NT_HEADER_PREFIX_BYTES: usize = 84;
const PE_SIGNATURE_BYTES: &[u8; 4] = b"PE\0\0";
const IMAGE_DOS_SIGNATURE: &[u8; 2] = b"MZ";
const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const MIN_OPTIONAL_HEADER_FOR_SIZE_OF_IMAGE: u16 = 60;
const PROTECTION_BASE_MASK: u32 = 0xff;

const READ_PROCESS_ACCESS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE;
const MUTATING_PROCESS_ACCESS: u32 = READ_PROCESS_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

/// Marker for a handle opened without memory-mutation rights.
#[derive(Debug)]
pub enum ReadOnlyAccess {}

/// Marker for a handle explicitly opened with memory-mutation rights.
#[derive(Debug)]
pub enum MutationAccess {}

/// One exact Windows process and main-module mapping.
///
/// The value is movable but intentionally not `Sync`; one future helper worker
/// must serialize access to the owned handle. It does not stop target threads.
/// A caller must establish a valid stopped-state authority before using a write
/// through this lower-level boundary.
#[derive(Debug)]
pub struct LiveProcessAccess<Mode> {
    process: OwnedHandle,
    binding: LiveTargetBinding,
    executable: ExactExecutable,
    _mode: PhantomData<Mode>,
    _single_owner: PhantomData<Cell<()>>,
}

pub type ReadOnlyLiveProcessAccess = LiveProcessAccess<ReadOnlyAccess>;
pub type MutatingLiveProcessAccess = LiveProcessAccess<MutationAccess>;

impl LiveProcessAccess<ReadOnlyAccess> {
    /// Opens exactly the selected PID without mutation rights.
    pub fn open_read_only(request: OpenLiveProcessRequest) -> Result<Self, LiveAccessError> {
        Self::open_with_access(request, READ_PROCESS_ACCESS)
    }
}

impl LiveProcessAccess<MutationAccess> {
    /// Opens exactly the selected PID with explicit memory-mutation rights.
    pub fn open_mutating(request: OpenLiveProcessRequest) -> Result<Self, LiveAccessError> {
        Self::open_with_access(request, MUTATING_PROCESS_ACCESS)
    }
}

impl<Mode> LiveProcessAccess<Mode> {
    fn open_with_access(
        request: OpenLiveProcessRequest,
        process_access: u32,
    ) -> Result<Self, LiveAccessError> {
        // SAFETY: all arguments are scalar values; ownership of any valid
        // returned real handle is immediately transferred to `OwnedHandle`.
        let raw = unsafe { OpenProcess(process_access, FALSE, request.process_id().get()) };
        let process = owned_handle(raw, "open selected live process")?;
        let actual_start_key = process_start_key(&process)?;
        if actual_start_key != request.expected_start_key().get() {
            return Err(LiveAccessError::ProcessStartIdentityMismatch {
                expected: request.expected_start_key().get(),
                actual: actual_start_key,
            });
        }
        let executable = open_exact_executable(&process, request.expected_main_module_binary_id())?;
        let binding = observe_live_target(
            &process,
            request.process_id(),
            request.expected_main_image_base(),
            request.expected_main_module_binary_id(),
            &executable,
        )?;

        Ok(Self {
            process,
            binding,
            executable,
            _mode: PhantomData,
            _single_owner: PhantomData,
        })
    }

    #[must_use]
    pub const fn binding(&self) -> &LiveTargetBinding {
        &self.binding
    }

    /// Diagnostic path observed while hashing the exact executable.
    ///
    /// This path is not authority. Every operation refreshes and compares the
    /// complete process/main-module binding instead.
    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.executable.path
    }

    /// Re-derives the complete binding and accepts it only when it equals both
    /// the handle's opening binding and the caller's exact expected binding.
    pub fn refresh_binding(
        &self,
        expected: &LiveTargetBinding,
    ) -> Result<LiveTargetBinding, LiveAccessError> {
        self.ensure_exact_binding(expected)
    }

    /// Reads a nonempty bounded span from the validated main-image RVA range.
    ///
    /// The result is published only after a second full binding validation, so
    /// a stale/exited/mismatched process discards the temporary bytes.
    pub fn read_exact_rva(
        &self,
        expected_binding: &LiveTargetBinding,
        rva: u64,
        size: usize,
    ) -> Result<Vec<u8>, LiveAccessError> {
        validate_read_size(size)?;
        let binding = self.ensure_exact_binding(expected_binding)?;
        let address = binding.address_for_rva_span(rva, usize_to_u64(size))?;
        let bytes = read_raw_exact(&self.process, address.get(), size)?;
        self.ensure_exact_binding(expected_binding)?;
        Ok(bytes)
    }

    fn ensure_exact_binding(
        &self,
        expected: &LiveTargetBinding,
    ) -> Result<LiveTargetBinding, LiveAccessError> {
        ensure_exact_binding_parts(&self.process, &self.binding, &self.executable, expected)
    }
}

fn ensure_exact_binding_parts(
    process: &OwnedHandle,
    retained: &LiveTargetBinding,
    executable: &ExactExecutable,
    expected: &LiveTargetBinding,
) -> Result<LiveTargetBinding, LiveAccessError> {
    if expected != retained {
        return Err(LiveAccessError::BindingMismatch);
    }
    let observed = observe_live_target(
        process,
        retained.process().process_id,
        retained.actual_image_base(),
        retained.main_module_binary_id(),
        executable,
    )?;
    if observed.process().start_key != retained.process().start_key {
        return Err(LiveAccessError::ProcessStartIdentityChanged);
    }
    if &observed != retained {
        return Err(LiveAccessError::BindingMismatch);
    }
    Ok(observed)
}

impl LiveProcessAccess<MutationAccess> {
    /// Performs one same-length, main-image, executable-page mutation.
    ///
    /// The caller must present the exact retained binding and exact bytes it
    /// expects to replace. The operation revalidates binding before comparison,
    /// again immediately before changing protection, and after readback. It
    /// rejects cross-region and cross-system-page writes so one captured page
    /// protection can be restored exactly, flushes the instruction cache,
    /// restores protection, and verifies the replacement bytes before
    /// returning a receipt.
    pub fn compare_before_write_rva(
        &mut self,
        expected_binding: &LiveTargetBinding,
        rva: u64,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<WriteReceipt, LiveAccessError> {
        validate_write_request(expected, replacement)?;
        let size = usize_to_u64(expected.len());
        let binding = self.ensure_exact_binding(expected_binding)?;
        let address = binding.address_for_rva_span(rva, size)?.get();
        let mut operations = WindowsMutationOperations {
            process: &self.process,
            retained_binding: &self.binding,
            executable: &self.executable,
        };
        compare_before_write_transaction(
            &mut operations,
            expected_binding,
            rva,
            address,
            expected,
            replacement,
        )?;

        Ok(WriteReceipt {
            binding: binding.clone(),
            rva,
            bytes_written: replacement.len(),
        })
    }
}

#[must_use = "a successful mutation receipt is the only proof this call completed"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReceipt {
    binding: LiveTargetBinding,
    rva: u64,
    bytes_written: usize,
}

impl WriteReceipt {
    #[must_use]
    pub const fn binding(&self) -> &LiveTargetBinding {
        &self.binding
    }

    #[must_use]
    pub const fn rva(&self) -> u64 {
        self.rva
    }

    #[must_use]
    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum MutationStage {
    #[error("detecting a protection race")]
    ProtectionRace,
    #[error("revalidating expected bytes after changing protection")]
    RevalidateExpectedBytes,
    #[error("writing replacement bytes")]
    WriteReplacement,
    #[error("flushing replacement instructions")]
    FlushReplacement,
    #[error("restoring page protection")]
    RestoreProtection,
    #[error("verifying replacement bytes")]
    VerifyReplacement,
    #[error("validating the final live binding")]
    ValidateFinalBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationRecovery {
    /// ReSymbol detected failure before calling `WriteProcessMemory`.
    ///
    /// This makes no claim about concurrent target-side writes; it records
    /// only that this operation did not attempt to modify the byte span.
    NoWriteAttempted {
        /// Whether the protection observed immediately before ReSymbol's
        /// change was successfully restored.
        protection_restored: bool,
    },
    Restored,
    Indeterminate {
        bytes_restored: bool,
        instruction_cache_flushed: bool,
        protection_restored: bool,
    },
}

impl fmt::Display for MutationRecovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWriteAttempted {
                protection_restored,
            } => write!(
                formatter,
                "no byte write attempted (protection_restored={protection_restored})"
            ),
            Self::Restored => formatter.write_str("original bytes and protection restored"),
            Self::Indeterminate {
                bytes_restored,
                instruction_cache_flushed,
                protection_restored,
            } => write!(
                formatter,
                "indeterminate (bytes_restored={bytes_restored}, cache_flushed={instruction_cache_flushed}, protection_restored={protection_restored})"
            ),
        }
    }
}

#[derive(Debug, Error)]
pub enum LiveAccessError {
    #[error(transparent)]
    InvalidRequest(#[from] AccessRequestError),
    #[error("{operation} failed: {source}")]
    Win32 {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("selected process exited before the operation completed")]
    ProcessExited,
    #[error("selected process handle no longer identifies the requested PID")]
    ProcessIdChanged,
    #[error("selected process creation identity changed")]
    ProcessStartIdentityChanged,
    #[error(
        "selected process creation identity mismatch: expected {expected:#x}, observed {actual:#x}"
    )]
    ProcessStartIdentityMismatch { expected: u64, actual: u64 },
    #[error("Windows returned an invalid zero process creation identity")]
    ZeroProcessStartKey,
    #[error("queried executable path is empty, relative, or over the Windows path bound")]
    InvalidExecutablePath,
    #[error("executable path {path} is not a regular file")]
    ExecutableNotRegular { path: PathBuf },
    #[error("{operation} failed for executable {path}: {source}")]
    ExecutableIo {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("executable changed while its exact identity was being derived")]
    ExecutableChangedDuringIdentity,
    #[error("selected process executable path changed after the exact file handle was retained")]
    ExecutablePathChanged,
    #[error("retained executable file evidence changed after the live binding was created")]
    ExecutableEvidenceChanged,
    #[error("main executable identity mismatch: expected {expected}, observed {actual}")]
    BinaryIdentityMismatch {
        expected: BinaryId,
        actual: BinaryId,
    },
    #[error("main executable has an invalid PE image: {detail}")]
    InvalidPeImage { detail: &'static str },
    #[error("PE header offset or prefix lies outside the main image")]
    PeHeaderOutOfRange,
    #[error("Tool Help returned a main module for another PID")]
    ModuleProcessMismatch,
    #[error("main module has a zero base or zero image size")]
    EmptyMainModule,
    #[error("Tool Help returned an empty, relative, or truncated main-module path")]
    InvalidMainModulePath,
    #[error("Tool Help's main-module path differs from the retained exact executable")]
    MainModulePathMismatch,
    #[error(
        "main-module base differs from provider evidence: expected {expected:#x}, observed {actual:#x}"
    )]
    MainModuleBaseMismatch { expected: u64, actual: u64 },
    #[error("main module range overflows the target address space")]
    MainModuleRangeOverflow,
    #[error("main-module file SizeOfImage {file:#x} differs from Tool Help size {module:#x}")]
    FileModuleSizeMismatch { file: u32, module: u32 },
    #[error("remote PE SizeOfImage {remote:#x} differs from Tool Help size {module:#x}")]
    RemoteModuleSizeMismatch { remote: u32, module: u32 },
    #[error("main module is not one committed MEM_IMAGE allocation rooted at its image base")]
    InvalidMainModuleMapping,
    #[error("main module contains more than {limit} distinct memory regions")]
    MainModuleRegionLimitExceeded { limit: usize },
    #[error("live target binding construction failed: {0}")]
    BindingConstruction(LiveTargetBindingError),
    #[error("caller binding does not exactly match the retained live target")]
    BindingMismatch,
    #[error("RVA translation failed: {0}")]
    RvaRange(#[from] LiveTargetBindingError),
    #[error("address or size does not fit this process architecture")]
    AddressDoesNotFitPointer,
    #[error("live memory read was partial: requested {expected}, received {actual}")]
    PartialRead { expected: usize, actual: usize },
    #[error("live memory write was partial: requested {expected}, wrote {actual}")]
    PartialWrite { expected: usize, actual: usize },
    #[error(
        "Windows returned a partial memory-region record: expected {expected}, received {actual}"
    )]
    PartialMemoryRegionQuery { expected: usize, actual: usize },
    #[error(
        "live bytes no longer match the compare-before-write expectation at RVA {rva:#x} ({size} bytes)"
    )]
    CompareMismatch { rva: u64, size: usize },
    #[error(
        "write span is not wholly inside one committed executable main-image region and one system page"
    )]
    UnsafeWriteRegion,
    #[error("Windows returned an invalid zero system page size")]
    InvalidSystemPageSize,
    #[error("mutation failed while {stage}: {failure}; recovery: {recovery}")]
    MutationFailed {
        stage: MutationStage,
        failure: String,
        recovery: MutationRecovery,
    },
}

#[derive(Debug)]
struct ExactExecutable {
    file: File,
    process_path: PathBuf,
    path: PathBuf,
    file_size: u64,
    size_of_image: u32,
}

#[derive(Debug, Clone, Copy)]
struct MainModule {
    base: u64,
    size_of_image: u32,
}

#[derive(Debug, Clone, Copy)]
struct WritableCodeRegion {
    protection: PAGE_PROTECTION_FLAGS,
}

/// Private operation boundary for one mutation transaction.
///
/// Production uses one instance bound to one owned process handle. Tests use a
/// per-test in-memory instance so faults remain deterministic and cannot leak
/// between concurrent tests or weaken the Win32 validation path.
trait MutationOperations {
    fn ensure_exact_binding(&mut self, expected: &LiveTargetBinding)
    -> Result<(), LiveAccessError>;

    fn read_exact(&mut self, address: u64, size: usize) -> Result<Vec<u8>, LiveAccessError>;

    fn writable_code_region(
        &mut self,
        expected_binding: &LiveTargetBinding,
        address: u64,
        size: usize,
    ) -> Result<WritableCodeRegion, LiveAccessError>;

    fn protect(
        &mut self,
        address: u64,
        size: usize,
        protection: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS, LiveAccessError>;

    fn write_exact(&mut self, address: u64, bytes: &[u8]) -> Result<(), LiveAccessError>;

    fn flush(&mut self, address: u64, size: usize) -> Result<(), LiveAccessError>;

    fn restore(
        &mut self,
        address: u64,
        size: usize,
        protection: PAGE_PROTECTION_FLAGS,
    ) -> Result<(), LiveAccessError>;
}

struct WindowsMutationOperations<'a> {
    process: &'a OwnedHandle,
    retained_binding: &'a LiveTargetBinding,
    executable: &'a ExactExecutable,
}

impl MutationOperations for WindowsMutationOperations<'_> {
    fn ensure_exact_binding(
        &mut self,
        expected: &LiveTargetBinding,
    ) -> Result<(), LiveAccessError> {
        ensure_exact_binding_parts(
            self.process,
            self.retained_binding,
            self.executable,
            expected,
        )
        .map(|_| ())
    }

    fn read_exact(&mut self, address: u64, size: usize) -> Result<Vec<u8>, LiveAccessError> {
        read_raw_exact(self.process, address, size)
    }

    fn writable_code_region(
        &mut self,
        expected_binding: &LiveTargetBinding,
        address: u64,
        size: usize,
    ) -> Result<WritableCodeRegion, LiveAccessError> {
        writable_code_region(self.process, expected_binding, address, size)
    }

    fn protect(
        &mut self,
        address: u64,
        size: usize,
        protection: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS, LiveAccessError> {
        protect_raw(self.process, address, size, protection)
    }

    fn write_exact(&mut self, address: u64, bytes: &[u8]) -> Result<(), LiveAccessError> {
        write_raw_exact(self.process, address, bytes)
    }

    fn flush(&mut self, address: u64, size: usize) -> Result<(), LiveAccessError> {
        flush_raw(self.process, address, size)
    }

    fn restore(
        &mut self,
        address: u64,
        size: usize,
        protection: PAGE_PROTECTION_FLAGS,
    ) -> Result<(), LiveAccessError> {
        restore_raw(self.process, address, size, protection)
    }
}

fn observe_live_target(
    process: &OwnedHandle,
    selected_pid: resymbol_debugger::protocol::ProcessId,
    expected_image_base: MemoryAddress,
    expected_binary_id: &BinaryId,
    executable: &ExactExecutable,
) -> Result<LiveTargetBinding, LiveAccessError> {
    ensure_process_active(process)?;
    // SAFETY: `process` owns a valid process handle for this call's duration.
    let actual_pid = unsafe { GetProcessId(raw_handle(process)) };
    if actual_pid == 0 {
        return Err(last_win32("query selected process identifier"));
    }
    if actual_pid != selected_pid.get() {
        return Err(LiveAccessError::ProcessIdChanged);
    }

    let start_key_before = process_start_key(process)?;
    validate_exact_executable(process, executable)?;

    let module = main_module(selected_pid.get(), &executable.process_path)?;
    if module.base != expected_image_base.get() {
        return Err(LiveAccessError::MainModuleBaseMismatch {
            expected: expected_image_base.get(),
            actual: module.base,
        });
    }
    if executable.size_of_image != module.size_of_image {
        return Err(LiveAccessError::FileModuleSizeMismatch {
            file: executable.size_of_image,
            module: module.size_of_image,
        });
    }
    validate_main_module_mapping(process, module)?;
    let remote_size_of_image = remote_pe_size_of_image(process, module)?;
    if remote_size_of_image != module.size_of_image {
        return Err(LiveAccessError::RemoteModuleSizeMismatch {
            remote: remote_size_of_image,
            module: module.size_of_image,
        });
    }

    ensure_process_active(process)?;
    let start_key_after = process_start_key(process)?;
    if start_key_before != start_key_after {
        return Err(LiveAccessError::ProcessStartIdentityChanged);
    }

    let start_key =
        ProcessStartKey::new(start_key_before).map_err(|_| LiveAccessError::ZeroProcessStartKey)?;
    let process_identity = ProcessIdentity {
        process_id: selected_pid,
        start_key,
        binary_id: expected_binary_id.clone(),
    };
    let binding = LiveTargetBinding::new(
        process_identity,
        expected_binary_id.clone(),
        MemoryAddress::new(module.base),
        module.size_of_image,
    )
    .map_err(LiveAccessError::BindingConstruction)?;
    Ok(binding)
}

fn open_exact_executable(
    process: &OwnedHandle,
    expected_binary_id: &BinaryId,
) -> Result<ExactExecutable, LiveAccessError> {
    ensure_process_active(process)?;
    let start_key_before = process_start_key(process)?;
    let queried_path = query_executable_path(process)?;
    let path = canonical_executable_path(&queried_path)?;
    let mut file = OpenOptions::new()
        .read(true)
        // Successful opening with read-only sharing excludes existing or new
        // writers/deleters for the lifetime of this retained handle.
        .share_mode(FILE_SHARE_READ)
        .open(&path)
        .map_err(|source| LiveAccessError::ExecutableIo {
            operation: "open",
            path: path.clone(),
            source,
        })?;
    let before = file
        .metadata()
        .map_err(|source| LiveAccessError::ExecutableIo {
            operation: "read metadata",
            path: path.clone(),
            source,
        })?;
    if !before.is_file() {
        return Err(LiveAccessError::ExecutableNotRegular { path });
    }
    let size_of_image = file_pe_size_of_image(&file, before.len(), &path)?;
    // Windows' positional `FileExt::seek_read` also leaves the shared file
    // cursor at the end of its read. The PE-header reads above therefore must
    // not determine where the whole-file identity hash begins.
    file.rewind()
        .map_err(|source| LiveAccessError::ExecutableIo {
            operation: "rewind before hash",
            path: path.clone(),
            source,
        })?;
    let (binary_id, hashed_size) =
        BinaryId::digest_reader(BufReader::new(&file)).map_err(|source| {
            LiveAccessError::ExecutableIo {
                operation: "hash",
                path: path.clone(),
                source,
            }
        })?;
    let after = file
        .metadata()
        .map_err(|source| LiveAccessError::ExecutableIo {
            operation: "re-read metadata",
            path: path.clone(),
            source,
        })?;
    if before.len() != hashed_size || before.len() != after.len() || !after.is_file() {
        return Err(LiveAccessError::ExecutableChangedDuringIdentity);
    }
    if &binary_id != expected_binary_id {
        return Err(LiveAccessError::BinaryIdentityMismatch {
            expected: expected_binary_id.clone(),
            actual: binary_id,
        });
    }
    ensure_process_active(process)?;
    if process_start_key(process)? != start_key_before {
        return Err(LiveAccessError::ProcessStartIdentityChanged);
    }

    Ok(ExactExecutable {
        file,
        process_path: queried_path,
        path,
        file_size: before.len(),
        size_of_image,
    })
}

fn validate_exact_executable(
    process: &OwnedHandle,
    executable: &ExactExecutable,
) -> Result<(), LiveAccessError> {
    let queried_path = query_executable_path(process)?;
    if queried_path != executable.process_path {
        return Err(LiveAccessError::ExecutablePathChanged);
    }
    let metadata = executable
        .file
        .metadata()
        .map_err(|source| LiveAccessError::ExecutableIo {
            operation: "refresh retained metadata",
            path: executable.path.clone(),
            source,
        })?;
    if !metadata.is_file() || metadata.len() != executable.file_size {
        return Err(LiveAccessError::ExecutableEvidenceChanged);
    }
    let size_of_image =
        file_pe_size_of_image(&executable.file, executable.file_size, &executable.path)?;
    if size_of_image != executable.size_of_image {
        return Err(LiveAccessError::ExecutableEvidenceChanged);
    }
    Ok(())
}

fn canonical_executable_path(path: &Path) -> Result<PathBuf, LiveAccessError> {
    fs::canonicalize(path).map_err(|source| LiveAccessError::ExecutableIo {
        operation: "canonicalize",
        path: path.to_path_buf(),
        source,
    })
}

fn ensure_process_active(process: &OwnedHandle) -> Result<(), LiveAccessError> {
    // SAFETY: `process` owns a valid synchronizable process handle.
    match unsafe { WaitForSingleObject(raw_handle(process), 0) } {
        WAIT_TIMEOUT => Ok(()),
        WAIT_OBJECT_0 => Err(LiveAccessError::ProcessExited),
        WAIT_FAILED => Err(last_win32("query selected process liveness")),
        _ => Err(LiveAccessError::ProcessExited),
    }
}

fn process_start_key(process: &OwnedHandle) -> Result<u64, LiveAccessError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `process` is valid and all four FILETIME outputs point to
    // initialized writable storage for the call's duration.
    if unsafe {
        GetProcessTimes(
            raw_handle(process),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == FALSE
    {
        return Err(last_win32("query selected process creation time"));
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn query_executable_path(process: &OwnedHandle) -> Result<PathBuf, LiveAccessError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let mut capacity = INITIAL_IMAGE_PATH_CHARS;
    loop {
        let mut buffer = vec![0_u16; capacity];
        let mut characters =
            u32::try_from(buffer.len()).map_err(|_| LiveAccessError::InvalidExecutablePath)?;
        // SAFETY: `process` is valid, `buffer` is writable for `characters`
        // UTF-16 units, and the size pointer remains valid for the call.
        if unsafe {
            QueryFullProcessImageNameW(raw_handle(process), 0, buffer.as_mut_ptr(), &mut characters)
        } != FALSE
        {
            let characters =
                usize::try_from(characters).map_err(|_| LiveAccessError::InvalidExecutablePath)?;
            if characters == 0 || characters > buffer.len() {
                return Err(LiveAccessError::InvalidExecutablePath);
            }
            let path = PathBuf::from(OsString::from_wide(&buffer[..characters]));
            if !path.is_absolute() {
                return Err(LiveAccessError::InvalidExecutablePath);
            }
            return Ok(path);
        }

        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32)
            && capacity < MAX_IMAGE_PATH_CHARS
        {
            capacity = capacity.saturating_mul(2).min(MAX_IMAGE_PATH_CHARS);
            continue;
        }
        return Err(LiveAccessError::Win32 {
            operation: "query selected executable path",
            source: error,
        });
    }
}

fn file_pe_size_of_image(file: &File, file_size: u64, path: &Path) -> Result<u32, LiveAccessError> {
    let mut dos = [0_u8; DOS_HEADER_BYTES];
    seek_read_exact(file, &mut dos, 0, path)?;
    let pe_offset = pe_offset(&dos)?;
    let nt_end = pe_offset
        .checked_add(NT_HEADER_PREFIX_BYTES as u64)
        .ok_or(LiveAccessError::PeHeaderOutOfRange)?;
    if nt_end > file_size {
        return Err(LiveAccessError::PeHeaderOutOfRange);
    }
    let mut nt = [0_u8; NT_HEADER_PREFIX_BYTES];
    seek_read_exact(file, &mut nt, pe_offset, path)?;
    nt_size_of_image(&nt)
}

fn seek_read_exact(
    file: &File,
    mut destination: &mut [u8],
    mut offset: u64,
    path: &Path,
) -> Result<(), LiveAccessError> {
    while !destination.is_empty() {
        let read = file.seek_read(destination, offset).map_err(|source| {
            LiveAccessError::ExecutableIo {
                operation: "read PE header",
                path: path.to_path_buf(),
                source,
            }
        })?;
        if read == 0 {
            return Err(LiveAccessError::PeHeaderOutOfRange);
        }
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| LiveAccessError::PeHeaderOutOfRange)?)
            .ok_or(LiveAccessError::PeHeaderOutOfRange)?;
        destination = &mut destination[read..];
    }
    Ok(())
}

fn pe_offset(dos: &[u8; DOS_HEADER_BYTES]) -> Result<u64, LiveAccessError> {
    if &dos[..2] != IMAGE_DOS_SIGNATURE {
        return Err(LiveAccessError::InvalidPeImage {
            detail: "missing DOS signature",
        });
    }
    Ok(u64::from(u32::from_le_bytes(
        dos[0x3c..0x40]
            .try_into()
            .expect("DOS prefix contains e_lfanew"),
    )))
}

fn nt_size_of_image(nt: &[u8; NT_HEADER_PREFIX_BYTES]) -> Result<u32, LiveAccessError> {
    if &nt[..4] != PE_SIGNATURE_BYTES {
        return Err(LiveAccessError::InvalidPeImage {
            detail: "missing PE signature",
        });
    }
    let optional_size = u16::from_le_bytes(
        nt[20..22]
            .try_into()
            .expect("NT prefix contains optional-header size"),
    );
    if optional_size < MIN_OPTIONAL_HEADER_FOR_SIZE_OF_IMAGE {
        return Err(LiveAccessError::InvalidPeImage {
            detail: "optional header is too short for SizeOfImage",
        });
    }
    let magic = u16::from_le_bytes(
        nt[24..26]
            .try_into()
            .expect("NT prefix contains optional-header magic"),
    );
    if magic != PE32_MAGIC && magic != PE32_PLUS_MAGIC {
        return Err(LiveAccessError::InvalidPeImage {
            detail: "unsupported optional-header magic",
        });
    }
    let size = u32::from_le_bytes(
        nt[80..84]
            .try_into()
            .expect("NT prefix contains SizeOfImage"),
    );
    if size == 0 {
        return Err(LiveAccessError::InvalidPeImage {
            detail: "SizeOfImage is zero",
        });
    }
    Ok(size)
}

fn main_module(process_id: u32, expected_path: &Path) -> Result<MainModule, LiveAccessError> {
    for attempt in 0..MODULE_SNAPSHOT_ATTEMPTS {
        // SAFETY: arguments are scalar snapshot flags and the selected PID;
        // any valid returned handle is immediately transferred to one owner.
        let raw = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id)
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BAD_LENGTH as i32)
                && attempt + 1 < MODULE_SNAPSHOT_ATTEMPTS
            {
                continue;
            }
            return Err(LiveAccessError::Win32 {
                operation: "snapshot selected process modules",
                source: error,
            });
        }
        let snapshot = owned_handle(raw, "own selected process module snapshot")?;
        let mut entry = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..MODULEENTRY32W::default()
        };
        // SAFETY: `snapshot` is a valid module snapshot and `entry.dwSize`
        // describes the writable structure supplied to Win32.
        if unsafe { Module32FirstW(raw_handle(&snapshot), &mut entry) } == FALSE {
            return Err(last_win32("read selected process main module"));
        }
        if entry.th32ProcessID != process_id {
            return Err(LiveAccessError::ModuleProcessMismatch);
        }
        let module_path = module_entry_path(&entry)?;
        if module_path != expected_path {
            return Err(LiveAccessError::MainModulePathMismatch);
        }
        let base = pointer_to_u64(entry.modBaseAddr.cast_const().cast());
        if base == 0 || entry.modBaseSize == 0 {
            return Err(LiveAccessError::EmptyMainModule);
        }
        base.checked_add(u64::from(entry.modBaseSize))
            .ok_or(LiveAccessError::MainModuleRangeOverflow)?;
        return Ok(MainModule {
            base,
            size_of_image: entry.modBaseSize,
        });
    }
    Err(last_win32("snapshot selected process modules"))
}

fn module_entry_path(entry: &MODULEENTRY32W) -> Result<PathBuf, LiveAccessError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let Some(length) = entry.szExePath.iter().position(|character| *character == 0) else {
        return Err(LiveAccessError::InvalidMainModulePath);
    };
    // A terminator only in the final fixed-size slot is indistinguishable from
    // a truncated Tool Help path. Reject that ambiguous edge rather than
    // treating a prefix as exact module evidence.
    if length == 0 || length + 1 == entry.szExePath.len() {
        return Err(LiveAccessError::InvalidMainModulePath);
    }
    let path = PathBuf::from(OsString::from_wide(&entry.szExePath[..length]));
    if !path.is_absolute() {
        return Err(LiveAccessError::InvalidMainModulePath);
    }
    Ok(path)
}

fn validate_main_module_mapping(
    process: &OwnedHandle,
    module: MainModule,
) -> Result<(), LiveAccessError> {
    let module_end = module
        .base
        .checked_add(u64::from(module.size_of_image))
        .ok_or(LiveAccessError::MainModuleRangeOverflow)?;

    let mut cursor = module.base;
    for _ in 0..MAX_MAIN_IMAGE_REGIONS {
        if cursor == module_end {
            return Ok(());
        }
        let information = query_region(process, cursor)?;
        let allocation_base = pointer_to_u64(information.AllocationBase.cast_const());
        let region_base = pointer_to_u64(information.BaseAddress.cast_const());
        cursor = next_main_image_cursor(
            module,
            cursor,
            allocation_base,
            region_base,
            usize_to_u64(information.RegionSize),
            information.State,
            information.Type,
        )?;
    }
    if cursor == module_end {
        Ok(())
    } else {
        Err(LiveAccessError::MainModuleRegionLimitExceeded {
            limit: MAX_MAIN_IMAGE_REGIONS,
        })
    }
}

fn next_main_image_cursor(
    module: MainModule,
    cursor: u64,
    allocation_base: u64,
    region_base: u64,
    region_size: u64,
    state: u32,
    memory_type: u32,
) -> Result<u64, LiveAccessError> {
    let module_end = module
        .base
        .checked_add(u64::from(module.size_of_image))
        .ok_or(LiveAccessError::MainModuleRangeOverflow)?;
    let region_end = region_base
        .checked_add(region_size)
        .ok_or(LiveAccessError::MainModuleRangeOverflow)?;
    if cursor < module.base
        || cursor >= module_end
        || allocation_base != module.base
        || region_base != cursor
        || state != MEM_COMMIT
        || memory_type != MEM_IMAGE
        || region_end <= cursor
        || region_end > module_end
    {
        return Err(LiveAccessError::InvalidMainModuleMapping);
    }
    Ok(region_end)
}

fn remote_pe_size_of_image(
    process: &OwnedHandle,
    module: MainModule,
) -> Result<u32, LiveAccessError> {
    let dos = read_raw_exact(process, module.base, DOS_HEADER_BYTES)?;
    let dos: [u8; DOS_HEADER_BYTES] = dos
        .try_into()
        .expect("exact DOS-header read has fixed length");
    let pe_offset = pe_offset(&dos)?;
    let nt_end = pe_offset
        .checked_add(NT_HEADER_PREFIX_BYTES as u64)
        .ok_or(LiveAccessError::PeHeaderOutOfRange)?;
    if nt_end > u64::from(module.size_of_image) {
        return Err(LiveAccessError::PeHeaderOutOfRange);
    }
    let address = module
        .base
        .checked_add(pe_offset)
        .ok_or(LiveAccessError::PeHeaderOutOfRange)?;
    let nt = read_raw_exact(process, address, NT_HEADER_PREFIX_BYTES)?;
    let nt: [u8; NT_HEADER_PREFIX_BYTES] = nt
        .try_into()
        .expect("exact NT-header read has fixed length");
    nt_size_of_image(&nt)
}

fn writable_code_region(
    process: &OwnedHandle,
    binding: &LiveTargetBinding,
    address: u64,
    size: usize,
) -> Result<WritableCodeRegion, LiveAccessError> {
    let information = query_region(process, address)?;
    let region_base = pointer_to_u64(information.BaseAddress.cast_const());
    let allocation_base = pointer_to_u64(information.AllocationBase.cast_const());
    let region_end = region_base
        .checked_add(usize_to_u64(information.RegionSize))
        .ok_or(LiveAccessError::UnsafeWriteRegion)?;
    let write_end = address
        .checked_add(usize_to_u64(size))
        .ok_or(LiveAccessError::UnsafeWriteRegion)?;
    let page_size = system_page_size()?;
    let protection_base = information.Protect & PROTECTION_BASE_MASK;
    let executable = matches!(
        protection_base,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    );
    if information.State != MEM_COMMIT
        || information.Type != MEM_IMAGE
        || allocation_base != binding.actual_image_base().get()
        || address < region_base
        || write_end > region_end
        || information.Protect & PAGE_GUARD != 0
        || protection_base == PAGE_NOACCESS
        || !executable
        || !span_fits_single_page(address, size, page_size)
    {
        return Err(LiveAccessError::UnsafeWriteRegion);
    }
    Ok(WritableCodeRegion {
        protection: information.Protect,
    })
}

fn span_fits_single_page(address: u64, size: usize, page_size: u64) -> bool {
    if size == 0 || page_size == 0 {
        return false;
    }
    let Some(end) = address.checked_add(usize_to_u64(size)) else {
        return false;
    };
    let Some(last_address) = end.checked_sub(1) else {
        return false;
    };
    address / page_size == last_address / page_size
}

fn system_page_size() -> Result<u64, LiveAccessError> {
    let mut information = SYSTEM_INFO::default();
    // SAFETY: `information` is writable at the exact size expected by Win32.
    unsafe { GetSystemInfo(&mut information) };
    let page_size = u64::from(information.dwPageSize);
    if page_size == 0 {
        Err(LiveAccessError::InvalidSystemPageSize)
    } else {
        Ok(page_size)
    }
}

fn query_region(
    process: &OwnedHandle,
    address: u64,
) -> Result<MEMORY_BASIC_INFORMATION, LiveAccessError> {
    let pointer = address_to_pointer(address)?;
    let mut information = MEMORY_BASIC_INFORMATION::default();
    // SAFETY: the process handle is valid, `pointer` is only interpreted in
    // that remote address space, and `information` is writable at its size.
    let returned = unsafe {
        VirtualQueryEx(
            raw_handle(process),
            pointer,
            &mut information,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if returned == 0 {
        return Err(last_win32("query selected process memory region"));
    }
    if returned != size_of::<MEMORY_BASIC_INFORMATION>() {
        return Err(LiveAccessError::PartialMemoryRegionQuery {
            expected: size_of::<MEMORY_BASIC_INFORMATION>(),
            actual: returned,
        });
    }
    Ok(information)
}

fn read_raw_exact(
    process: &OwnedHandle,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, LiveAccessError> {
    let pointer = address_to_pointer(address)?;
    let mut bytes = vec![0_u8; size];
    let mut read = 0_usize;
    // SAFETY: `bytes` owns a writable buffer of exactly `size` bytes and the
    // remote pointer is never dereferenced in this process.
    let result = unsafe {
        ReadProcessMemory(
            raw_handle(process),
            pointer,
            bytes.as_mut_ptr().cast(),
            size,
            &mut read,
        )
    };
    if result == FALSE {
        if read != 0 {
            return Err(LiveAccessError::PartialRead {
                expected: size,
                actual: read,
            });
        }
        return Err(last_win32("read selected process memory"));
    }
    if read != size {
        return Err(LiveAccessError::PartialRead {
            expected: size,
            actual: read,
        });
    }
    Ok(bytes)
}

fn write_raw_exact(
    process: &OwnedHandle,
    address: u64,
    bytes: &[u8],
) -> Result<(), LiveAccessError> {
    let pointer = address_to_pointer(address)?;
    let mut written = 0_usize;
    // SAFETY: `bytes` remains alive and readable for the complete call; the
    // remote pointer is interpreted only by Win32 for the owned process.
    let result = unsafe {
        WriteProcessMemory(
            raw_handle(process),
            pointer,
            bytes.as_ptr().cast(),
            bytes.len(),
            &mut written,
        )
    };
    if result == FALSE {
        if written != 0 {
            return Err(LiveAccessError::PartialWrite {
                expected: bytes.len(),
                actual: written,
            });
        }
        return Err(last_win32("write selected process memory"));
    }
    if written != bytes.len() {
        return Err(LiveAccessError::PartialWrite {
            expected: bytes.len(),
            actual: written,
        });
    }
    Ok(())
}

fn protect_raw(
    process: &OwnedHandle,
    address: u64,
    size: usize,
    protection: PAGE_PROTECTION_FLAGS,
) -> Result<PAGE_PROTECTION_FLAGS, LiveAccessError> {
    let pointer = address_to_pointer(address)?;
    let mut old = 0;
    // SAFETY: the process handle is valid, the nonempty span was validated by
    // the caller, and `old` is writable for the returned protection value.
    if unsafe { VirtualProtectEx(raw_handle(process), pointer, size, protection, &mut old) }
        == FALSE
    {
        return Err(last_win32("change selected process page protection"));
    }
    Ok(old)
}

fn restore_raw(
    process: &OwnedHandle,
    address: u64,
    size: usize,
    protection: PAGE_PROTECTION_FLAGS,
) -> Result<(), LiveAccessError> {
    protect_raw(process, address, size, protection).map(|_| ())
}

fn flush_raw(process: &OwnedHandle, address: u64, size: usize) -> Result<(), LiveAccessError> {
    let pointer = address_to_pointer(address)?;
    // SAFETY: the handle is valid and the address/size pair describes the
    // remote code span that was just written.
    if unsafe { FlushInstructionCache(raw_handle(process), pointer, size) } == FALSE {
        Err(last_win32("flush selected process instruction cache"))
    } else {
        Ok(())
    }
}

fn compare_before_write_transaction<O: MutationOperations>(
    operations: &mut O,
    expected_binding: &LiveTargetBinding,
    rva: u64,
    address: u64,
    expected: &[u8],
    replacement: &[u8],
) -> Result<(), LiveAccessError> {
    let actual = operations.read_exact(address, expected.len())?;
    if actual != expected {
        return Err(LiveAccessError::CompareMismatch {
            rva,
            size: expected.len(),
        });
    }

    // Close the potentially expensive identity-to-mutation window as much as
    // this non-suspending foundation can. A provider must still stop the
    // process before granting authority to call this method.
    operations.ensure_exact_binding(expected_binding)?;
    let region = operations.writable_code_region(expected_binding, address, expected.len())?;
    let original_protection =
        operations.protect(address, expected.len(), PAGE_EXECUTE_READWRITE)?;
    if original_protection != region.protection {
        // Protection changed, but no byte write was attempted. Do not run byte
        // recovery with a stale compare buffer; only undo our protection
        // change after revalidating the exact target.
        let protection_restored = restore_prewrite_protection(
            operations,
            expected_binding,
            address,
            expected.len(),
            original_protection,
        );
        return Err(LiveAccessError::MutationFailed {
            stage: MutationStage::ProtectionRace,
            failure: format!(
                "queried protection {:#x} changed to {original_protection:#x}",
                region.protection
            ),
            recovery: MutationRecovery::NoWriteAttempted {
                protection_restored,
            },
        });
    }

    match operations.read_exact(address, expected.len()) {
        Ok(actual) if actual == expected => {}
        Ok(_) => {
            let protection_restored = restore_prewrite_protection(
                operations,
                expected_binding,
                address,
                expected.len(),
                original_protection,
            );
            return Err(LiveAccessError::MutationFailed {
                stage: MutationStage::RevalidateExpectedBytes,
                failure: "live bytes changed after the initial comparison".to_owned(),
                recovery: MutationRecovery::NoWriteAttempted {
                    protection_restored,
                },
            });
        }
        Err(error) => {
            let protection_restored = restore_prewrite_protection(
                operations,
                expected_binding,
                address,
                expected.len(),
                original_protection,
            );
            return Err(LiveAccessError::MutationFailed {
                stage: MutationStage::RevalidateExpectedBytes,
                failure: error.to_string(),
                recovery: MutationRecovery::NoWriteAttempted {
                    protection_restored,
                },
            });
        }
    }

    if let Err(error) = operations.write_exact(address, replacement) {
        let recovery = recover_original_bytes(
            operations,
            expected_binding,
            address,
            expected,
            original_protection,
            true,
        );
        return Err(mutation_failure(
            MutationStage::WriteReplacement,
            error,
            recovery,
        ));
    }
    if let Err(error) = operations.flush(address, replacement.len()) {
        let recovery = recover_original_bytes(
            operations,
            expected_binding,
            address,
            expected,
            original_protection,
            true,
        );
        return Err(mutation_failure(
            MutationStage::FlushReplacement,
            error,
            recovery,
        ));
    }
    if let Err(error) = operations.restore(address, replacement.len(), original_protection) {
        let recovery = recover_original_bytes(
            operations,
            expected_binding,
            address,
            expected,
            original_protection,
            true,
        );
        return Err(mutation_failure(
            MutationStage::RestoreProtection,
            error,
            recovery,
        ));
    }

    match operations.read_exact(address, replacement.len()) {
        Ok(readback) if readback == replacement => {}
        Ok(_) => {
            let recovery = recover_original_bytes(
                operations,
                expected_binding,
                address,
                expected,
                original_protection,
                false,
            );
            return Err(LiveAccessError::MutationFailed {
                stage: MutationStage::VerifyReplacement,
                failure: "replacement readback did not match".to_owned(),
                recovery,
            });
        }
        Err(error) => {
            let recovery = recover_original_bytes(
                operations,
                expected_binding,
                address,
                expected,
                original_protection,
                false,
            );
            return Err(mutation_failure(
                MutationStage::VerifyReplacement,
                error,
                recovery,
            ));
        }
    }

    if let Err(error) = operations.ensure_exact_binding(expected_binding) {
        let recovery = recover_original_bytes(
            operations,
            expected_binding,
            address,
            expected,
            original_protection,
            false,
        );
        return Err(mutation_failure(
            MutationStage::ValidateFinalBinding,
            error,
            recovery,
        ));
    }

    Ok(())
}

fn restore_prewrite_protection<O: MutationOperations>(
    operations: &mut O,
    expected_binding: &LiveTargetBinding,
    address: u64,
    size: usize,
    original_protection: PAGE_PROTECTION_FLAGS,
) -> bool {
    if operations.ensure_exact_binding(expected_binding).is_err() {
        return false;
    }
    let Ok(region) = operations.writable_code_region(expected_binding, address, size) else {
        return false;
    };
    if region.protection != PAGE_EXECUTE_READWRITE {
        return false;
    }
    if operations
        .restore(address, size, original_protection)
        .is_err()
    {
        return false;
    }
    operations.ensure_exact_binding(expected_binding).is_ok()
        && operations
            .writable_code_region(expected_binding, address, size)
            .is_ok_and(|region| region.protection == original_protection)
}

fn recover_original_bytes<O: MutationOperations>(
    operations: &mut O,
    expected_binding: &LiveTargetBinding,
    address: u64,
    expected: &[u8],
    original_protection: PAGE_PROTECTION_FLAGS,
    protection_may_be_changed: bool,
) -> MutationRecovery {
    if operations.ensure_exact_binding(expected_binding).is_err() {
        return indeterminate_recovery();
    }
    let Ok(region) = operations.writable_code_region(expected_binding, address, expected.len())
    else {
        return indeterminate_recovery();
    };
    let protection_is_changed = if protection_may_be_changed {
        if region.protection == PAGE_EXECUTE_READWRITE {
            true
        } else if region.protection == original_protection {
            false
        } else {
            return indeterminate_recovery();
        }
    } else if region.protection == original_protection {
        false
    } else {
        return indeterminate_recovery();
    };

    recover_original_bytes_checked(
        operations,
        expected_binding,
        address,
        expected,
        original_protection,
        protection_is_changed,
    )
}

fn recover_original_bytes_checked<O: MutationOperations>(
    operations: &mut O,
    expected_binding: &LiveTargetBinding,
    address: u64,
    expected: &[u8],
    original_protection: PAGE_PROTECTION_FLAGS,
    protection_is_changed: bool,
) -> MutationRecovery {
    let mut writable = protection_is_changed;
    if !writable {
        match operations.protect(address, expected.len(), PAGE_EXECUTE_READWRITE) {
            Ok(observed) if observed == original_protection => writable = true,
            Ok(observed) => {
                let _ = operations.restore(address, expected.len(), observed);
                return indeterminate_recovery();
            }
            Err(_) => {
                return indeterminate_recovery();
            }
        }
    }

    // Recheck both process identity and allocation immediately before rollback.
    // If either changed, do not write, flush, or adjust protection on a
    // replacement mapping.
    if !writable
        || operations.ensure_exact_binding(expected_binding).is_err()
        || !operations
            .writable_code_region(expected_binding, address, expected.len())
            .is_ok_and(|region| region.protection == PAGE_EXECUTE_READWRITE)
    {
        return indeterminate_recovery();
    }

    let wrote = operations.write_exact(address, expected).is_ok();
    let flushed = wrote
        && operations.ensure_exact_binding(expected_binding).is_ok()
        && operations
            .writable_code_region(expected_binding, address, expected.len())
            .is_ok_and(|region| region.protection == PAGE_EXECUTE_READWRITE)
        && operations.flush(address, expected.len()).is_ok();
    let protection_restored = operations.ensure_exact_binding(expected_binding).is_ok()
        && operations
            .writable_code_region(expected_binding, address, expected.len())
            .is_ok_and(|region| region.protection == PAGE_EXECUTE_READWRITE)
        && operations
            .restore(address, expected.len(), original_protection)
            .is_ok()
        && operations.ensure_exact_binding(expected_binding).is_ok()
        && operations
            .writable_code_region(expected_binding, address, expected.len())
            .is_ok_and(|region| region.protection == original_protection);
    let bytes_restored = wrote
        && operations.ensure_exact_binding(expected_binding).is_ok()
        && operations
            .writable_code_region(expected_binding, address, expected.len())
            .is_ok()
        && operations
            .read_exact(address, expected.len())
            .is_ok_and(|bytes| bytes == expected);
    if bytes_restored && flushed && protection_restored {
        MutationRecovery::Restored
    } else {
        MutationRecovery::Indeterminate {
            bytes_restored,
            instruction_cache_flushed: flushed,
            protection_restored,
        }
    }
}

const fn indeterminate_recovery() -> MutationRecovery {
    MutationRecovery::Indeterminate {
        bytes_restored: false,
        instruction_cache_flushed: false,
        protection_restored: false,
    }
}

fn mutation_failure(
    stage: MutationStage,
    error: LiveAccessError,
    recovery: MutationRecovery,
) -> LiveAccessError {
    LiveAccessError::MutationFailed {
        stage,
        failure: error.to_string(),
        recovery,
    }
}

fn pointer_to_u64(pointer: *const c_void) -> u64 {
    pointer as usize as u64
}

fn address_to_pointer(address: u64) -> Result<*const c_void, LiveAccessError> {
    let address =
        usize::try_from(address).map_err(|_| LiveAccessError::AddressDoesNotFitPointer)?;
    Ok(address as *const c_void)
}

fn usize_to_u64(value: usize) -> u64 {
    value as u64
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
}

fn owned_handle(handle: HANDLE, operation: &'static str) -> Result<OwnedHandle, LiveAccessError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(last_win32(operation))
    } else {
        // SAFETY: the checked non-null, non-pseudo handle is newly returned by
        // an ownership-transferring Win32 API and has no other Rust owner.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }
}

fn last_win32(operation: &'static str) -> LiveAccessError {
    LiveAccessError::Win32 {
        operation,
        source: io::Error::last_os_error(),
    }
}

#[cfg(test)]
mod tests {
    use std::{io, os::windows::ffi::OsStrExt as _, path::Path};

    use resymbol_core::BinaryId;
    use resymbol_debugger::protocol::{
        LiveTargetBinding, MemoryAddress, ProcessId, ProcessIdentity, ProcessStartKey,
    };

    use windows_sys::Win32::System::{
        Diagnostics::ToolHelp::MODULEENTRY32W,
        Memory::{
            MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_PROTECTION_FLAGS,
        },
    };

    use super::{
        DOS_HEADER_BYTES, IMAGE_DOS_SIGNATURE, LiveAccessError, MainModule, MutationOperations,
        MutationRecovery, MutationStage, NT_HEADER_PREFIX_BYTES, PE_SIGNATURE_BYTES,
        PE32_PLUS_MAGIC, WritableCodeRegion, compare_before_write_transaction, module_entry_path,
        next_main_image_cursor, nt_size_of_image, pe_offset, span_fits_single_page,
    };

    fn valid_headers() -> ([u8; DOS_HEADER_BYTES], [u8; NT_HEADER_PREFIX_BYTES]) {
        let mut dos = [0_u8; DOS_HEADER_BYTES];
        dos[..2].copy_from_slice(IMAGE_DOS_SIGNATURE);
        dos[0x3c..0x40].copy_from_slice(&0x100_u32.to_le_bytes());

        let mut nt = [0_u8; NT_HEADER_PREFIX_BYTES];
        nt[..4].copy_from_slice(PE_SIGNATURE_BYTES);
        nt[20..22].copy_from_slice(&0xf0_u16.to_le_bytes());
        nt[24..26].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        nt[80..84].copy_from_slice(&0x7000_u32.to_le_bytes());
        (dos, nt)
    }

    const TEST_ADDRESS: u64 = 0x1_1000;
    const TEST_RVA: u64 = 0x1_000;
    const ORIGINAL_BYTES: &[u8; 8] = b"RSYMLIVE";
    const REPLACEMENT_BYTES: &[u8; 8] = b"R5YML1VE";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RecordedMutationOperation {
        EnsureBinding,
        Read,
        QueryRegion,
        Protect,
        Write,
        Flush,
        Restore,
    }

    struct FaultMutationOperations {
        binding: LiveTargetBinding,
        bytes: Vec<u8>,
        protection: PAGE_PROTECTION_FLAGS,
        retained_allocation: u64,
        current_allocation: u64,
        identity_valid: bool,
        operations: Vec<RecordedMutationOperation>,
        binding_calls: usize,
        protect_calls: usize,
        write_calls: usize,
        flush_calls: usize,
        restore_calls: usize,
        fail_binding_calls: Vec<usize>,
        fail_write_before_calls: Vec<usize>,
        fail_write_after_calls: Vec<usize>,
        fail_flush_calls: Vec<usize>,
        fail_restore_calls: Vec<usize>,
        invalidate_identity_on_binding_failure: bool,
        replace_allocation_on_flush_failure: bool,
        protect_observed_once: Option<PAGE_PROTECTION_FLAGS>,
        bytes_after_first_protect: Option<Vec<u8>>,
        bytes_after_first_flush: Option<Vec<u8>>,
    }

    impl FaultMutationOperations {
        fn new() -> Self {
            Self {
                binding: test_binding(),
                bytes: ORIGINAL_BYTES.to_vec(),
                protection: PAGE_EXECUTE_READ,
                retained_allocation: 1,
                current_allocation: 1,
                identity_valid: true,
                operations: Vec::new(),
                binding_calls: 0,
                protect_calls: 0,
                write_calls: 0,
                flush_calls: 0,
                restore_calls: 0,
                fail_binding_calls: Vec::new(),
                fail_write_before_calls: Vec::new(),
                fail_write_after_calls: Vec::new(),
                fail_flush_calls: Vec::new(),
                fail_restore_calls: Vec::new(),
                invalidate_identity_on_binding_failure: false,
                replace_allocation_on_flush_failure: false,
                protect_observed_once: None,
                bytes_after_first_protect: None,
                bytes_after_first_flush: None,
            }
        }

        fn count(&self, operation: RecordedMutationOperation) -> usize {
            self.operations
                .iter()
                .filter(|recorded| **recorded == operation)
                .count()
        }
    }

    impl MutationOperations for FaultMutationOperations {
        fn ensure_exact_binding(
            &mut self,
            expected: &LiveTargetBinding,
        ) -> Result<(), LiveAccessError> {
            self.operations
                .push(RecordedMutationOperation::EnsureBinding);
            self.binding_calls += 1;
            let injected = self.fail_binding_calls.contains(&self.binding_calls);
            if injected && self.invalidate_identity_on_binding_failure {
                self.identity_valid = false;
            }
            if injected
                || !self.identity_valid
                || self.current_allocation != self.retained_allocation
                || expected != &self.binding
            {
                Err(LiveAccessError::BindingMismatch)
            } else {
                Ok(())
            }
        }

        fn read_exact(&mut self, address: u64, size: usize) -> Result<Vec<u8>, LiveAccessError> {
            self.operations.push(RecordedMutationOperation::Read);
            assert_eq!(address, TEST_ADDRESS);
            assert_eq!(size, self.bytes.len());
            Ok(self.bytes.clone())
        }

        fn writable_code_region(
            &mut self,
            expected_binding: &LiveTargetBinding,
            address: u64,
            size: usize,
        ) -> Result<WritableCodeRegion, LiveAccessError> {
            self.operations.push(RecordedMutationOperation::QueryRegion);
            assert_eq!(address, TEST_ADDRESS);
            assert_eq!(size, self.bytes.len());
            if !self.identity_valid
                || self.current_allocation != self.retained_allocation
                || expected_binding != &self.binding
            {
                return Err(LiveAccessError::UnsafeWriteRegion);
            }
            Ok(WritableCodeRegion {
                protection: self.protection,
            })
        }

        fn protect(
            &mut self,
            address: u64,
            size: usize,
            protection: PAGE_PROTECTION_FLAGS,
        ) -> Result<PAGE_PROTECTION_FLAGS, LiveAccessError> {
            self.operations.push(RecordedMutationOperation::Protect);
            self.protect_calls += 1;
            assert_eq!(address, TEST_ADDRESS);
            assert_eq!(size, self.bytes.len());
            let observed = self.protect_observed_once.take().unwrap_or(self.protection);
            self.protection = protection;
            if self.protect_calls == 1 {
                if let Some(bytes) = self.bytes_after_first_protect.take() {
                    self.bytes = bytes;
                }
            }
            Ok(observed)
        }

        fn write_exact(&mut self, address: u64, bytes: &[u8]) -> Result<(), LiveAccessError> {
            self.operations.push(RecordedMutationOperation::Write);
            self.write_calls += 1;
            assert_eq!(address, TEST_ADDRESS);
            assert_eq!(bytes.len(), self.bytes.len());
            if self.fail_write_before_calls.contains(&self.write_calls) {
                return Err(injected_error("write exact bytes"));
            }
            self.bytes.copy_from_slice(bytes);
            if self.fail_write_after_calls.contains(&self.write_calls) {
                Err(injected_error("write exact bytes after side effect"))
            } else {
                Ok(())
            }
        }

        fn flush(&mut self, address: u64, size: usize) -> Result<(), LiveAccessError> {
            self.operations.push(RecordedMutationOperation::Flush);
            self.flush_calls += 1;
            assert_eq!(address, TEST_ADDRESS);
            assert_eq!(size, self.bytes.len());
            if self.fail_flush_calls.contains(&self.flush_calls) {
                if self.replace_allocation_on_flush_failure {
                    self.current_allocation += 1;
                }
                Err(injected_error("flush exact bytes"))
            } else {
                if self.flush_calls == 1 {
                    if let Some(bytes) = self.bytes_after_first_flush.take() {
                        self.bytes = bytes;
                    }
                }
                Ok(())
            }
        }

        fn restore(
            &mut self,
            address: u64,
            size: usize,
            protection: PAGE_PROTECTION_FLAGS,
        ) -> Result<(), LiveAccessError> {
            self.operations.push(RecordedMutationOperation::Restore);
            self.restore_calls += 1;
            assert_eq!(address, TEST_ADDRESS);
            assert_eq!(size, self.bytes.len());
            if self.fail_restore_calls.contains(&self.restore_calls) {
                return Err(injected_error("restore exact protection"));
            }
            self.protection = protection;
            Ok(())
        }
    }

    fn test_binding() -> LiveTargetBinding {
        let binary_id = BinaryId::digest(b"fault-injection-live-target");
        LiveTargetBinding::new(
            ProcessIdentity {
                process_id: ProcessId::new(7).expect("nonzero test PID"),
                start_key: ProcessStartKey::new(11).expect("nonzero test start key"),
                binary_id: binary_id.clone(),
            },
            binary_id,
            MemoryAddress::new(TEST_ADDRESS - TEST_RVA),
            0x4_000,
        )
        .expect("valid deterministic live binding")
    }

    fn injected_error(operation: &'static str) -> LiveAccessError {
        LiveAccessError::Win32 {
            operation,
            source: io::Error::other("deterministic injected failure"),
        }
    }

    fn run_fault_transaction(
        operations: &mut FaultMutationOperations,
    ) -> Result<(), LiveAccessError> {
        let binding = operations.binding.clone();
        compare_before_write_transaction(
            operations,
            &binding,
            TEST_RVA,
            TEST_ADDRESS,
            ORIGINAL_BYTES,
            REPLACEMENT_BYTES,
        )
    }

    fn mutation_failure_parts(
        result: Result<(), LiveAccessError>,
    ) -> (MutationStage, MutationRecovery) {
        match result {
            Err(LiveAccessError::MutationFailed {
                stage, recovery, ..
            }) => (stage, recovery),
            other => panic!("expected mutation failure, received {other:?}"),
        }
    }

    #[test]
    fn successful_transaction_preserves_exact_operation_order() {
        let mut operations = FaultMutationOperations::new();

        run_fault_transaction(&mut operations).expect("deterministic mutation succeeds");

        assert_eq!(
            operations.operations,
            [
                RecordedMutationOperation::Read,
                RecordedMutationOperation::EnsureBinding,
                RecordedMutationOperation::QueryRegion,
                RecordedMutationOperation::Protect,
                RecordedMutationOperation::Read,
                RecordedMutationOperation::Write,
                RecordedMutationOperation::Flush,
                RecordedMutationOperation::Restore,
                RecordedMutationOperation::Read,
                RecordedMutationOperation::EnsureBinding,
            ]
        );
        assert_eq!(operations.bytes, REPLACEMENT_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn protection_race_restores_only_protection_without_attempting_a_byte_write() {
        let mut operations = FaultMutationOperations::new();
        operations.protect_observed_once = Some(PAGE_EXECUTE);

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::ProtectionRace);
        assert_eq!(
            recovery,
            MutationRecovery::NoWriteAttempted {
                protection_restored: true,
            }
        );
        assert_eq!(operations.count(RecordedMutationOperation::Write), 0);
        assert_eq!(operations.bytes, ORIGINAL_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE);
    }

    #[test]
    fn unverified_prewrite_protection_restore_makes_no_success_claim() {
        let mut operations = FaultMutationOperations::new();
        operations.protect_observed_once = Some(PAGE_EXECUTE);
        operations.fail_binding_calls.push(3);

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::ProtectionRace);
        assert_eq!(
            recovery,
            MutationRecovery::NoWriteAttempted {
                protection_restored: false,
            }
        );
        assert_eq!(operations.count(RecordedMutationOperation::Write), 0);
        assert_eq!(operations.bytes, ORIGINAL_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE);
    }

    #[test]
    fn post_protect_compare_mismatch_never_overwrites_concurrent_bytes() {
        let mut operations = FaultMutationOperations::new();
        let concurrent = b"CONCURNT".to_vec();
        operations.bytes_after_first_protect = Some(concurrent.clone());

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::RevalidateExpectedBytes);
        assert_eq!(
            recovery,
            MutationRecovery::NoWriteAttempted {
                protection_restored: true,
            }
        );
        assert_eq!(operations.count(RecordedMutationOperation::Write), 0);
        assert_eq!(operations.bytes, concurrent);
        assert_eq!(operations.protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn write_failure_after_a_side_effect_reports_complete_recovery() {
        let mut operations = FaultMutationOperations::new();
        operations.fail_write_after_calls.push(1);

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::WriteReplacement);
        assert_eq!(recovery, MutationRecovery::Restored);
        assert_eq!(operations.count(RecordedMutationOperation::Write), 2);
        assert_eq!(operations.bytes, ORIGINAL_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn replacement_flush_failure_reports_complete_recovery() {
        let mut operations = FaultMutationOperations::new();
        operations.fail_flush_calls.push(1);

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::FlushReplacement);
        assert_eq!(recovery, MutationRecovery::Restored);
        assert_eq!(operations.bytes, ORIGINAL_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn replacement_protection_restore_failure_reports_complete_recovery() {
        let mut operations = FaultMutationOperations::new();
        operations.fail_restore_calls.push(1);

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::RestoreProtection);
        assert_eq!(recovery, MutationRecovery::Restored);
        assert_eq!(operations.bytes, ORIGINAL_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn replacement_readback_mismatch_reports_complete_recovery() {
        let mut operations = FaultMutationOperations::new();
        operations.bytes_after_first_flush = Some(b"CORRUPTD".to_vec());

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::VerifyReplacement);
        assert_eq!(recovery, MutationRecovery::Restored);
        assert_eq!(operations.bytes, ORIGINAL_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn transient_final_binding_failure_reports_complete_recovery() {
        let mut operations = FaultMutationOperations::new();
        operations.fail_binding_calls.push(2);

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::ValidateFinalBinding);
        assert_eq!(recovery, MutationRecovery::Restored);
        assert_eq!(operations.bytes, ORIGINAL_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn failed_recovery_write_reports_only_restored_protection() {
        let mut operations = FaultMutationOperations::new();
        operations.fail_flush_calls.push(1);
        operations.fail_write_before_calls.push(2);

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::FlushReplacement);
        assert_eq!(
            recovery,
            MutationRecovery::Indeterminate {
                bytes_restored: false,
                instruction_cache_flushed: false,
                protection_restored: true,
            }
        );
        assert_eq!(operations.bytes, REPLACEMENT_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn failed_recovery_flush_reports_verified_bytes_and_protection() {
        let mut operations = FaultMutationOperations::new();
        operations.fail_flush_calls.extend([1, 2]);

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::FlushReplacement);
        assert_eq!(
            recovery,
            MutationRecovery::Indeterminate {
                bytes_restored: true,
                instruction_cache_flushed: false,
                protection_restored: true,
            }
        );
        assert_eq!(operations.bytes, ORIGINAL_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READ);
    }

    #[test]
    fn failed_recovery_restore_reports_verified_bytes_and_cache_flush() {
        let mut operations = FaultMutationOperations::new();
        operations.fail_flush_calls.push(1);
        operations.fail_restore_calls.push(1);

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::FlushReplacement);
        assert_eq!(
            recovery,
            MutationRecovery::Indeterminate {
                bytes_restored: true,
                instruction_cache_flushed: true,
                protection_restored: false,
            }
        );
        assert_eq!(operations.bytes, ORIGINAL_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READWRITE);
    }

    #[test]
    fn stale_identity_after_final_validation_failure_prevents_rollback_write() {
        let mut operations = FaultMutationOperations::new();
        operations.fail_binding_calls.push(2);
        operations.invalidate_identity_on_binding_failure = true;

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::ValidateFinalBinding);
        assert_eq!(
            recovery,
            MutationRecovery::Indeterminate {
                bytes_restored: false,
                instruction_cache_flushed: false,
                protection_restored: false,
            }
        );
        assert_eq!(operations.count(RecordedMutationOperation::Write), 1);
        assert_eq!(operations.bytes, REPLACEMENT_BYTES);
    }

    #[test]
    fn recovery_never_touches_a_replacement_allocation() {
        let mut operations = FaultMutationOperations::new();
        operations.fail_flush_calls.push(1);
        operations.replace_allocation_on_flush_failure = true;

        let (stage, recovery) = mutation_failure_parts(run_fault_transaction(&mut operations));

        assert_eq!(stage, MutationStage::FlushReplacement);
        assert_eq!(
            recovery,
            MutationRecovery::Indeterminate {
                bytes_restored: false,
                instruction_cache_flushed: false,
                protection_restored: false,
            }
        );
        assert_ne!(
            operations.current_allocation,
            operations.retained_allocation
        );
        assert_eq!(operations.count(RecordedMutationOperation::Write), 1);
        assert_eq!(operations.count(RecordedMutationOperation::Restore), 0);
        assert_eq!(operations.bytes, REPLACEMENT_BYTES);
        assert_eq!(operations.protection, PAGE_EXECUTE_READWRITE);
    }

    #[test]
    fn parses_bounded_pe_identity_fields() {
        let (dos, nt) = valid_headers();
        assert_eq!(pe_offset(&dos).expect("valid DOS header"), 0x100);
        assert_eq!(
            nt_size_of_image(&nt).expect("valid NT header prefix"),
            0x7000
        );
    }

    #[test]
    fn rejects_malformed_or_empty_pe_identity_fields() {
        let (mut dos, mut nt) = valid_headers();
        dos[0] = 0;
        assert!(matches!(
            pe_offset(&dos),
            Err(LiveAccessError::InvalidPeImage { .. })
        ));

        nt[0] = 0;
        assert!(matches!(
            nt_size_of_image(&nt),
            Err(LiveAccessError::InvalidPeImage { .. })
        ));
        let (_, mut nt) = valid_headers();
        nt[80..84].fill(0);
        assert!(matches!(
            nt_size_of_image(&nt),
            Err(LiveAccessError::InvalidPeImage { .. })
        ));
    }

    #[test]
    fn module_entry_path_requires_unambiguous_absolute_utf16() {
        let absolute = Path::new(r"C:\Program Files\ReSymbol\fixture.exe");
        let encoded: Vec<u16> = absolute.as_os_str().encode_wide().collect();
        let mut entry = MODULEENTRY32W::default();
        assert!(encoded.len() + 1 < entry.szExePath.len());
        entry.szExePath[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(
            module_entry_path(&entry).expect("absolute terminated module path"),
            absolute.to_path_buf()
        );

        let mut empty = MODULEENTRY32W::default();
        assert!(matches!(
            module_entry_path(&empty),
            Err(LiveAccessError::InvalidMainModulePath)
        ));

        let relative = Path::new("fixture.exe");
        let encoded: Vec<u16> = relative.as_os_str().encode_wide().collect();
        empty.szExePath[..encoded.len()].copy_from_slice(&encoded);
        assert!(matches!(
            module_entry_path(&empty),
            Err(LiveAccessError::InvalidMainModulePath)
        ));

        let mut unterminated = MODULEENTRY32W::default();
        unterminated.szExePath.fill(u16::from(b'x'));
        assert!(matches!(
            module_entry_path(&unterminated),
            Err(LiveAccessError::InvalidMainModulePath)
        ));

        let mut ambiguous = MODULEENTRY32W::default();
        let last = ambiguous.szExePath.len() - 1;
        ambiguous.szExePath[..last].fill(u16::from(b'x'));
        ambiguous.szExePath[..3].copy_from_slice(&[
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
        ]);
        assert!(matches!(
            module_entry_path(&ambiguous),
            Err(LiveAccessError::InvalidMainModulePath)
        ));
    }

    #[test]
    fn complete_main_image_walk_rejects_gaps_aliases_and_overshoot() {
        let module = MainModule {
            base: 0x1_0000,
            size_of_image: 0x3_000,
        };
        let second = next_main_image_cursor(
            module,
            module.base,
            module.base,
            module.base,
            0x1_000,
            MEM_COMMIT,
            MEM_IMAGE,
        )
        .expect("first exact image region");
        assert_eq!(second, 0x1_1000);
        assert_eq!(
            next_main_image_cursor(
                module,
                second,
                module.base,
                second,
                0x2_000,
                MEM_COMMIT,
                MEM_IMAGE,
            )
            .expect("second exact image region"),
            0x1_3000
        );

        let invalid = [
            (module.base + 1, module.base, 0x1_000, MEM_COMMIT, MEM_IMAGE),
            (module.base, module.base + 1, 0x1_000, MEM_COMMIT, MEM_IMAGE),
            (module.base, module.base, 0, MEM_COMMIT, MEM_IMAGE),
            (module.base, module.base, 0x1_000, 0, MEM_IMAGE),
            (module.base, module.base, 0x1_000, MEM_COMMIT, 0),
            (module.base, module.base, 0x4_000, MEM_COMMIT, MEM_IMAGE),
        ];
        for (allocation_base, region_base, region_size, state, memory_type) in invalid {
            assert!(matches!(
                next_main_image_cursor(
                    module,
                    module.base,
                    allocation_base,
                    region_base,
                    region_size,
                    state,
                    memory_type,
                ),
                Err(LiveAccessError::InvalidMainModuleMapping)
            ));
        }
        assert!(matches!(
            next_main_image_cursor(
                module,
                module.base - 1,
                module.base,
                module.base - 1,
                1,
                MEM_COMMIT,
                MEM_IMAGE,
            ),
            Err(LiveAccessError::InvalidMainModuleMapping)
        ));
        assert!(matches!(
            next_main_image_cursor(
                module,
                module.base + u64::from(module.size_of_image),
                module.base,
                module.base + u64::from(module.size_of_image),
                1,
                MEM_COMMIT,
                MEM_IMAGE,
            ),
            Err(LiveAccessError::InvalidMainModuleMapping)
        ));

        let overflowing_module = MainModule {
            base: u64::MAX - 0x10,
            size_of_image: 0x100,
        };
        assert!(matches!(
            next_main_image_cursor(
                overflowing_module,
                overflowing_module.base,
                overflowing_module.base,
                overflowing_module.base,
                1,
                MEM_COMMIT,
                MEM_IMAGE,
            ),
            Err(LiveAccessError::MainModuleRangeOverflow)
        ));
        let overflowing_region = MainModule {
            base: u64::MAX - 0x2_000,
            size_of_image: 0x1_000,
        };
        assert!(matches!(
            next_main_image_cursor(
                overflowing_region,
                overflowing_region.base,
                overflowing_region.base,
                overflowing_region.base,
                0x3_000,
                MEM_COMMIT,
                MEM_IMAGE,
            ),
            Err(LiveAccessError::MainModuleRangeOverflow)
        ));
    }

    #[test]
    fn write_spans_are_nonempty_overflow_safe_and_page_bounded() {
        assert!(span_fits_single_page(0x1_000, 1, 0x1_000));
        assert!(span_fits_single_page(0x1_000, 0x1_000, 0x1_000));
        assert!(span_fits_single_page(0x1_001, 0xfff, 0x1_000));
        assert!(!span_fits_single_page(0x1_fff, 2, 0x1_000));
        assert!(!span_fits_single_page(0x1_000, 0, 0x1_000));
        assert!(!span_fits_single_page(0x1_000, 1, 0));
        assert!(!span_fits_single_page(u64::MAX, 2, 0x1_000));
    }

    #[test]
    fn prewrite_failure_evidence_does_not_claim_target_bytes_are_stable() {
        assert_eq!(
            MutationRecovery::NoWriteAttempted {
                protection_restored: true,
            }
            .to_string(),
            "no byte write attempted (protection_restored=true)"
        );
    }
}
