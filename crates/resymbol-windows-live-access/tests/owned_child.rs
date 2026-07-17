#![cfg(all(windows, feature = "live-access-test-fixture"))]

use std::{
    fs::File,
    io::{BufRead as _, BufReader, Write as _},
    process::{Child, ChildStdin, Command, Stdio},
};

use resymbol_core::BinaryId;
use resymbol_debugger::protocol::{
    LiveTargetBindingError, MemoryAddress, ProcessId, ProcessStartKey,
};
use resymbol_windows_live_access::{
    LiveAccessError, MutatingLiveProcessAccess, OpenLiveProcessRequest, ReadOnlyLiveProcessAccess,
};

const ORIGINAL: &[u8; 8] = b"RSYMLIVE";
const REPLACEMENT: &[u8; 8] = b"R5YML1VE";

struct OwnedFixtureChild {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl OwnedFixtureChild {
    fn finish(&mut self) {
        if let Some(mut stdin) = self.stdin.take() {
            writeln!(stdin).expect("release owned live-access fixture");
        }
        let status = self
            .child
            .wait()
            .expect("wait for owned live-access fixture");
        assert!(
            status.success(),
            "owned live-access fixture failed: {status}"
        );
    }
}

impl Drop for OwnedFixtureChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn exact_binding_read_compare_write_and_restore_owned_child() {
    let fixture = env!("CARGO_BIN_EXE_resymbol-windows-live-access-fixture");
    let mut child = Command::new(fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn owned live-access fixture");
    let stdin = child.stdin.take().expect("fixture stdin");
    let stdout = child.stdout.take().expect("fixture stdout");
    let mut owned = OwnedFixtureChild {
        child,
        stdin: Some(stdin),
    };
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read fixture target address");
    let mut fields = line.split_ascii_whitespace();
    let start_key = u64::from_str_radix(
        fields.next().expect("fixture emits a process start key"),
        16,
    )
    .expect("fixture start key is hexadecimal");
    let image_base =
        u64::from_str_radix(fields.next().expect("fixture emits a main-image base"), 16)
            .expect("fixture image base is hexadecimal");
    let absolute_address =
        u64::from_str_radix(fields.next().expect("fixture emits a target address"), 16)
            .expect("fixture target address is hexadecimal");
    assert!(
        fields.next().is_none(),
        "fixture emits exactly three fields"
    );
    let start_key = ProcessStartKey::new(start_key).expect("fixture start key is nonzero");
    let image_base = MemoryAddress::new(image_base);

    let (binary_id, _) =
        BinaryId::digest_reader(File::open(fixture).expect("open exact owned fixture executable"))
            .expect("hash exact owned fixture executable");
    let process_id = ProcessId::new(owned.child.id()).expect("child PID is nonzero");
    let wrong_identity = ReadOnlyLiveProcessAccess::open_read_only(OpenLiveProcessRequest::new(
        process_id,
        start_key,
        image_base,
        BinaryId::digest(b"not the owned fixture"),
    ));
    assert!(
        matches!(
            &wrong_identity,
            Err(LiveAccessError::BinaryIdentityMismatch { .. })
        ),
        "unexpected wrong-identity result: {wrong_identity:?}"
    );

    let wrong_start_key = ProcessStartKey::new(
        start_key
            .get()
            .checked_add(1)
            .expect("fixture start key has successor"),
    )
    .expect("wrong start key remains nonzero");
    assert!(matches!(
        ReadOnlyLiveProcessAccess::open_read_only(OpenLiveProcessRequest::new(
            process_id,
            wrong_start_key,
            image_base,
            binary_id.clone(),
        )),
        Err(LiveAccessError::ProcessStartIdentityMismatch { .. })
    ));

    let wrong_image_base = MemoryAddress::new(
        image_base
            .get()
            .checked_add(0x1_0000)
            .expect("fixture image base has bounded successor"),
    );
    assert!(matches!(
        ReadOnlyLiveProcessAccess::open_read_only(OpenLiveProcessRequest::new(
            process_id,
            start_key,
            wrong_image_base,
            binary_id.clone(),
        )),
        Err(LiveAccessError::MainModuleBaseMismatch { .. })
    ));

    let read_only = ReadOnlyLiveProcessAccess::open_read_only(OpenLiveProcessRequest::new(
        process_id,
        start_key,
        image_base,
        binary_id.clone(),
    ))
    .expect("open exact owned fixture read-only");
    let canonical_fixture =
        std::fs::canonicalize(fixture).expect("canonicalize owned fixture executable");
    assert_eq!(read_only.executable_path(), canonical_fixture.as_path());
    let read_only_binding = read_only.binding().clone();
    let read_only_rva = absolute_address
        .checked_sub(read_only_binding.actual_image_base().get())
        .expect("fixture target lies in its main image");
    assert_eq!(
        read_only
            .read_exact_rva(&read_only_binding, read_only_rva, ORIGINAL.len())
            .expect("read original fixture bytes through read-only handle"),
        ORIGINAL
    );
    drop(read_only);

    let mut access = MutatingLiveProcessAccess::open_mutating(OpenLiveProcessRequest::new(
        process_id, start_key, image_base, binary_id,
    ))
    .expect("open exact owned fixture for mutation");
    let binding = access.binding().clone();
    let rva = absolute_address
        .checked_sub(binding.actual_image_base().get())
        .expect("fixture target lies in its main image");

    assert_eq!(
        access
            .read_exact_rva(&binding, rva, ORIGINAL.len())
            .expect("read original fixture bytes"),
        ORIGINAL
    );
    assert!(matches!(
        access.read_exact_rva(&binding, u64::from(binding.size_of_image()), ORIGINAL.len(),),
        Err(LiveAccessError::RvaRange(
            LiveTargetBindingError::RvaOutOfImage { .. }
        ))
    ));
    assert!(matches!(
        access.compare_before_write_rva(&binding, rva, b"WRONGBYT", REPLACEMENT),
        Err(LiveAccessError::CompareMismatch { .. })
    ));
    assert_eq!(
        access
            .read_exact_rva(&binding, rva, ORIGINAL.len())
            .expect("failed compare leaves original bytes"),
        ORIGINAL
    );

    let receipt = access
        .compare_before_write_rva(&binding, rva, ORIGINAL, REPLACEMENT)
        .expect("replace exact fixture bytes");
    assert_eq!(receipt.binding(), &binding);
    assert_eq!(receipt.rva(), rva);
    assert_eq!(receipt.bytes_written(), REPLACEMENT.len());
    assert_eq!(
        access
            .read_exact_rva(&binding, rva, REPLACEMENT.len())
            .expect("read replacement fixture bytes"),
        REPLACEMENT
    );

    let _restore_receipt = access
        .compare_before_write_rva(&binding, rva, REPLACEMENT, ORIGINAL)
        .expect("restore exact fixture bytes");
    assert_eq!(
        access
            .read_exact_rva(&binding, rva, ORIGINAL.len())
            .expect("read restored fixture bytes"),
        ORIGINAL
    );
    assert_eq!(
        access
            .refresh_binding(&binding)
            .expect("refresh exact fixture binding"),
        binding
    );
    owned.finish();
    assert!(matches!(
        access.refresh_binding(&binding),
        Err(LiveAccessError::ProcessExited)
    ));
}
