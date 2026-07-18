//! Real end-to-end ptrace exercise. `#[ignore]`d and gated on Linux + the
//! fixture feature, because a sandboxed CI environment may forbid ptrace
//! (yama `ptrace_scope`, seccomp). Run explicitly with:
//!
//! ```text
//! cargo test -p resymbol-linux-debug-host --features linux-debug-host-test-fixture \
//!     --test ptrace_end_to_end -- --ignored --exact launch_step_read_and_run_to_exit
//! ```

#![cfg(all(target_os = "linux", feature = "linux-debug-host-test-fixture"))]

use resymbol_linux_debug_host::{LaunchSpec, WaitOutcome, launch};

#[test]
#[ignore = "requires ptrace permission; run explicitly"]
fn launch_step_read_and_run_to_exit() {
    let fixture = env!("CARGO_BIN_EXE_resymbol-linux-debug-host-fixture");
    let mut session = launch(&LaunchSpec::new(fixture)).expect("launch traced child");

    // The child is stopped at its entry; RIP and RSP must be sane.
    let regs = session.read_registers().expect("read registers at entry");
    assert_ne!(regs.instruction_pointer(), 0, "entry RIP should be nonzero");
    assert_ne!(regs.stack_pointer(), 0, "entry RSP should be nonzero");

    // Reading the instruction bytes at RIP must succeed.
    let code = session
        .read_memory(regs.instruction_pointer(), 8)
        .expect("read code at entry");
    assert_eq!(code.len(), 8);

    // Single-step a handful of instructions; RIP should keep advancing (or the
    // process may finish, which is also acceptable).
    for _ in 0..4 {
        match session.single_step().expect("single-step") {
            WaitOutcome::Stopped(_) => {}
            WaitOutcome::Finished(_) => return,
            WaitOutcome::BreakpointHit { .. } => {}
        }
    }

    // Registers remain writable while stopped.
    let mut regs = session.read_registers().expect("read registers mid-run");
    regs.rax = 0x1234_5678;
    session.write_registers(&regs).expect("write registers");
    assert_eq!(session.read_registers().unwrap().rax, 0x1234_5678);

    // Run to completion.
    loop {
        match session.continue_execution().expect("continue") {
            WaitOutcome::Finished(_) => break,
            _ => continue,
        }
    }
}
