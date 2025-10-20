use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Error, Pid, Ptracer, Restart, Signal};

#[macro_use]
mod support;
use support::*;

#[test]
#[timeout(2000)]
fn test_child_exit_status() -> Result<()> {
    let cmd = Command::new("true");
    let mut tracer = Ptracer::new();
    let mut tracee = tracer.spawn(cmd)?;

    let mut events = vec![];

    while let Some(tracee) = tracer.wait()? {
        eprintln!("{}: {:?}", tracee.pid(), tracee.stop());

        events.push(tracee);

        tracer.restart(tracee, Restart::Continue)?;
    }

    eprintln!("waiting on tracee: {}", tracee.id());

    let status = tracee.wait()?;
    eprintln!("tracee status: {status}");

    assert!(status.success());
    assert_eq!(status.code(), Some(0));

    assert_equivalent(&events, &[
        event!(0, SyscallExit),
        event!(0, Exiting { exit_code: 0 }, SIGTRAP),
    ]);

    eprintln!("ok!");

    Ok(())
}

#[test]
#[timeout(1000)]
fn test_kill_sigtrap() -> Result<()> {
    let mut cmd = Command::new("sleep");
    cmd.arg("60");

    let mut tracer = Ptracer::new();
    let mut child = tracer.spawn(cmd)?;

    let mut events = vec![];

    let pid = Pid::from_raw(child.id() as i32);
    nix::sys::signal::kill(pid, Signal::SIGTRAP)?;

    while let Some(tracee) = tracer.wait()? {
        events.push(tracee);

        eprintln!("{}: {:?}", tracee.pid(), tracee.stop());

        tracer.restart(tracee, Restart::Continue)?;
    }

    let status = child.wait()?;
    assert!(!status.success());
    assert_eq!(status.signal(), Some(5));
    assert!(status.core_dumped());

    assert_equivalent(&events, &[
        event!(0, SyscallExit),
        event!(0, SignalDelivery { signal: SIGTRAP}, SIGTRAP),
        event!(0, Signaling { signal: SIGTRAP, core_dumped: true }, SIGTRAP),
    ]);

    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[test]
#[timeout(100)]
fn test_tracee_died() -> Result<()> {
    let cmd = Command::new("true");

    let mut tracer = Ptracer::new();
    let mut child = tracer.spawn(cmd)?;

    let mut died = false;

    let mut events = vec![];

    while let Some(tracee) = tracer.wait()? {
        events.push(tracee);

        // Kill the stopped tracee, so restart and subsequent ptrace calls fail.
        child.kill()?;

        if let Err(err) = tracer.restart(tracee, Restart::Continue) {
            assert!(matches!(err, Error::TraceeDied { .. }));
            assert!(err.tracee_died());

            let regs = tracee.registers();

            assert!(regs.is_err());

            if let Err(err) = regs {
                assert!(matches!(err, Error::TraceeDied { .. }));
                assert!(err.tracee_died());
            } else {
                unreachable!();
            }

            died = true;
        }
    }

    assert!(died);

    assert_equivalent(&events, &[
        event!(0, SyscallExit),
        event!(0, Signaling { signal: Signal::SIGKILL, core_dumped: false }, SIGTRAP),
    ]);

    Ok(())
}

#[test]
#[timeout(2000)]
fn test_waiting_child() -> Result<()> {
    let mut cmd = Command::new("/bin/bash");
    cmd.args(&["-c", "sleep 1; wait; echo ok!"]);

    let mut tracer = Ptracer::new();
    let mut tracee = tracer.spawn(cmd)?;
    eprintln!("tracee pid = {}", tracee.id());

    let mut events = vec![];

    while let Some(tracee) = tracer.wait()? {
        eprintln!("{}: {:?}", tracee.pid(), tracee.stop());

        events.push(tracee);

        tracer.restart(tracee, Restart::Continue)?;
    }

    assert_equivalent(&events, &[
        event!(0, SyscallExit),
        event!(0, Fork { new: pid!(1) }, SIGTRAP),
        event!(1, Attach),
        event!(1, Exec { old: pid!(1) }, SIGTRAP),
        event!(1, Exiting { exit_code: 0}, SIGTRAP),
        event!(0, SignalDelivery { signal: Signal::SIGCHLD }, SIGCHLD),
        event!(0, Exiting { exit_code: 0 }, SIGTRAP)
    ]);

    eprintln!("waiting on tracee: {}", tracee.id());
    eprintln!("tracee status: {}", tracee.wait()?);

    eprintln!("ok!");

    Ok(())
}

#[test]
#[timeout(3000)]
fn test_wait_untraced_child() -> Result<()> {
    // Untraced, exits before tracee.
    let mut fast = Command::new("sleep").arg("0.1").spawn()?;

    // Untraced, exits after tracee.
    let mut slow = Command::new("sleep").arg("2").spawn()?;

    // Traced.
    let mut traceme = Command::new("sleep");
    traceme.arg("1");

    let mut tracer = Ptracer::new();
    let mut tracee = tracer.spawn(traceme)?;

    let mut events = vec![];

    while let Some(tracee) = tracer.wait()? {
        events.push(tracee);

        eprintln!("{}: {:?}", tracee.pid(), tracee.stop());

        tracer.restart(tracee, Restart::Continue)?;
    }

    assert_equivalent(&events, &[
        event!(0, SyscallExit),
        event!(0, Exiting { exit_code: 0}, SIGTRAP),
    ]);

    eprintln!("waiting on tracee: {}", tracee.id());
    eprintln!("tracee status: {}", tracee.wait()?);

    eprintln!("waiting on fast: {}", fast.id());
    eprintln!("fast status: {}", fast.wait()?);

    eprintln!("waiting on slow: {}", slow.id());
    eprintln!("slow status: {}", slow.wait()?);

    eprintln!("ok!");

    Ok(())
}

#[cfg(feature = "test-programs")]
#[test]
#[timeout(2000)]
fn test_exec_off_leader() -> Result<()> {
    let cmd = Command::new("test-programs/exec-off-leader/target/release/exec-off-leader");
    let mut tracer = Ptracer::new();
    let mut tracee = tracer.spawn(cmd)?;

    let mut events = vec![];

    while let Some(tracee) = tracer.wait()? {
        events.push(tracee);
        tracer.restart(tracee, Restart::Continue)?;
    }

    let status = tracee.wait()?;
    assert!(status.success());
    assert_eq!(status.code(), Some(0));

    assert_equivalent(&events, &[
        event!(0, SyscallExit),
        event!(0, Clone { new: pid!(1) }, SIGTRAP),
        event!(1, Attach),
        event!(0, Exiting { exit_code: 0}, SIGTRAP),
        event!(0, Exec { old: pid!(1) }, SIGTRAP),  // PID 1 becomes leader
        event!(0, Exiting { exit_code: 0 }, SIGTRAP),
    ]);

    Ok(())
}
