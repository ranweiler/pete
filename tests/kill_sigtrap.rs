use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Pid, Ptracer, Restart, Signal};

#[macro_use]
mod support;
use support::*;

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
