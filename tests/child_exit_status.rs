use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Ptracer, Restart};

#[macro_use]
mod support;
use support::*;

#[test]
#[timeout(2000)]
fn test_trace_true() -> Result<()> {
    let cmd = Command::new("true");
    let mut tracer = Ptracer::new();
    let mut tracee = tracer.spawn(cmd)?;

    let mut events = vec![];

    while let Some(tracee) = tracer.wait()? {
        eprintln!("{}: {:?}", tracee.pid, tracee.stop);
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
