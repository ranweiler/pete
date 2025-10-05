use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Ptracer, Restart};

#[macro_use]
mod support;
use support::*;

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

        eprintln!("{}: {:?}", tracee.pid, tracee.stop);

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
