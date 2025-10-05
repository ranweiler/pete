use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Ptracer, Restart, Signal};

#[macro_use]
mod support;
use support::*;

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
        eprintln!("{}: {:?}", tracee.pid, tracee.stop);
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
