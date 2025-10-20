use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Options, Ptracer, Restart};

#[macro_use]
mod support;
use support::*;

#[test]
#[timeout(2000)]
fn test_tracee_required_options() -> Result<()> {
    let mut cmd = Command::new("/bin/bash");
    cmd.args(&[
        "-c",
        "( true )"
    ]);
    let mut tracer = Ptracer::new();
    let mut child = tracer.spawn(cmd)?;

    let mut events = vec![];

    while let Some(mut tracee) = tracer.wait()? {
        events.push(tracee);

        let opts = Options::PTRACE_O_TRACEFORK;
        tracee.set_options(opts)?;

        tracer.restart(tracee, Restart::Continue)?;
    }

    assert_equivalent(&events, &[
        event!(0, SyscallExit),
        event!(0, Fork { new: pid!(1) }, SIGTRAP),
        event!(1, Attach),
        event!(1, Exiting { exit_code: 0 }, SIGTRAP),
        event!(0, SignalDelivery { signal: SIGCHLD }, SIGCHLD),
        event!(0, Exiting { exit_code: 0 }, SIGTRAP),
    ]);

    child.wait()?;

    Ok(())
}
