use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Error, Ptracer, Restart, Signal};

#[macro_use]
mod support;
use support::*;

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
