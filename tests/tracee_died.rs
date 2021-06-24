use std::process::Command;

use anyhow::Result;
use pete::{Error, Ptracer, Restart};

#[test]
fn test_tracee_died() -> Result<()> {
    let cmd = Command::new("true");

    let mut tracer = Ptracer::new();
    let mut child = tracer.spawn(cmd)?;

    let mut died = false;

    while let Some(tracee) = tracer.wait()? {
        // Kill the stopped tracee, so restart and subsequent ptrace calls fail.
        child.kill()?;

        if let Err(err) = tracer.restart(tracee, Restart::Continue) {
            assert!(matches!(err, Error::Restart { .. }));
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

    Ok(())
}
