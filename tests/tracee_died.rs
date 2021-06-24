use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Error, Ptracer, Restart};

// Support absence of `matches!(0` in rustc 1.41.0.
macro_rules! assert_matches {
    ($expr: expr, $pat: pat) => {
        if let $pat = $expr {
            // Pass.
        } else {
            panic!("expected `{}` to match `{}`", stringify!($expr), stringify!($pat));
        }
    }
}

#[test]
#[timeout(100)]
fn test_tracee_died() -> Result<()> {
    let cmd = Command::new("true");

    let mut tracer = Ptracer::new();
    let mut child = tracer.spawn(cmd)?;

    let mut died = false;

    while let Some(tracee) = tracer.wait()? {
        // Kill the stopped tracee, so restart and subsequent ptrace calls fail.
        child.kill()?;

        if let Err(err) = tracer.restart(tracee, Restart::Continue) {
            assert_matches!(err, Error::Restart { .. });
            assert!(err.tracee_died());

            let regs = tracee.registers();

            assert!(regs.is_err());

            if let Err(err) = regs {
                assert_matches!(err, Error::TraceeDied { .. });
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
