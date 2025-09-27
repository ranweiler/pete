use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Ptracer, Restart};

#[test]
#[timeout(2000)]
fn test_trace_true() -> Result<()> {
    let cmd = Command::new("true");
    let mut tracer = Ptracer::new();
    let mut tracee = tracer.spawn(cmd)?;

    while let Some(tracee) = tracer.wait()? {
        eprintln!("{}: {:?}", tracee.pid, tracee.stop);

        tracer.restart(tracee, Restart::Continue)?;
    }

    eprintln!("waiting on tracee: {}", tracee.id());

    let status = tracee.wait()?;
    eprintln!("tracee status: {status}");

    assert!(status.success());
    assert_eq!(status.code(), Some(0));

    eprintln!("ok!");

    Ok(())
}
