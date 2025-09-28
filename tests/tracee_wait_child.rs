use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Ptracer, Restart};

#[test]
#[timeout(2000)]
fn test_waiting_child() -> Result<()> {
    let mut cmd = Command::new("/bin/bash");
    cmd.args(&["-c", "sleep 1; wait; echo ok!"]);

    let mut tracer = Ptracer::new();
    let mut tracee = tracer.spawn(cmd)?;
    eprintln!("tracee pid = {}", tracee.id());

    while let Some(tracee) = tracer.wait()? {
        eprintln!("{}: {:?}", tracee.pid, tracee.stop);

        tracer.restart(tracee, Restart::Continue)?;
    }

    eprintln!("waiting on tracee: {}", tracee.id());
    eprintln!("tracee status: {}", tracee.wait()?);

    eprintln!("ok!");

    Ok(())
}
