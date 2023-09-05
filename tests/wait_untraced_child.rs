use std::process::Command;

use anyhow::Result;
use ntest::timeout;
use pete::{Ptracer, Restart};

#[test]
#[timeout(5000)]
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

    while let Some(tracee) = tracer.wait()? {
        eprintln!("{}: {:?}", tracee.pid, tracee.stop);

        tracer.restart(tracee, Restart::Continue)?;
    }

    eprintln!("waiting on tracee: {}", tracee.id());
    println!("tracee status: {}", tracee.wait()?);

    eprintln!("waiting on fast: {}", fast.id());
    println!("fast status: {}", fast.wait()?);

    eprintln!("waiting on slow: {}", slow.id());
    println!("slow status: {}", slow.wait()?);

    eprintln!("ok!");

    Ok(())
}
