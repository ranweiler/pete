use std::env;

use pete::{Ptracer, Restart};


fn main() -> anyhow::Result<()> {
    let argv = env::args().skip(1).collect();
    let mut ptracer = Ptracer::new();

    // Tracee is in pre-exec ptrace-stop.
    let tracee = ptracer.spawn(argv)?;
    ptracer.restart(tracee, Restart::Continue)?;

    while let Some(tracee) = ptracer.wait()? {
        let regs = tracee.registers()?;
        let pc = regs.rip as u64;

        println!("{:>16x}: {:?}", pc, tracee.stop);

        ptracer.restart(tracee, Restart::Continue)?;
    }

    Ok(())
}
