use std::env;
use std::process::Command;

use pete::{Ptracer, Restart};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let argv: Vec<String> = env::args().skip(1).collect();
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);

    let mut ptracer = Ptracer::new();
    let _child = ptracer.spawn(cmd)?;

    while let Some(tracee) = ptracer.wait()? {
        let regs = tracee.registers()?;
        let pc = regs.rip as u64;

        let pid = tracee.pid();
        let stop = tracee.stop();
        println!("pid = {}, pc = {:x}: {:?}", pid, pc, stop);

        ptracer.restart(tracee, Restart::Continue)?;
    }

    Ok(())
}
