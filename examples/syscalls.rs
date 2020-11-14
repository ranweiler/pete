use std::collections::BTreeMap;
use std::env;

use pete::{Command, Ptracer, Restart, Stop};


fn main() -> anyhow::Result<()> {
    let syscalls = load_syscalls();

    let argv = env::args().skip(1).collect();
    let cmd = Command::new(argv)?;

    let mut ptracer = Ptracer::new();

    // Tracee is in pre-exec ptrace-stop.
    let tracee = ptracer.spawn(cmd)?;
    ptracer.restart(tracee, Restart::Syscall)?;

    while let Some(tracee) = ptracer.wait()? {
        let regs = tracee.registers()?;
        let pc = regs.rip as u64;

        match tracee.stop {
            Stop::SyscallEnterStop(..) |
            Stop::SyscallExitStop(..)=> {
                let rax = regs.orig_rax;
                let syscall = syscalls
                    .get(&rax)
                    .cloned()
                    .unwrap_or_else(|| format!("unknown (rax = 0x{:x})", rax));

                println!("{:>16x}: [{}], {:?}", pc, syscall, tracee.stop);
            },
            _ => {
                println!("{:>16x}: {:?}", pc, tracee.stop);
            },
        }

        ptracer.restart(tracee, Restart::Syscall)?;
    }

    Ok(())
}

const SYSCALLS: &'static str = include_str!("data/syscalls_x64.tsv");

fn load_syscalls() -> BTreeMap<u64, String> {
    let mut syscalls = BTreeMap::new();

    for line in SYSCALLS.split_terminator('\n') {
        let cols: Vec<_> = line.split('\t').collect();
        let callno: u64 = cols[0].parse().unwrap();
        let name = cols[1].to_owned();
        syscalls.insert(callno, name);
    }

    // Work around in-band communication in impl of `rt_sigreturn()`.
    syscalls.insert(-1i64 as u64, "rt_sigreturn".into());

    syscalls
}
