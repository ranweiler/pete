use std::collections::BTreeMap;
use std::env;
use std::process::Command;

use pete::{Ptracer, Restart, Stop, Tracee};


fn main() -> anyhow::Result<()> {
    let syscalls = load_syscalls();

    let argv: Vec<String> = env::args().skip(1).collect();
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);

    let mut ptracer = Ptracer::new();
    let _child = ptracer.spawn(cmd)?;

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

                let Tracee { pid, stop, .. } = tracee;
                println!("pid = {}, pc = {:x}: [{}], {:?}", pid, pc, syscall, stop);
            },
            _ => {
                let Tracee { pid, stop, .. } = tracee;
                println!("pid = {}, pc = {:x}: {:?}", pid, pc, stop);
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
