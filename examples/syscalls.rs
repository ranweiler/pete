use std::collections::BTreeMap;
use std::process::Command;

use anyhow::Result;
use pete::{Ptracer, Restart, Stop, Tracee};
use lazy_static::lazy_static;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(short, long)]
    tsv: bool,

    #[structopt(min_values = 1)]
    argv: Vec<String>,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();
    let argv: Vec<String> = opt.argv;
    let mut cmd = Command::new(&argv[0]);
    if let Some(args) = argv.get(1..) {
        cmd.args(args);
    }

    let mut ptracer = Ptracer::new();
    let _child = ptracer.spawn(cmd)?;

    while let Some(mut tracee) = ptracer.wait()? {
        if opt.tsv {
            on_stop_tsv(&mut tracee)?;
        } else {
            on_stop(&mut tracee)?;
        }

        ptracer.restart(tracee, Restart::Syscall)?;
    }

    Ok(())
}

fn on_stop(tracee: &mut Tracee) -> Result<()> {
    let regs = tracee.registers()?;
    let pc = regs.rip as u64;

    match tracee.stop {
        Stop::SyscallEnterStop(..) |
        Stop::SyscallExitStop(..) => {
            let syscallno = regs.orig_rax;
            let syscall = SYSCALL_TABLE
                .get(&syscallno)
                .cloned()
                .unwrap_or_else(|| format!("unknown (syscallno = 0x{:x})", syscallno));

            let Tracee { pid, stop, .. } = tracee;
            println!("pid = {}, pc = {:x}: [{}], {:?}", pid, pc, syscall, stop);
        },
        _ => {
            let Tracee { pid, stop, .. } = tracee;
            println!("pid = {}, pc = {:x}: {:?}", pid, pc, stop);
        },
    }

    Ok(())
}

fn on_stop_tsv(tracee: &mut Tracee) -> Result<()> {
    match tracee.stop {
        Stop::SyscallEnterStop(..) => {
            on_syscall_stop_tsv(tracee, true)?;
        }
        Stop::SyscallExitStop(..)=> {
            on_syscall_stop_tsv(tracee, false)?;
        }
        _ => {},
    }

    Ok(())
}

fn on_syscall_stop_tsv(tracee: &mut Tracee, syscall_enter: bool) -> Result<()> {
    let regs = tracee.registers()?;
    let syscallno = regs.orig_rax;
    let stop_type = if syscall_enter { "enter" } else { "exit" };

    println!("{}\t{}\t{}", tracee.pid, stop_type, syscallno);

    Ok(())
}

const SYSCALLS: &'static str = include_str!("data/syscalls_x64.tsv");

lazy_static! {
    static ref SYSCALL_TABLE: SyscallTable = load_syscall_table();
}

type SyscallTable = BTreeMap<u64, String>;

fn load_syscall_table() -> SyscallTable {
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
