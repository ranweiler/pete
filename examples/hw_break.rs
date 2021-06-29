use std::process::Command;

use anyhow::Result;
use pete::{x86, Ptracer, Restart, Signal, Stop, Tracee};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(short, long)]
    quiet: bool,

    #[structopt(min_values = 1)]
    argv: Vec<String>,

    #[structopt(short, long, parse(try_from_str = parse_breakpoint))]
    breakpoint: u64,
}

fn parse_breakpoint(s: &str) -> Result<u64> {
    let s = s.trim_start_matches("0x");
    Ok(u64::from_str_radix(s, 16)?)
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    let mut cmd = Command::new(&opt.argv[0]);

    if let Some(args) = opt.argv.get(1..) {
        cmd.args(args);
    }

    let mut ptracer = Ptracer::new();
    let _child = ptracer.spawn(cmd)?;

    let mut hit = false;
    let mut set = false;

    while let Some(mut tracee) = ptracer.wait()? {
        let regs = tracee.registers()?;
        let pc = regs.rip as u64;

        if !set {
            // Set HW breakpoitn on exit from `exec(2)`.
            set_hw_breakpoint(&mut tracee, opt.breakpoint)?;
            set = true;
        }

        let Tracee { pid, stop, .. } = tracee;

        if !opt.quiet {
            println!("pid = {}, pc = {:x}: {:?}", pid, pc, stop);
        }

        if let Stop::SignalDeliveryStop { signal: Signal::SIGTRAP } = stop {
            if pc == opt.breakpoint {
                hit = true;
            }
        }

        ptracer.restart(tracee, Restart::Continue)?;
    }

    if hit {
        println!("hit breakpoint: 0x{:x}", opt.breakpoint);
    }

    Ok(())
}

fn set_hw_breakpoint(tracee: &mut Tracee, va: u64) -> Result<()> {
    tracee.set_debug_register(x86::DebugRegister::Dr0, va)?;

    let dr7_reserved = 0x100;
    let dr7_enable_dr0_local = 0x1;
    let dr7: u64 = dr7_reserved | dr7_enable_dr0_local;

    tracee.set_debug_register(x86::DebugRegister::Dr7, dr7)?;

    Ok(())
}
