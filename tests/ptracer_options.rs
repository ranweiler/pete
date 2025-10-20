use anyhow::Result;

use pete::{Options, Ptracer};
use pete::ptracer::REQUIRED_OPTIONS;

type O = Options;

const CASES: &[O] = &[
    // Invalid
    O::empty(),
    REQUIRED_OPTIONS.difference(O::PTRACE_O_TRACEEXEC),
    REQUIRED_OPTIONS.difference(O::PTRACE_O_TRACEEXIT),
    REQUIRED_OPTIONS.difference(O::PTRACE_O_TRACESYSGOOD),
    O::all().difference(O::PTRACE_O_TRACEEXEC),
    O::all().difference(O::PTRACE_O_TRACEEXIT),
    O::all().difference(O::PTRACE_O_TRACESYSGOOD),

    // Ok
    REQUIRED_OPTIONS,
    REQUIRED_OPTIONS.union(O::PTRACE_O_TRACEFORK),  // Irrelevant
    O::all(),
];

#[test]
fn test_ptracer_options_default() -> Result<()> {
    let tracer = Ptracer::new();
    assert!(tracer.traceme_options().contains(REQUIRED_OPTIONS));
    Ok(())
}

#[test]
fn test_ptracer_options() -> Result<()> {
    for &opts in CASES {
        let mut tracer = Ptracer::new();
        tracer.set_traceme_options(opts);
        assert!(tracer.traceme_options().contains(REQUIRED_OPTIONS));
    }

    Ok(())
}
