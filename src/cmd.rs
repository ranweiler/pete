use std::ffi::{CString, NulError};

use nix::{
    sys::{signal::{raise, Signal}, ptrace},
    unistd::{fork, ForkResult, Pid},
};

use crate::error::Error;


/// Command to spawn as a child process to be traced.
#[derive(Clone, Debug)]
pub struct Command {
    /// Argument vector to pass to `execv()`.
    argv: Vec<CString>,

    /// Request `PTRACE_TRACEME` and raise `SIGSTOP` after forking, pre-exec.
    ///
    /// Defaults to `true`.
    trace_me: bool,
}

impl Command {
    pub fn new(argv: Vec<impl Into<Vec<u8>>>) -> Result<Self, NulError> {
        if argv.is_empty() {
            panic!("Command exe required");
        }

        // Ensure we own NUL-terminated strings to for the foreign exec call.
        //
        // We're heap-allocating, so always do this before forking.
        let argv: Result<Vec<_>, _> = argv
            .into_iter()
            .map(CString::new)
            .collect();
        let argv = argv?;

        Ok(Self { argv, trace_me: true })
    }

    /// Set the value of the `trace_me` flag.
    pub fn trace_me(mut self, trace_me: bool) -> Self {
        self.trace_me = trace_me;
        self
    }

    /// Fork and exec a child process determined by `self.argv`.
    ///
    /// If `self.trace_me`, the child process will set itself as a tracee of the parent,
    /// then raise `SIGSTOP` so the parent can resume and observe it without a race.
    pub fn fork_exec(self) -> Result<Pid, Error> {
        // Heap-allocates, must occur pre-fork.
        let argv = self.argv();

        match fork()? {
            ForkResult::Child => {
                // If any post-fork call fails, `panic`, since `?` may call `malloc`
                // via `Into`, which is not async-signal-safe.

                if self.trace_me {
                    ptrace::traceme()?;

                    if let Err(_) = raise(Signal::SIGSTOP) {
                        panic!("Unable to raise SIGSTOP");
                    }
                }

                // Use unsafe `libc::execv`, because the `nix` wrapper heap- allocates a
                // `Vec` internally, which is not async-signal-safe.
                unsafe {
                    if 0 != libc::execv(argv[0], argv.as_ptr()) {
                        panic!("Unable to exec tracee");
                    }
                }

                unreachable!();
            },
            ForkResult::Parent { child } => {
                Ok(child)
            },
        }
    }

    // Construct NUL-terminated arguments for `execv`. We heap-allocate to return a `Vec`,
    // and so must do this before calling `fork()`.
    fn argv(&self) -> Vec<*const libc::c_char> {
        let mut argv: Vec<_> = self.argv
            .iter()
            .map(|s| s.as_ptr())
            .collect();
        argv.push(std::ptr::null());
        argv
    }
}
