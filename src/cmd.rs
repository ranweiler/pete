use std::collections::HashMap;
use std::ffi::{CString, NulError, OsString};
use std::os::raw::c_char;

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

    /// Environment to use for the child process.
    ///
    /// Inherits the parent's environment by default.
    env: OsEnv,
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

        let env = OsEnv::new()?;

        Ok(Self { argv, env, trace_me: true })
    }

    pub fn env(&mut self) -> &mut OsEnv {
        &mut self.env
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
        // These calls heap-allocate, and must occur pre-fork.
        let argv = NullTerminatedPointerArray::new(&self.argv);
        let env = self.env.as_vec();
        let env = NullTerminatedPointerArray::new(&env);

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
                    if 0 != libc::execve(&*argv[0], argv.as_ptr(), env.as_ptr()) {
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
}

#[derive(Clone, Debug)]
pub struct OsEnv {
    kvs: HashMap<OsString, CString>,
}

impl OsEnv {
    pub fn new() -> Result<Self, NulError> {
        let kvs = HashMap::new();
        let mut env = Self { kvs };

        // Inherit parent environment by default.
        for (key, val) in std::env::vars_os() {
            OsEnv::set(&mut env, key, val)?;
        }

        Ok(env)
    }

    pub fn set<K, V>(&mut self, key: K, val: V) -> Result<(), NulError>
    where
        K: Into<OsString>,
        V: Into<OsString>,
    {
        use std::os::unix::ffi::OsStrExt;

        let key = key.into();
        let val = val.into();

        // Create an `OsString` of the form `${key}=${value}`.
        let mut kv = OsString::new();
        kv.push(&key);
        kv.push("=");
        kv.push(val);

        // NUL-terminate the KV string.
        let kv = CString::new(kv.as_bytes())?;

        self.kvs.insert(key, kv);

        Ok(())
    }

    pub fn clear(&mut self) {
        self.kvs.clear();
    }

    pub fn as_vec(&self) -> Vec<CString> {
        self.kvs.values().cloned().collect()
    }
}

// View of a slice of `CString` values, as a null-terminated array of pointers to
// `c_char`. For passing args to `execve()`.
struct NullTerminatedPointerArray<'a> {
    // Owned pointer array which must always be NULL-terminated.
    array: Vec<*const libc::c_char>,

    // Borrow of pointed-to `CString` data. Pointers in `array` are valid only
    // while we have this borrow.
    _data: &'a [CString],
}

impl<'a> NullTerminatedPointerArray<'a> {
    pub fn new(data: &'a [CString]) -> Self {
        let mut array: Vec<_> = data
            .iter()
            .map(|s| s.as_ptr())
            .collect();
        array.push(std::ptr::null());

        Self { array, _data: data }
    }
}

impl<'a> std::ops::Deref for NullTerminatedPointerArray<'a> {
    type Target = [*const c_char];

    fn deref(&self) -> &Self::Target {
        &self.array
    }
}
