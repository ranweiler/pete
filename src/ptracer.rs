use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

use nix::sys::{
    ptrace,
    wait::{self, WaitPidFlag, WaitStatus},
};

use crate::error::{Error, Result};


pub use nix::unistd::Pid;
pub use nix::sys::ptrace::Options;
pub use nix::sys::signal::Signal;

pub type Registers = libc::user_regs_struct;
pub type Siginfo = libc::siginfo_t;

const WALL: Option<WaitPidFlag> = Some(WaitPidFlag::__WALL);

/// Various ptrace-stops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    AttachStop(Pid),

    // signal-delivery-stop
    SignalDeliveryStop(Pid, Signal),

    // group-stop
    GroupStop(Pid, Signal),

    // syscall-stops
    SyscallEnterStop(Pid),
    SyscallExitStop(Pid),

    // ptrace-event-stops
    Clone(Pid, Pid),
    Fork(Pid, Pid),
    Exec(Pid, Pid),
    Exiting(Pid, i32),
    Signaling(Pid, Signal, bool),
    Vfork(Pid, Pid),
    VforkDone(Pid, Pid),
    Seccomp(u16),
}

/// Ptrace restart requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Restart {
    Step,
    Continue,
    Syscall,
}

/// Tracee in ptrace-stop, with an optional pending signal.
///
/// Describes how the stopped tracee would continue if it weren't traced, and thus how to
/// restart it to resume normal execution.
///
/// The underlying tracee is not guaranteed to exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tracee {
    pub pid: Pid,
    pub pending: Option<Signal>,
    pub stop: Stop,

    #[doc(hidden)]
    pub _not_send: PhantomData<*const ()>,
}

impl Tracee {
    pub fn new(pid: Pid, pending: impl Into<Option<Signal>>, stop: Stop) -> Self {
        let pending = pending.into();
        let _not_send = PhantomData;

        Self { pid, pending, stop, _not_send }
    }

    /// Set a signal to deliver to the stopped process upon restart.
    pub fn inject(&mut self, pending: Signal) {
        self.pending = Some(pending);
    }

    /// Remove any signal scheduled for delivery to `pid` upon restart.
    pub fn suppress(&mut self) {
        self.pending = None;
    }

    /// Set custom tracing options on the tracee.
    pub fn set_options(&mut self, options: Options) -> Result<()> {
        Ok(ptrace::setoptions(self.pid, options)?)
    }

    pub fn registers(&self) -> Result<Registers> {
        Ok(ptrace::getregs(self.pid)?)
    }

    pub fn set_registers(&mut self, regs: Registers) -> Result<()> {
        Ok(ptrace::setregs(self.pid, regs)?)
    }

    pub fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(len);
        data.resize(len, 0);
        let len_read = self.read_memory_mut(addr, &mut data)?;
        data.truncate(len_read);
        Ok(data)
    }

    pub fn read_memory_mut(&self, addr: u64, data: &mut [u8]) -> Result<usize> {
        use std::os::unix::fs::FileExt;

        let mem = fs::File::open(self.proc_mem_path())?;
        let len = mem.read_at(data, addr)?;
        Ok(len)
    }

    pub fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<usize> {
        use std::os::unix::fs::FileExt;

        let mem = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.proc_mem_path())?;

        let len = mem.write_at(data, addr)?;

        Ok(len)
    }

    fn proc_mem_path(&self) -> String {
        let tid = self.pid.as_raw() as u32;
        format!("/proc/{}/mem", tid)
    }

    pub fn siginfo(&self) -> Result<Option<Siginfo>> {
        let info = if let Stop::SignalDeliveryStop(..) = self.stop {
            Some(ptrace::getsiginfo(self.pid)?)
        } else {
            None
        };

        Ok(info)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    // Traced, no special expectation for next stop.
    Traced,

    // Newly-attached, expecting a SIGSTOP.
    Attaching,

    // Self-attached, via `spawn()` with a pre-exec `TRACEME` request.
    Spawned,

    // After a syscall-exit-stop or seccomp-stop.
    Syscalling,
}

/// Tracer for a (possibly multi-threaded) Linux process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ptracer {
    /// Ptrace options that will be applied to tracees, by default.
    options: Options,

    /// Known tracees, and their state.
    tracees: BTreeMap<i32, State>,
}

impl Ptracer {
    pub fn new() -> Self {
        let options = Options::all();
        let tracees = BTreeMap::new();

        Self { options, tracees }
    }

    /// Resume the stopped tracee, delivering any pending signal.
    pub fn restart(&mut self, tracee: Tracee, restart: Restart) -> Result<()> {
        let Tracee { pid, pending, .. } = tracee;

        let r = match restart {
            Restart::Step =>
                ptrace::step(pid, pending),
            Restart::Continue =>
                ptrace::cont(pid, pending),
            Restart::Syscall =>
                ptrace::syscall(pid, pending),
        };

        r.map_err(|source| Error::Restart {
            pid,
            mode: restart,
            source,
        })
    }

    pub fn spawn(&mut self, mut cmd: Command) -> Result<Child> {
        // On fork, request `PTRACE_TRACEME`.
        unsafe {
            cmd.pre_exec(|| ptrace::traceme().map_err(as_ioerror))
        };

        let child = cmd.spawn()?;

        // Register the tracee as having been spawned with a pre-exec `TRACEME` request.
        // This lets us interpret the `SIGTRAP` that will be issued for `execve()`, set
        // the desired trace options, &c.
        let pid = Pid::from_raw(child.id() as i32);
        self.set_tracee_state(pid, State::Spawned);

        Ok(child)
    }

    /// Attach to a running tracee. This will deliver a SIGSTOP.
    ///
    /// Warning: the tracee may not be considered stopped until it has been seen
    /// to stop via `wait()`.
    pub fn attach(&mut self, pid: Pid) -> Result<()> {
        let r = ptrace::attach(pid);
        let r = r.map_err(|source| Error::Attach { pid, source });

        self.mark_tracee(pid);

        r
    }

    /// Wait for some running tracee process to stop.
    pub fn wait(&mut self) -> Result<Option<Tracee>> {
        use Signal::*;

        let status = match wait::waitpid(None, WALL) {
            Ok(status) =>
                status,
            Err(nix::Error::Sys(errno)) if errno == nix::errno::Errno::ECHILD =>
                // No more children to wait on: we're done.
                return Ok(None),
            Err(err) =>
                return Err(err.into()),
        };

        let tracee = match status {
            WaitStatus::Exited(pid, _exit_code) => {
                self.remove_tracee(pid);
                return self.wait();
            },
            WaitStatus::Signaled(pid, _sig, _is_core_dump) => {
                self.remove_tracee(pid);
                return self.wait();
            },
            WaitStatus::Stopped(pid, SIGTRAP) => {
                let state = self.tracee_state_mut(pid);

                if let Some(state @ State::Spawned) = state {
                    // A `SIGTRAP` for a tracee in the `Spawned` state means it has returned from a
                    // successful `execve()` after requesting `PTRACE_TRACEME`. From the manual:
                    //
                    //     If the `PTRACE_O_TRACEEXEC` option is not in effect, all successful calls
                    //     to `execve(2)` by the traced process will cause it to be sent a `SIGTRAP`
                    //     signal, giving the parent a chance to gain control before the new program
                    //     begins execution.
                    //
                    // `PTRACE_O_TRACEEXEC` is not set by default, so it is not set when the child
                    // requests the attach. We will thus see its exec as a `SIGTRAP`, no matter what
                    // is set in `self.options`.
                    let stop = Stop::SyscallExitStop(pid);
                    let mut tracee = Tracee::new(pid, None, stop);

                    // Update the tracee state so subsequent traps are interpreted correctly.
                    *state = State::Traced;

                    // Set global tracing options on this root tracee. Auto-attached tracees from
                    // fork, clone, and exec will inherit them.
                    tracee.set_options(self.options)?;

                    tracee
                } else {
                    let stop = Stop::SignalDeliveryStop(pid, SIGTRAP);
                    Tracee::new(pid, None, stop)
                }
            },
            WaitStatus::Stopped(pid, sig) => {
                if sig == SIGSTOP {
                    if let Some(state) = self.tracee_state_mut(pid) {
                        if *state == State::Attaching {
                            *state = State::Traced;
                            let stop = Stop::AttachStop(pid);
                            let tracee = Tracee::new(pid, None, stop);
                            return Ok(Some(tracee));
                        }
                    }
                    else {
                        // We may see an attach-stop out-of-order, before the ptrace-event-stop
                        // which would otherwise have us mark it as `Attaching`. Since `Attaching`
                        // only exists to let us know that the next stop (i.e. this stop) is an
                        // attach-stop, we can directly initialize this tracee as `Traced`.
                        self.set_tracee_state(pid, State::Traced);
                        let stop = Stop::AttachStop(pid);
                        let tracee = Tracee::new(pid, None, stop);
                        return Ok(Some(tracee));
                    }
                }

                let stop = if is_group_stop(pid, sig)? {
                    Stop::GroupStop(pid, sig)
                } else {
                    Stop::SignalDeliveryStop(pid, sig)
                };

                Tracee::new(pid, sig, stop)
            },
            WaitStatus::PtraceEvent(pid, sig, code) => {
                match code {
                    libc::PTRACE_EVENT_FORK => {
                        let new_pid = Pid::from_raw(ptrace::getevent(pid)? as u32 as i32);

                        // When we return, `new_pid` will start as a tracee, but will be delivered
                        // a `SIGSTOP`. Mark it so we can recognize the `SIGSTOP` as an attach-stop.
                        self.mark_tracee(new_pid);

                        let stop = Stop::Fork(pid, new_pid);
                        Tracee::new(pid, sig, stop)
                    },
                    libc::PTRACE_EVENT_CLONE => {
                        let new_pid = Pid::from_raw(ptrace::getevent(pid)? as u32 as i32);

                        // When we return, `new_pid` will start as a tracee, but will be delivered
                        // a `SIGSTOP`. Mark it so we can recognize the `SIGSTOP` as an attach-stop.
                        self.mark_tracee(new_pid);

                        let stop = Stop::Clone(pid, new_pid);
                        Tracee::new(pid, sig, stop)
                    },
                    libc::PTRACE_EVENT_EXEC => {
                        // We are in one of two cases. The exec has either occurred on the main
                        // thread of the thread group, or not. In either case, the new tid of the
                        // execing thread will be equal to the tgid. In the off-main case, this is
                        // a change, and the old state for the tid == tgid will be invalid.

                        // The current `pid` is now equal to the tgid of `old_pid`.
                        let old_pid = Pid::from_raw(ptrace::getevent(pid)? as u32 as i32);

                        if old_pid != pid {
                            // We exec'd off-thread, and previous tid state is now invalid.
                            self.remove_tracee(old_pid);
                        }

                        // We know we are in a syscall. Make sure we can correctly label the next
                        // syscall-stop as an exit-stop.
                        //
                        // Important: if we trace all the syscall-stops, we will report the syscall-
                        // enter-stop as occurring on `old_pid`, but its matching syscall-exit-stop
                        // as occurring on `pid`. This is correct, but might look odd.
                        self.set_tracee_state(pid, State::Syscalling);

                        let stop = Stop::Exec(old_pid, pid);

                        Tracee::new(pid, sig, stop)
                    },
                    libc::PTRACE_EVENT_EXIT => {
                        // In this context, `PTRACE_GETEVENTMSG` returns the pending wait status
                        // as an `unsigned long`. We are only interested in the low 16-bit word.
                        let status = ptrace::getevent(pid)? as u16;

                        self.remove_tracee(pid);

                        let stop = match ExitType::parse(status)? {
                            ExitType::Exit(exit_code) =>
                                Stop::Exiting(pid, exit_code),
                            ExitType::Signaled(sig, core_dumped) =>
                                Stop::Signaling(pid, sig, core_dumped),
                        };

                        Tracee::new(pid, sig, stop)
                    },
                    libc::PTRACE_EVENT_VFORK => {
                        let new_pid = Pid::from_raw(ptrace::getevent(pid)? as u32 as i32);
                        self.mark_tracee(new_pid);

                        let stop = Stop::Vfork(pid, new_pid);

                        Tracee::new(pid, sig, stop)
                    },
                    libc::PTRACE_EVENT_VFORK_DONE => {
                        let new_pid = Pid::from_raw(ptrace::getevent(pid)? as u32 as i32);
                        let stop = Stop::VforkDone(pid, new_pid);

                        Tracee::new(pid, sig, stop)
                    },
                    libc::PTRACE_EVENT_SECCOMP => {
                        // `SECCOMP_RET_DATA`, which is the low 16 bits of an int.
                        let ret_data = ptrace::getevent(pid)? as u16;
                        let stop = Stop::Seccomp(ret_data);

                        if let Some(state) = self.tracee_state_mut(pid) {
                            *state = State::Syscalling;
                        } else {
                            internal_error!("seccomp ptrace-event-stop for non-tracee");
                        }

                        Tracee::new(pid, sig, stop)
                    },
                    libc::PTRACE_EVENT_STOP => {
                        // Unreachable by us, since we do not expose `PTRACE_SEIZE` &c.
                        internal_error!("unreachable ptrace-event-stop")
                    },
                    _ => {
                        // All kernel-delivered `event` values are matched above.
                        internal_error!("unexpected ptrace-event-stop code")
                    },
                }
            },
            // A signal-delivery-stop never happens between syscall-enter-stop and syscall-exit-stop.
            // It will always happen _after_ syscall-exit-stop, and not necessarily immediately. We
            // may observe ptrace-event-stops in-between -enter and -exit.
            //
            // From the manual:
            //
            //     No matter which method caused the syscall-entry-stop, if the tracer restarts
            //     the tracee with PTRACE_SYSCALL, the tracee enters syscall-exit-stop
            //     when the system call is finished, or if it is interrupted by a sig‐
            //     nal. (That is, signal-delivery-stop never happens between syscall-
            //     enter-stop and syscall-exit-stop; it happens after syscall-exit-
            //     stop.).  If the tracee is continued using any other method (including
            //     PTRACE_SYSEMU), no syscall-exit-stop occurs.
            //
            //     [...]
            //
            //     Syscall-enter-stop and syscall-exit-stop are indistinguishable from
            //     each other by the tracer.  The tracer needs to keep track of the
            //     sequence of ptrace-stops in order to not misinterpret syscall-enter-
            //     stop as syscall-exit-stop or vice versa.  In general, a syscall-
            //     enter-stop is always followed by syscall-exit-stop, PTRACE_EVENT
            //     stop, or the tracee's death; no other kinds of ptrace-stop can occur
            //     in between.  However, note that seccomp stops (see below) can cause
            //     syscall-exit-stops, without preceding syscall-entry-stops.  If sec‐
            //     comp is in use, care needs to be taken not to misinterpret such stops
            //     as syscall-entry-stops.
            //
            WaitStatus::PtraceSyscall(pid) => {
                let stop = match self.tracee_state_mut(pid) {
                    Some(state) => {
                        match state {
                            State::Syscalling => {
                                *state = State::Traced;
                                Stop::SyscallExitStop(pid)
                            },
                            State::Traced => {
                                *state = State::Syscalling;
                                Stop::SyscallEnterStop(pid)
                            },
                            State::Attaching => {
                                // A tracee in this state is waiting for a `SIGSTOP`, which is an
                                // artifact of `PTRACE_ATTACH`. The next wait status will thus be
                                // either a `SIGSTOP`, `SIGKILL`, or a `PTRACE_EVENT_EXIT`.
                                internal_error!("syscall-stop for `Attaching` tracee")
                            },
                            State::Spawned => {
                                // We only set the tracee state to `Spawned` after a successful call
                                // to `Command::spawn()` with a pre-exec `TRACEME` request.
                                //
                                // The self-attached tracee will continue until `execve()`. Since it
                                // can only self-attach with default options, the `execve()` will be
                                // seen as a `SIGTRAP` signal-delivery-stop, not a syscall-stop or
                                // ptrace-event-stop, and so we can never reach this case.
                                internal_error!("syscall-stop for `Spawning` tracee")
                            },
                        }
                    },
                    None => {
                        // Assumes any pid we are tracing is also indexed in `self.tracees`.
                        internal_error!("syscall-stop for unregistered tracee")
                    },
                };

                Tracee::new(pid, None, stop)
            },
            // Assume `!WNOHANG`, `!WCONTINUED`.
            WaitStatus::Continued(_) |
            WaitStatus::StillAlive =>
                internal_error!("unreachable `wait()` status"),
        };

        Ok(Some(tracee))
    }

    fn remove_tracee(&mut self, pid: Pid) -> Option<State> {
        self.tracees.remove(&pid.as_raw())
    }

    fn set_tracee_state(&mut self, pid: Pid, state: State) {
        self.tracees.insert(pid.as_raw(), state);
    }

    fn tracee_state_mut(&mut self, pid: Pid) -> Option<&mut State> {
        self.tracees.get_mut(&pid.as_raw())
    }

    // Mark `pid` as a new tracee pending attach-stop, if it isn't already known.
    fn mark_tracee(&mut self, pid: Pid) {
        self.tracees.entry(pid.as_raw()).or_insert(State::Attaching);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExitType {
    Exit(i32),
    Signaled(Signal, bool),
}

impl ExitType {
    fn parse(status: u16) -> Result<Self> {
        // The bit layout of the word `status` is:
        //
        //   15                         8   7                     0
        //    +-------------------------+---+---------------------+
        //    |        exit_code        | c |       sig_no        |
        //    +-------------------------+---+---------------------+
        //
        // If `status[6:0]` is nonzero, then `pid` is being signaled with `sig_no`,
        // and a set `status[7]` bit flags a core dump. Otherwise, it is a normal
        // exit with exit code `status[15:8]`.
        let sig_no = status & 0x7f;
        let exiting = sig_no == 0;

        let ty = if exiting {
            // Extract, zero-extend, cast.
            let exit_code = (status >> 8) as u8 as u32 as i32;

            ExitType::Exit(exit_code)
        } else {
            use std::convert::TryFrom;

            let core_dump = (status & (1 << 7)) >> 7;
            let signal = Signal::try_from(sig_no as i32)?;
            let core_dump = core_dump > 0;

            ExitType::Signaled(signal, core_dump)
        };

        Ok(ty)
    }
}

// Check if a wait stop with signal delivery is a group-stop.
//
// Assumes attach-stop has already been ruled out.
fn is_group_stop(pid: Pid, sig: Signal) -> Result<bool> {
    use Signal::*;

    match sig {
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => {
            use nix::{errno::Errno, Error};

            // Possible group-stop. Check `siginfo` to disambiguate.
            //
            // From the manual:
            //
            //     If PTRACE_GETSIGINFO fails with EINVAL, then it is definitely a
            //     group-stop.  (Other failure codes are possible, such as ESRCH
            //     ("no such process") if a SIGKILL killed the tracee.)
            //
            match ptrace::getsiginfo(pid) {
                Err(Error::Sys(Errno::EINVAL)) =>
                    Ok(true),
                Err(err) =>
                    Err(err.into()),
                Ok(_) =>
                    Ok(false)
            }
        },
        _ => {
            // Definitely not a group-stop.
            //
            // From the manual:
            //
            //     The call can be avoided if the signal is not SIGSTOP, SIGTSTP,
            //     SIGTTIN, or SIGTTOU; only these four signals are stopping signals.
            //     If the tracer sees something else, it can't be a group-stop.
            //
            Ok(false)
        },
    }
}

// Only intended for the result of `ptrace::traceme()`.
fn as_ioerror(err: nix::Error) -> io::Error {
    if let Some(errno) = err.as_errno() {
        io::Error::from_raw_os_error(errno as i32)
    } else {
        // Should be unreachable when used with `ptrace::traceme()`, since its `Result`
        // comes from an internal call to `nix::Errno::result()`.
        io::Error::new(io::ErrorKind::Other, err)
    }
}
