//! Types for attaching to processes, managing tracees, and interpreting tracing events.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::Duration;

use nix::{
    errno::Errno,
    sys::{
        ptrace,
        wait::{self, WaitPidFlag, WaitStatus},
    },
};
use tracing::{debug, info, trace};

use crate::error::{Error, Result, ResultExt};

#[cfg(target_arch = "aarch64")]
use crate::aarch64;

#[cfg(target_arch = "x86_64")]
use crate::x86;

#[cfg(target_arch = "x86_64")]
use x86::DebugRegister;

#[cfg(target_arch = "aarch64")]
pub type DebugRegisters = aarch64::user_hwdebug_state;

pub use nix::unistd::Pid;
pub use nix::sys::ptrace::Options;

/// POSIX signal.
pub use nix::sys::signal::Signal;

/// Register state of a tracee.
#[cfg(target_arch = "aarch64")]
pub type Registers = aarch64::user_pt_regs;

/// Register state of a tracee.
#[cfg(target_arch = "x86_64")]
pub type Registers = libc::user_regs_struct;

/// Extra signal info, such as its cause.
pub type Siginfo = libc::siginfo_t;

/// Linux constant defined in `include/uapi/linux/elf.h`.
#[cfg(target_arch = "aarch64")]
const NT_PRSTATUS: i32 = 0x1;

/// A _ptrace-stop_, a tracee state in which it is stopped and ready to accept ptrace
/// commands.
///
/// These ptrace-stops may carry data obtained via additional (internal) ptrace requests
/// to `PTRACE_GETEVENTMSG`. Requests to `PTRACE_GETSIGINFO` may be made to disambiguate
/// stops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    Attach,

    // signal-delivery-stop
    SignalDelivery { signal: Signal },

    // group-stop
    Group { signal: Signal },

    // syscall-stops
    SyscallEnter,
    SyscallExit,

    // ptrace-event-stops
    Clone { new: Pid },
    Fork { new: Pid },
    Exec { old: Pid },
    Exiting { exit_code: i32 },
    Signaling {
        signal: Signal,
        core_dumped: bool,
    },
    Vfork { new: Pid },
    VforkDone { new: Pid },
    Seccomp { data: u16 },
}

/// Restart requests, which resume stopped tracees.
///
/// The restart mode determines the possible subsequent stops of the restarted tracee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Restart {
    Step,
    Continue,
    Syscall,
}

/// Tracee task in ptrace-stop, with an optional pending signal.
///
/// **Warning:** the underlying tracee is not guaranteed to exist, and
/// operations on it may fail between calls to [`Ptracer::wait()`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tracee {
    pid: Pid,
    pending: Option<Signal>,
    stop: Stop,

    #[doc(hidden)]
    _not_send: PhantomData<*const ()>,
}

impl Tracee {
    pub fn new(pid: Pid, pending: impl Into<Option<Signal>>, stop: Stop) -> Self {
        let pending = pending.into();
        let _not_send = PhantomData;

        Self { pid, pending, stop, _not_send }
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn pending_signal(&self) -> Option<Signal> {
        self.pending
    }

    pub fn set_pending_signal(&mut self, pending: impl Into<Option<Signal>>) {
        self.pending = pending.into();
    }

    pub fn stop(&self) -> Stop {
        self.stop
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
    ///
    /// **NOTE:** [`REQUIRED_OPTIONS`] are always set, even if unset in the passed value.
    pub fn set_options(&mut self, options: Options) -> Result<()> {
        let options = options | REQUIRED_OPTIONS;
        Ok(ptrace::setoptions(self.pid, options).died_if_esrch(self.pid)?)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn registers(&self) -> Result<Registers> {
        Ok(ptrace::getregs(self.pid).died_if_esrch(self.pid)?)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn registers(&self) -> Result<Registers> {

        let mut data = std::mem::MaybeUninit::uninit();
        let mut rv = libc::iovec {
            iov_base: &mut data as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<Registers>(),
        };

        let res = unsafe {
            libc::ptrace(libc::PTRACE_GETREGSET, self.pid, NT_PRSTATUS, &mut rv as *mut _ as *mut libc::c_void)
        };

        Errno::result(res)?;

        Ok( unsafe { data.assume_init() } )
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_registers(&mut self, regs: Registers) -> Result<()> {
        Ok(ptrace::setregs(self.pid, regs).died_if_esrch(self.pid)?)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn set_registers(&mut self, regs: Registers) -> Result<()> {
        let mut rv = libc::iovec {
            iov_base: &regs as *const _ as *const libc::c_void as *mut libc::c_void,
            iov_len: std::mem::size_of::<Registers>(),
        };

        let res = unsafe {
            libc::ptrace(libc::PTRACE_SETREGSET, self.pid, NT_PRSTATUS, &mut rv as *mut _ as *mut libc::c_void)
        };

        Errno::result(res)?;

        Ok(())
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

        let mem = self.memory()?;
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

    pub fn memory(&self) -> Result<fs::File> {
        Ok(fs::File::open(self.proc_mem_path())?)
    }

    pub fn siginfo(&self) -> Result<Option<Siginfo>> {
        let info = if let Stop::SignalDelivery { .. } = self.stop {
            Some(ptrace::getsiginfo(self.pid).died_if_esrch(self.pid)?)
        } else {
            None
        };

        Ok(info)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn debug_register(&self, dr: DebugRegister) -> Result<u64> {
        let index = 8 * u64::from(dr);

        if let Some(off) = DebugRegister::user_offset().checked_add(index) {
            self.peek_user(off)
        } else {
            internal_error!("unreachable overflow")
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn debug_registers(&self, regtype: aarch64::DebugRegisterType) -> Result<DebugRegisters> {
        let mut data = std::mem::MaybeUninit::uninit();
        let mut rv = libc::iovec {
            iov_base: &mut data as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<aarch64::user_hwdebug_state>(),
        };
        let res = unsafe {
            libc::ptrace(libc::PTRACE_GETREGSET, self.pid, regtype, &mut rv as *mut _ as *mut libc::c_void)
        };

        Errno::result(res)?;

        Ok(unsafe { data.assume_init() })
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_debug_register(&self, dr: DebugRegister, data: u64) -> Result<()> {
        let index = 8 * u64::from(dr);

        if let Some(off) = DebugRegister::user_offset().checked_add(index) {
            self.poke_user(off, data)
        } else {
            internal_error!("unreachable overflow")
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn set_debug_registers(&self, regtype: aarch64::DebugRegisterType, mut state: DebugRegisters) -> Result<()> {
        let mut rv = libc::iovec {
            iov_base: &mut state as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<aarch64::user_hwdebug_state>(),
        };
        let res = unsafe {
            libc::ptrace(libc::PTRACE_SETREGSET, self.pid, regtype, &mut rv as *mut _ as *mut libc::c_void)
        };

        Errno::result(res)?;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn peek_user(&self, off: u64) -> Result<u64> {
        // SAFETY: `off` does not require validation, because it is not actually used as a
        // pointer offset by the kernel.
        //
        // See: https://github.com/torvalds/linux/blob/v4.9/arch/x86/kernel/ptrace.c#L774-L791

        let data = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKUSER,
                self.pid,
                off,
                0,
            )
        };

        Ok(data as u64)
    }

    #[cfg(target_arch = "x86_64")]
    fn poke_user(&self, off: u64, data: u64) -> Result<()> {
        // SAFETY: `off` does not require validation, because it is not actually used as a
        // pointer offset by the kernel.
        //
        // See: https://github.com/torvalds/linux/blob/v4.9/arch/x86/kernel/ptrace.c#L774-L791

        unsafe {
            libc::ptrace(
                libc::PTRACE_POKEUSER,
                self.pid,
                off,
                data,
            )
        };

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    // Attached, no expectations for next stop.
    Running,

    // Newly-attached, expecting a SIGSTOP.
    Attaching,

    // Self-attached, via `spawn()` with a pre-exec `TRACEME` request.
    Spawned,

    // After a syscall-exit-stop or seccomp-stop.
    Syscalling,

    // Stopped mid-exit (but not yet reaped) and pending detach.
    Exiting,

    // Detach-restarted after ptrace-exit (PTRACE_EVENT_EXIT), but pending confirmed termination
    // via a WIFEXITED or WIFSIGNALED status. Could be non-terminally exec-exited.
    Exited,
}

/// Tracer for a Linux process.
///
/// By default, [spawning](Ptracer::spawn()) a child tracee will follow calls to `fork()`,
/// `clone()`, and `exec()`, tracing any child tasks (both threads and processes).
///
/// This can be configured for any stopped tracee via [`Tracee::set_options()`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ptracer {
    /// Ptrace options that will be applied to tracees, by default.
    options: Options,

    /// Time to sleep for before polling tracees for new events.
    poll_delay: Duration,

    /// Known tracees, and their state.
    tracees: BTreeMap<i32, State>,
}

const DEFAULT_POLL_DELAY: Duration = Duration::from_micros(1);
const DEFAULT_OPTIONS: Options = Options::all();

/// Options required for internal tracee state management.
/// These are:
/// - [`PTRACE_O_TRACEEXEC`](Options::PTRACE_O_TRACEEXEC)
/// - [`PTRACE_O_TRACEEXIT`](Options::PTRACE_O_TRACEEXIT)
/// - [`PTRACE_O_TRACESYSGOOD`](Options::PTRACE_O_TRACESYSGOOD)
pub const REQUIRED_OPTIONS: Options = Options::empty()
    .union(Options::PTRACE_O_TRACEEXEC)
    .union(Options::PTRACE_O_TRACEEXIT)
    .union(Options::PTRACE_O_TRACESYSGOOD);

impl Ptracer {
    pub fn new() -> Self {
        let options = DEFAULT_OPTIONS;
        let poll_delay = DEFAULT_POLL_DELAY;
        let tracees = BTreeMap::new();

        Self { options, poll_delay, tracees }
    }

    /// Return the ptrace options applied to newly-spawned tracees.
    ///
    /// The options set _when the new tracee requests attach_ will be inherited by any
    /// auto-attached children of that process.
    pub fn traceme_options(&self) -> Options {
        self.options
    }

    /// Set the ptrace options applied to newly-spawned tracees.
    ///
    /// **NOTE:**: [`REQUIRED_OPTIONS`] are always set, even if unset in the passed value.
    ///
    /// These options are _not_ automatically applied to _manually_-attached tracees.
    /// Setting this value does not affect any existing tracees--- see [`Tracee::set_options()`].
    pub fn set_traceme_options(&mut self, options: Options) {
        self.options = options | REQUIRED_OPTIONS;
    }

    /// Return the initial tracee poll delay.
    pub fn poll_delay(&self) -> Duration {
        self.poll_delay
    }

    /// Set the initial tracee poll delay.
    pub fn set_poll_delay(&mut self, poll_delay: Duration) {
        self.poll_delay = poll_delay;
    }

    /// Resume the stopped tracee, delivering any pending signal.
    pub fn restart(&mut self, tracee: Tracee, restart: Restart) -> Result<()> {
        let Tracee { pid, pending, .. } = tracee;

        let res = match self.try_tracee_state(pid)? {
            State::Exiting => {
                // Mark PID as _tentatively_ terminated. See `prune_terminated_tracee()`.
                self.set_tracee_state(pid, State::Exited);

                // Override restart request with a detach.
                ptrace::detach(pid, pending)
            },
            _ => {
                match restart {
                    Restart::Step =>
                        ptrace::step(pid, pending),
                    Restart::Continue =>
                        ptrace::cont(pid, pending),
                    Restart::Syscall =>
                        ptrace::syscall(pid, pending),
                }
            },
        };

        res.died_if_esrch(pid)?;

        Ok(())
    }

    /// Spawn `cmd` for tracing.
    ///
    /// The command will be configured to request `PTRACE_TRACEME` after `fork()` and
    /// pre-`exec()`. The caller will use this to avoid races and missed events.
    pub fn spawn(&mut self, mut cmd: Command) -> Result<Child> {
        // On fork, request `PTRACE_TRACEME`.
        unsafe {
            cmd.pre_exec(|| ptrace::traceme().map_err(|err| io::Error::from_raw_os_error(err as i32)))
        };

        let child = cmd.spawn()?;

        // Register the tracee as having been spawned with a pre-exec `TRACEME` request.
        // This lets us interpret the `SIGTRAP` that will be issued for `execve()`, set
        // the desired trace options, &c.
        let pid = Pid::from_raw(child.id() as i32);
        self.set_tracee_state(pid, State::Spawned);

        Ok(child)
    }

    /// Attach to a running tracee. This will deliver a `SIGSTOP`.
    ///
    /// **Warning:** the tracee may not be considered stopped until it has been seen to
    /// stop via `wait()`.
    pub fn attach(&mut self, pid: Pid) -> Result<()> {
        let r = ptrace::attach(pid);
        let r = r.map_err(|source| Error::Attach { pid, source });

        self.mark_tracee(pid);

        r
    }

    // Poll tracees for a `wait(2)` status change.
    fn poll_tracees(&mut self) -> Result<Option<WaitStatus>> {
        let flags = WaitPidFlag::__WALL | WaitPidFlag::WNOHANG;

        for (tracee, state) in self.tracees.clone().into_iter() {
            let pid = Pid::from_raw(tracee);

            if state == State::Exited {
                debug!("checking for termination of exited tracee: {pid}");

                let removed = self.prune_terminated_tracee(pid)?;
                if removed {
                    // PID will be reaped on next wait(2), so don't poll it below.
                    // We want to save the status for `Child::wait()`.
                    continue;
                }
            }

            match wait::waitpid(pid, Some(flags)) {
                Ok(WaitStatus::StillAlive) => {
                    // Alive, no state change. Check remaining tracees.
                    continue;
                },
                Ok(status) => {
                    // One of our tracees changed state.
                    return Ok(Some(status));
                },
                Err(errno) if errno == Errno::ECHILD => {
                    // No more children to wait on: we're done.
                    return Ok(None)
                },
                Err(err) => {
                    // Something else went wrong.
                    return Err(err.into())
                },
            };
        }

        // No tracee changed state.
        Ok(None)
    }

    // Peek at the wait status of an exited tracee, without consuming it. If the tracee
    // is truly terminating, remove it from the set of known tracees.
    //
    // Returns `true` iff the tracee was removed from the known tracee set.
    fn prune_terminated_tracee(&mut self, pid: Pid) -> Result<bool> {
        use nix::sys::wait::Id;

        // Peek wait() status without consuming.
        let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT;
        let id = Id::Pid(pid);

        let removed = match wait::waitid(id, flags) {
            Ok(status @ (WaitStatus::Exited(..) | WaitStatus::Signaled(..))) => {
                debug!(?status, "saw termination of exited tracee");

                // The exited thread is ready to be reaped on next wait(2). We can treat it as
                // reaped, and needn't peek it for potential exec()-resurrection.
                //
                // We also must not poll it: this will consume its status and reap it, which
                // breaks `Child::wait()`. Instead, prune it from our tracee set.
                self.remove_tracee(pid);

                true
            },
            Ok(status) => {
                debug!(?status, "non-termination status for exited tracee, resetting");

                // We have a new, non-termination status. We must be in a situation like
                // an off-thread exec(), where the exec()-ing thread assumes the TID of
                // the thread group leader and seems to be resurrected.
                //
                // From the ptrace(2) manual:
                //
                //   The tracer can't assume that the tracee always ends its life by
                //   reporting WIFEXITED(status) or WIFSIGNALED(status); there are
                //   cases where this does not occur.  For example, if a thread other
                //   than thread group leader does an execve(2), it disappears; its PID
                //   will never be seen again, and any subsequent ptrace stops will be
                //   reported under the thread group leader's PID.
                //
                // This is the situation we have detected.
                //
                // Reset the state of this PID to `Running` so we'll be able to observe
                // subsequent events normally.
                self.set_tracee_state(pid, State::Running);
                false
            },
            Err(errno) if errno == Errno::ECHILD => {
                debug!("ECHILD for exited tracee, assuming killed");
                self.remove_tracee(pid);
                true
            },
            Err(errno) => {
                debug!(%errno, "non-ECHILD err for exited tracee");
                self.remove_tracee(pid);
                return Err(errno.into())
            },
        };

        Ok(removed)
    }

    /// Wait for some running tracee process to stop.
    ///
    /// If there are no tracees to wait on, returns `None`.
    pub fn wait(&mut self) -> Result<Option<Tracee>> {
        use Signal::*;

        let mut poll_delay = self.poll_delay;

        // Wait on known tracees with exponential backoff.
        let status = loop {
            if self.tracees.is_empty() {
                debug!("no tracees to wait on");

                return Ok(None);
            }

            if let Some(status) = self.poll_tracees()? {
                // A tracee changed state; examine its `wait(2)` status.
                break status;
            } else {
                trace!(tracees = self.tracees.len(), ?poll_delay, "no tracee updates, backing off");

                std::thread::sleep(poll_delay);

                // Back off before next attempt.
                poll_delay *= 2;
            }
        };

        let tracee = match status {
            WaitStatus::Exited(_pid, _exit_code) => {
                internal_error!("consumed wait status for exited tracee");
            },
            WaitStatus::Signaled(_pid, _sig, _is_core_dump) => {
                internal_error!("consumed wait status for signaled tracee");
            },
            WaitStatus::Stopped(pid, signal @ SIGTRAP) => {
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
                    let stop = Stop::SyscallExit;
                    let mut tracee = Tracee::new(pid, None, stop);

                    // Update the tracee state so subsequent traps are interpreted correctly.
                    *state = State::Running;

                    // Set global tracing options on this root tracee. Auto-attached tracees from
                    // fork, clone, and exec will inherit them.
                    tracee.set_options(self.options)?;

                    tracee
                } else {
                    let stop = Stop::SignalDelivery { signal };
                    Tracee::new(pid, signal, stop)
                }
            },
            WaitStatus::Stopped(pid, signal) => {
                if signal == SIGSTOP {
                    if let Some(state) = self.tracee_state_mut(pid) {
                        if *state == State::Attaching {
                            *state = State::Running;
                            let stop = Stop::Attach;
                            let tracee = Tracee::new(pid, None, stop);
                            return Ok(Some(tracee));
                        }
                    } else {
                        // We may see an attach-stop out-of-order, before the ptrace-event-stop
                        // which would otherwise have us mark it as `Attaching`. Since `Attaching`
                        // only exists to let us know that the next stop (i.e. this stop) is an
                        // attach-stop, we can directly initialize this tracee as `Running`.
                        self.set_tracee_state(pid, State::Running);
                        let stop = Stop::Attach;
                        let tracee = Tracee::new(pid, None, stop);
                        return Ok(Some(tracee));
                    }
                }

                let stop = if is_group_stop(pid, signal)? {
                    Stop::Group { signal }
                } else {
                    Stop::SignalDelivery { signal }
                };

                Tracee::new(pid, signal, stop)
            },
            WaitStatus::PtraceEvent(pid, signal, code) => {
                match code {
                    libc::PTRACE_EVENT_FORK => {
                        let evt_data = ptrace::getevent(pid).died_if_esrch(pid)?;
                        let new = Pid::from_raw(evt_data as u32 as i32);

                        // When we return, `new` will start as a tracee, but will be delivered a
                        // `SIGSTOP`. Mark it so we can recognize the `SIGSTOP` as an attach-stop.
                        self.mark_tracee(new);

                        let stop = Stop::Fork { new };
                        Tracee::new(pid, signal, stop)
                    },
                    libc::PTRACE_EVENT_CLONE => {
                        let evt_data = ptrace::getevent(pid).died_if_esrch(pid)?;
                        let new = Pid::from_raw(evt_data as u32 as i32);

                        // When we return, `new` will start as a tracee, but will be delivered a
                        // `SIGSTOP`. Mark it so we can recognize the `SIGSTOP` as an attach-stop.
                        self.mark_tracee(new);

                        let stop = Stop::Clone { new };
                        Tracee::new(pid, signal, stop)
                    },
                    libc::PTRACE_EVENT_EXEC => {
                        // We are in one of two cases. The exec has either occurred on the main
                        // thread of the thread group, or not. In either case, the new tid of the
                        // execing thread will be equal to the tgid. In the off-main case, this is
                        // a change, and the old state for the tid == tgid will be invalid.

                        // The current `pid` is now equal to the tgid of `old`.
                        let evt_data = ptrace::getevent(pid).died_if_esrch(pid)?;
                        let old = Pid::from_raw(evt_data as u32 as i32);

                        if old != pid {
                            // We exec'd off-thread, and previous tid state is now invalid.
                            self.remove_tracee(old);
                        }

                        // We know we are in a syscall. Make sure we can correctly label the next
                        // syscall-stop as an exit-stop.
                        //
                        // Important: if we trace all the syscall-stops, we will report the syscall-
                        // enter-stop as occurring on `old`, but its matching syscall-exit-stop as
                        // occurring on `pid`. This is correct, but might look odd.
                        self.set_tracee_state(pid, State::Syscalling);

                        let stop = Stop::Exec { old };

                        Tracee::new(pid, signal, stop)
                    },
                    libc::PTRACE_EVENT_EXIT => {
                        // In this context, `PTRACE_GETEVENTMSG` returns the pending wait status
                        // as an `unsigned long`. We are only interested in the low 16-bit word.
                        let status = ptrace::getevent(pid).died_if_esrch(pid)? as u16;

                        // Mark the tracee as exiting so we can detach on next restart.
                        self.set_tracee_state(pid, State::Exiting);

                        let stop = match ExitType::parse(status)? {
                            ExitType::Exit(exit_code) =>
                                Stop::Exiting { exit_code },
                            ExitType::Signaled(signal, core_dumped) =>
                                Stop::Signaling { signal, core_dumped },
                        };

                        Tracee::new(pid, signal, stop)
                    },
                    libc::PTRACE_EVENT_VFORK => {
                        let evt_data = ptrace::getevent(pid).died_if_esrch(pid)?;
                        let new = Pid::from_raw(evt_data as u32 as i32);
                        self.mark_tracee(new);

                        let stop = Stop::Vfork { new };

                        Tracee::new(pid, signal, stop)
                    },
                    libc::PTRACE_EVENT_VFORK_DONE => {
                        let evt_data = ptrace::getevent(pid).died_if_esrch(pid)?;
                        let new = Pid::from_raw(evt_data as u32 as i32);
                        let stop = Stop::VforkDone {new };

                        Tracee::new(pid, signal, stop)
                    },
                    libc::PTRACE_EVENT_SECCOMP => {
                        // `SECCOMP_RET_DATA`, which is the low 16 bits of an int.
                        let data = ptrace::getevent(pid).died_if_esrch(pid)? as u16;
                        let stop = Stop::Seccomp { data };

                        if let Some(state) = self.tracee_state_mut(pid) {
                            *state = State::Syscalling;
                        } else {
                            internal_error!("seccomp ptrace-event-stop for non-tracee");
                        }

                        Tracee::new(pid, signal, stop)
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
                                *state = State::Running;
                                Stop::SyscallExit
                            },
                            State::Running => {
                                *state = State::Syscalling;
                                Stop::SyscallEnter
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
                            State::Exiting => {
                                // If the tracee was in the `Exiting` state, we should have detached on
                                // the next restart request.
                                internal_error!("unexpected event for exiting tracee")
                            },
                            State::Exited => {
                                // If the tracee was in the `Exited` state, we should only poll it with
                                // `WNOWAIT` until we either observe a terminal wait status or a new ptrace
                                // event that indicates we should reset the state to `Running`.
                                internal_error!("unexpected event for exited tracee")
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
        info!(pid = pid.as_raw(), "removing tracee");
        self.tracees.remove(&pid.as_raw())
    }

    fn tracee_state(&self, pid: Pid) -> Option<State> {
        self.tracees.get(&pid.as_raw()).copied()
    }

    fn try_tracee_state(&self, pid: Pid) -> Result<State> {
        self.tracee_state(pid).ok_or_else(|| Error::Internal("no tracee state".into()))
    }

    fn set_tracee_state(&mut self, pid: Pid, state: State) {
        debug!(pid = pid.as_raw(), ?state, "setting tracee state");

        self.tracees.insert(pid.as_raw(), state);
    }

    fn tracee_state_mut(&mut self, pid: Pid) -> Option<&mut State> {
        self.tracees.get_mut(&pid.as_raw())
    }

    // Mark `pid` as a new tracee pending attach-stop, if it isn't already known.
    fn mark_tracee(&mut self, pid: Pid) {
        debug!(pid = pid.as_raw(), "marking tracee as attaching if unknown");

        if !self.tracees.contains_key(&pid.as_raw()) {
            info!(pid = pid.as_raw(), "attaching to new tracee");
        }

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
            // Possible group-stop. Check `siginfo` to disambiguate.
            //
            // From the manual:
            //
            //     If PTRACE_GETSIGINFO fails with EINVAL, then it is definitely a
            //     group-stop.  (Other failure codes are possible, such as ESRCH
            //     ("no such process") if a SIGKILL killed the tracee.)
            //
            match ptrace::getsiginfo(pid) {
                Err(Errno::EINVAL) =>
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
