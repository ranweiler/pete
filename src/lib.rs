//! A friendly wrapper around the Linux `ptrace(2)` system call.
//!
//! The `ptrace(2)` interface entails interpreting a series of `wait(2)` statuses. The context used
//! to interpret a status includes the attach options set on each tracee, previously-seen stops,
//! recent `ptrace` requests, and in some cases, extra event data that must be queried using
//! additional `ptrace` calls.
//!
//! Pete is meant to instead permit reasoning directly about ptrace-stops, as described in the
//! manual. We hide the lowest-level contextual bookkeeping required to disambiguate
//! [ptrace-stops](ptracer::Stop). Whenever we can, we avoid extraneous ptrace calls, deferring to
//! downstream tracers implemented on top of the library. For example, Pete can distinguish a
//! syscall-enter-stop and syscall-exit-stop, but does not _automatically_ query register state to
//! identify the specific syscall.

#[macro_use]
pub mod error;

pub mod ptracer;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub mod x86;

#[doc(inline)]
pub use error::Error;

#[doc(inline)]
pub use ptracer::{Options, Pid, Ptracer, Restart, Siginfo, Signal, Stop, Tracee};

#[cfg(target_arch = "x86_64")]
#[doc(inline)]
pub use ptracer::Registers;
