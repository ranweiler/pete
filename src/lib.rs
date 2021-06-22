#[macro_use]
pub mod error;

pub mod ptracer;

#[doc(inline)]
pub use error::Error;

#[doc(inline)]
pub use ptracer::{Pid, Ptracer, Registers, Restart, Siginfo, Signal, Stop, Tracee};
