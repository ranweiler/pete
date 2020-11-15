use std::io;

use crate::ptracer::{Pid, Restart};


pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Could not attach to tracee = {pid}")]
    Attach {
        pid: Pid,
        source: nix::Error,
    },

    #[error("Could not restart tracee = {pid} with mode = {mode:?}")]
    Restart { pid: Pid, mode: Restart, source: nix::Error },

    #[error("Input/output error")]
    IO(#[from] io::Error),

    #[error("OS error")]
    OS(#[from] nix::Error),

    #[error("Internal error: please open an issue at https://github.com/ranweiler/pete/issues")]
    Internal,
}
