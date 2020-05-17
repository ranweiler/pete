use crate::ptracer::{Pid, Restart};


pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Could not attach to tracee = {pid}")]
    Attach {
        pid: Pid,
        source: nix::Error,
    },

    #[error("Error waiting for new status from tracees")]
    Wait { source: nix::Error },

    #[error("Could not restart tracee = {pid} with mode = {mode:?}")]
    Restart { pid: Pid, mode: Restart, source: nix::Error },

    #[error("Unexpected internal error")]
    Internal(#[from] nix::Error),
}
