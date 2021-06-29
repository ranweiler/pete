/// Register used to control or query hardware debug operations and state.
///
/// Accessing debug registers directly is a privileged operation, but a tracee's debug
/// registers are accessible via the `PEEKUSER` and `POKEUSER` requests. The relevant
/// subset of possible `USER` requests are available via `Tracee::debug_register()` and
/// `Tracee::set_debug_register()`.
///
/// See: Intel SDM, Vol. 3, 17.2
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebugRegister {
    /// Debug address register 0.
    Dr0 = 0,

    /// Debug address register 1.
    Dr1,

    /// Debug address register 2.
    Dr2,

    /// Debug address register 3.
    Dr3,

    /// Reserved. Ignored when used via `ptrace(2)`.
    Dr4,

    /// Reserved. Ignored when used via `ptrace(2)`.
    Dr5,

    /// Debug status register.
    Dr6,

    /// Debug control register.
    Dr7,
}

impl DebugRegister {
    /// Return the offset into debug register array in the virtual `user` struct.
    pub(crate) fn user_offset() -> u64 {
        memoffset::offset_of!(libc::user, u_debugreg) as u64
    }
}

impl From<DebugRegister> for u64 {
    fn from(dr: DebugRegister) -> u64 {
        dr as u64
    }
}
