/// Debug registers are used to control and query processor debug operations and state.
/// Accessing them directly is a privileged operation, but a tracee's debug registers are
/// accessible via the `PEEKUSER` and `POKEUSER` requests. The debug-relevant subset of
/// possible `USER` requests are available via `Tracee::debug_register()` and
/// `Tracee::set_debug_register()`.
///
/// See: Intel SDM, Vol. 3, 17.2
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebugRegister {
    // Debug address registers.
    Dr0 = 0,
    Dr1,
    Dr2,
    Dr3,

    // Reserved. Use causes invalid opcode exception.
    Dr4,
    Dr5,

    // Debug status register.
    Dr6,

    // Debug control register.
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
