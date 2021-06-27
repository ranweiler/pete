#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebugRegister {
    Dr0 = 0,
    Dr1,
    Dr2,
    Dr3,
    Dr4,
    Dr5,
    Dr6,
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
