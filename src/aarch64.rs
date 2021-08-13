#[cfg(all(target_os = "android"))]
pub(crate) const PTRACE_GETREGSET: i32 = 0x4204;

#[cfg(all(not(target_os = "android")))]
pub(crate) const PTRACE_GETREGSET: u32 = 0x4204;

#[cfg(all(target_os = "android"))]
pub(crate) const PTRACE_SETREGSET: i32 = 0x4205;

#[cfg(all(not(target_os = "android")))]
pub(crate) const PTRACE_SETREGSET: u32 = 0x4205;

/// Defined in [`include/uapi/linux/elf.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/include/uapi/linux/elf.h#421).
const NT_ARM_HW_BREAK: i32 = 0x402;
const NT_ARM_HW_WATCH: i32 = 0x403;

pub type DebugRegisters = user_hwdebug_state;

/// Defined in [`arch/arm64/include/uapi/asm/ptrace.h`](https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/arch/arm64/include/uapi/asm/ptrace.h#88).
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct user_pt_regs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64
}

/// Nested, untagged struct declaration in `user_hwdebug_state`.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct user_hwdebug_state_reg {
    pub addr: u64,
    pub ctrl: u32,
    pad: u32,
}

#[cfg(target_arch = "aarch64")]
impl user_hwdebug_state_reg {
    pub fn new() -> Self {
        Self {
            addr: 0,
            ctrl: 0,
            pad: 0,
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[repr(i32)]
#[derive(Copy, Clone)]
pub enum DebugRegisterType {
    Break = NT_ARM_HW_BREAK,
    Watch = NT_ARM_HW_WATCH,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct user_hwdebug_state {
    pub dbg_info: u32,
    pad: u32,
    pub dbg_regs: [user_hwdebug_state_reg; 4],
}

#[cfg(target_arch = "aarch64")]
impl user_hwdebug_state {
    pub fn new() -> Self {
        Self {
            dbg_info: 0,
            pad: 0,
            dbg_regs: [user_hwdebug_state_reg::new(); 4],
        }
    }
}
