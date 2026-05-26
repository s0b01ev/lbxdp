#![no_std]

pub const MAX_BACKENDS: u32 = 4;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LBConfig {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LBConfig {}
