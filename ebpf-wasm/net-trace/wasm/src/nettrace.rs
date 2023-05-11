#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct event {
    pub opt_type: u32,
    pub pid: u32,
    pub comm: [u8; 128],
    pub sockfd: u32,
    pub upstream_addr_v4: u32,
    pub upstream_addr_v6: [u8;16],
    pub upstream_port: u32,

    pub downstream_addr_v4: u32,
    pub downstream_addr_v6:[u8; 16],
    pub downstream_port: u32,
    pub fix: u32,
    pub exe_time: u64,
}

impl Default for event {
    fn default() -> event {
        event {
            opt_type: 0u32,
            pid: 0u32,
            comm: [0u8; 128],
            sockfd: 0u32,
            upstream_addr_v4: 0u32,
            upstream_addr_v6: [0u8;16],
            upstream_port: 0u32,

            downstream_addr_v4: 0u32,
            downstream_addr_v6:[0u8; 16],
            downstream_port: 0u32,
            fix: 0u32,
            exe_time: 0u64,
        }
    }
}