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
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct sock_drop_event {
    pub pid: u32,
    pub socket_family: u32,
    pub ip_proto: u16,
    pub comm: [u8; 128],
    pub sport: u16,
    pub dport: u16,
    pub saddr_v4: u32,
    pub daddr_v4: u32,
    pub saddr_v6: [u8;16],
    pub daddr_v6: [u8;16],
	pub reason: u32,
}

impl Default for sock_drop_event {
    fn default() -> sock_drop_event {
        sock_drop_event {
            pid: 0u32,
            socket_family: 0u32,
            ip_proto: 0u16,
            comm: [0u8; 128],
            sport: 0u16,
            dport: 0u16,
            saddr_v4: 0u32,
            daddr_v4: 0u32,
            saddr_v6: [0u8;16],
            daddr_v6: [0u8;16],
            reason: 0u32,
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct tcp_retransmit_event {
    pub retran_type: u32,
    pub pid: u32,
    pub comm: [u8; 128],
    pub family: u16,
    pub sport: u16,
    pub dport: u16,
    pub saddr_v4: [u8;4],
    pub daddr_v4: [u8;4],
    pub saddr_v6: [u8;16],
    pub daddr_v6: [u8;16],
    pub state: u8,
}

impl Default for tcp_retransmit_event  {
    fn default() -> tcp_retransmit_event{
        tcp_retransmit_event {
            retran_type: 0u32,
            pid: 0u32,
            comm: [0u8; 128],
            family: 0u16,
            sport: 0u16,
            dport: 0u16,
            saddr_v4: [0u8;4],
            daddr_v4: [0u8;4],
            saddr_v6: [0u8;16],
            daddr_v6: [0u8;16],
            state: 0u8,
        }
    }
}