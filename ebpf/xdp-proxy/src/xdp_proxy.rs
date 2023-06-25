#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct proxy_config_t {
   // pub client_ip: u32,
    pub loadbalancer_port: u16,
    pub loadbalancer_ip: u32,
    pub endpoint_ip: u32,
    pub endpoint_port: u16,
    pub ifindex: u32,
    pub lo_ifindex: u32,

}

impl Default for proxy_config_t {
    fn default() -> proxy_config_t {
        proxy_config_t {
            loadbalancer_port: 0u16,
            loadbalancer_ip: 0u32,
            endpoint_ip: 0u32,
            endpoint_port: 0u16,
            ifindex: 0u32,
            lo_ifindex: 0u32,
        }
    }
}