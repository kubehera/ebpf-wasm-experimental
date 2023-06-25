use libarp::{client::ArpClient,interfaces::MacAddr};
use std::net::Ipv4Addr;
use std::io::Error;

pub fn get_mac(ip_addr: Ipv4Addr) -> Result<MacAddr, Error> {
    let mut client = ArpClient::new().unwrap();
    client.ip_to_mac(ip_addr, None)
}