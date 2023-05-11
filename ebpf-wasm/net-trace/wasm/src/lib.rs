use lazy_static::lazy_static;
use std::sync::Mutex;
use std::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use cidr_utils::cidr::Ipv4Cidr;
use cidr_utils::utils::Ipv4CidrCombiner;

use std::time::SystemTime;
use chrono::{DateTime, Local};

use plain::Plain;
use phf::phf_map;

mod nettrace;

use nettrace::*;

lazy_static! {
    static ref READ_BUF: Mutex<String> = Mutex::new(String::from("Hello, world!"));
    static ref WRITE_BUF: Mutex<Vec<u8>> = Mutex::new(vec![0u8;0]);
    static ref PRIVATE_CIDR:Ipv4CidrCombiner = init_private_cidr();
}

fn init_private_cidr() -> Ipv4CidrCombiner{
    let mut private_cidr:Ipv4CidrCombiner = Ipv4CidrCombiner::new();
    private_cidr.push(Ipv4Cidr::from_str("10.0.0.0/8").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("172.16.0.0/12").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("192.168.0.0/16").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("0.0.0.0/8").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("100.64.0.0/10").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("127.0.0.0/8").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("169.254.0.0/16").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("192.0.0.0/24").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("192.0.2.0/24").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("198.18.0.0/15").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("198.51.100.0/24").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("203.0.113.0/24").unwrap());
    private_cidr.push(Ipv4Cidr::from_str("255.255.255.255/32").unwrap());

    return private_cidr
}

#[no_mangle]
pub unsafe extern fn init_write(len: usize) -> *const u8 {
    let mut write = WRITE_BUF.lock().unwrap();
    *write=Vec::with_capacity(len);
    write.set_len(len);
    write.as_ptr()
}

#[no_mangle]
pub extern fn get_string() -> *const u8{
    let read = READ_BUF.lock().unwrap();
    return read.as_ptr()
}
#[no_mangle]
pub extern fn get_string_len() -> usize{
    let read = READ_BUF.lock().unwrap();
    let binding = read.to_owned();
    let bytes = binding.as_bytes();
    return bytes.len()
}

static OPTTYPES: phf::Map<u32, &'static str> = phf_map! {
    1u32 => "SOCKET_OPTS_TYPE_CONNECT",
    2u32 => "SOCKET_OPTS_TYPE_ACCEPT",
    3u32 => "SOCKET_OPTS_TYPE_CLOSE",
};

unsafe impl Plain for event {}

#[no_mangle]
pub unsafe extern "C" fn run_handler(extra_fields: bool){

    let mut read = READ_BUF.lock().unwrap();
    let write = WRITE_BUF.lock().unwrap().to_owned();

    let mut event = event::default();
    plain::copy_from_bytes(&mut event, &write).expect("Data buffer was too short");
    let output_str = _handle_event(extra_fields, event);
    *read = output_str;
}

fn is_private_addr(ipaddr: String)->bool {
    PRIVATE_CIDR.contains(Ipv4Addr::from_str(&ipaddr).unwrap())
}

fn _handle_event(extra_fields: bool, event: event) -> String{

    let now = SystemTime::now();
    let now: DateTime<Local> = now.into();
    let now = now.format("%H:%M:%S").to_string();

    let comm_str = std::str::from_utf8(&event.comm)
        .unwrap()
        .trim_end_matches(char::from(0));
    let opttype_name = match OPTTYPES.get(&event.opt_type) {
        Some(&x) => x,
        None => "?",
    };


    let upstream_addr_v4 = format!("{}",Ipv4Addr::from(u32::from_be(event.upstream_addr_v4)));
    let downstream_addr_v4 = format!("{}",Ipv4Addr::from(u32::from_be(event.downstream_addr_v4)));

    if is_private_addr(upstream_addr_v4.clone()) && is_private_addr(downstream_addr_v4.clone()){
        return format!("内网访问地址: upstream-{} downstream-{}", upstream_addr_v4.clone(), downstream_addr_v4.clone())
    }
    let upstream_addr_v6 = std::str::from_utf8(&event.upstream_addr_v6)
        .unwrap()
        .trim_end_matches(char::from(0));
    let downstream_addr_v6 = std::str::from_utf8(&event.downstream_addr_v6)
        .unwrap()
        .trim_end_matches(char::from(0));

    return format!(
        "time-{:#?} pid-{:<6} comm-{:<16} type-{:<20} upstream-v4-{:<15} downstream-v4-{:<15} upstream-v6-{:<16} downstream-v6-{:<16}",
        now,
        event.pid,
        comm_str,
        opttype_name,
        upstream_addr_v4,
        downstream_addr_v4,
        upstream_addr_v6,
        downstream_addr_v6,
    )
}