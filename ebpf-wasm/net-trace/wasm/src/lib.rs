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

unsafe impl Plain for event {}
unsafe impl Plain for sock_drop_event {}
unsafe impl Plain for tcp_retransmit_event {}

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

static TCPSTATE: phf::Map<u8, &'static str> = phf_map! {
    1u8 => "ESTABLISHED",
    2u8 => "SYN_SENT",
    3u8 => "SYN_RECV",
    4u8 => "FIN_WAIT1",
    5u8 => "FIN_WAIT2",
    6u8 => "TIME_WAIT",
    7u8 => "CLOSE",
    8u8 => "CLOSE_WAIT",
    9u8 => "LAST_ACK",
    10u8 => "LISTEN",
    11u8 => "CLOSING",
    12u8 => "NEW_SYN_RECV",
};

/*static SKB_DROP_REASON: phf::Map<u32, &'static str> = phf_map! {
	0u32 => "SKB_DROP_REASON_NOT_SPECIFIED",
	1u32 => "SKB_DROP_REASON_NO_SOCKET",
	2u32 => "SKB_DROP_REASON_PKT_TOO_SMALL",
	3u32 => "SKB_DROP_REASON_TCP_CSUM",
	4u32 => "SKB_DROP_REASON_SOCKET_FILTER",
	5u32 => "SKB_DROP_REASON_UDP_CSUM",
	6u32 => "SKB_DROP_REASON_NETFILTER_DROP",
	7u32 => "SKB_DROP_REASON_OTHERHOST",
	8u32 => "SKB_DROP_REASON_IP_CSUM",
	9u32 => "SKB_DROP_REASON_IP_INHDR",
	10u32 => "SKB_DROP_REASON_IP_RPFILTER",
	11u32 => "SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST",
	12u32 => "SKB_DROP_REASON_MAX",
};*/
static IPPROTO: phf::Map<u16, &'static str> = phf_map! {
	0u16 => "IPPROTO_IP",
	1u16 => "IPPROTO_ICMP",
	2u16 => "IPPROTO_IGMP",
	4u16 => "IPPROTO_IPIP",
	6u16 => "IPPROTO_TCP",
	8u16 => "IPPROTO_EGP",
	12u16 => "IPPROTO_PUP",
	17u16 => "IPPROTO_UDP",
	22u16 => "IPPROTO_IDP",
	29u16 => "IPPROTO_TP",
	33u16 => "IPPROTO_DCCP",
	41u16 => "IPPROTO_IPV6",
	46u16 => "IPPROTO_RSVP",
	47u16 => "IPPROTO_GRE" ,
	50u16 => "IPPROTO_ESP",
	51u16 => "IPPROTO_AH",
	92u16 => "IPPROTO_MTP",
	94u16 => "IPPROTO_BEETPH",
	98u16 => "IPPROTO_ENCAP",
	103u16 => "IPPROTO_PIM",
	108u16 => "IPPROTO_COMP",
	132u16 => "IPPROTO_SCTP",
	136u16 => "IPPROTO_UDPLITE",
	137u16 => "IPPROTO_MPLS",
	143u16 => "IPPROTO_ETHERNET",
	255u16 => "IPPROTO_RAW",
	262u16 => "IPPROTO_MPTCP",
	263u16 => "IPPROTO_MAX",
};
static FAMILY: phf::Map<u32, &'static str> = phf_map! {
	2u32 => "IPV4",
	10u32 => "IPV6",
};
static FAMILY16: phf::Map<u16, &'static str> = phf_map! {
	2u16 => "IPV4",
	10u16 => "IPV6",
};
static RETRANSTYPE: phf::Map<u32, &'static str> = phf_map! {
	0u32 => "skb",
	1u32 => "synack",
};





#[no_mangle]
pub unsafe extern "C" fn run_handler(handle_type: i32){

    let mut read = READ_BUF.lock().unwrap();
    let write = WRITE_BUF.lock().unwrap().to_owned();

    if handle_type == 0{
        let mut event = event::default();
        plain::copy_from_bytes(&mut event, &write).expect("Data buffer was too short");
        let output_str = _handle_event(event);
        *read = output_str;
    }

    if handle_type == 1{
        let mut event = sock_drop_event::default();
        plain::copy_from_bytes(&mut event, &write).expect("Data buffer was too short");
        let output_str = _handle_drop_event(event);
        *read = output_str;
    }

    if handle_type == 2{
        let mut event = tcp_retransmit_event::default();
        plain::copy_from_bytes(&mut event, &write).expect("Data buffer was too short");
        let output_str = _handle_retransmit_event(event);
        *read = output_str;
    }
}

fn is_private_addr(ipaddr: String)->bool {
    PRIVATE_CIDR.contains(Ipv4Addr::from_str(&ipaddr).unwrap())
}

fn _handle_event(event: event) -> String{

    let now = SystemTime::now();
    let now: DateTime<Local> = now.into();
    let now = now.format("%H:%M:%S").to_string();

    let comm_str = std::str::from_utf8(&event.comm)
        .expect("Failed to get comm_str")
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
    let upstream_addr_v6 = format!("{}",Ipv6Addr::from(event.upstream_addr_v6));
    let downstream_addr_v6 = format!("{}",Ipv6Addr::from(event.downstream_addr_v6));

    return format!(
        "public-network: time-{:#?} pid-{:<6} comm-{:<32} type-{:<20} upstream-v4-{:<15} downstream-v4-{:<15} upstream-v6-{:<32} downstream-v6-{:<32}",
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

fn _handle_drop_event(event: sock_drop_event) -> String{

    let now = SystemTime::now();
    let now: DateTime<Local> = now.into();
    let now = now.format("%H:%M:%S").to_string();

    let comm_str = std::str::from_utf8(&event.comm)
        .expect("Failed to get comm_str")
        .trim_end_matches(char::from(0));
    /*let reason = match SKB_DROP_REASON.get(&event.reason) {
        Some(&x) => x,
        None => "?",
    };*/
    let proto = match IPPROTO.get(&event.ip_proto) {
        Some(&x) => x,
        None => "?",
    };

    let family = match FAMILY.get(&event.socket_family) {
        Some(&x) => x,
        None => "?",
    };

    if family == "IPV4"{
        let saddr_v4 = format!("{}",Ipv4Addr::from(u32::from_be(event.saddr_v4)));
        let daddr_v4 = format!("{}",Ipv4Addr::from(u32::from_be(event.daddr_v4)));
        if saddr_v4 != "0.0.0.0" && daddr_v4 != "0.0.0.0"{
            return format!(
                "socket-drop: time-{:#?} pid-{:<6} comm-{:<32} saddr-v4-{:<15} daddr-v4-{:<15}",
                now,
                event.pid,
                comm_str,
                saddr_v4,
                daddr_v4,
            )
        }
    } else if family == "IPV6" {
        let saddr_v6 = format!("{}",Ipv6Addr::from(event.saddr_v6));
        let daddr_v6 = format!("{}",Ipv6Addr::from(event.daddr_v6));
        if saddr_v6 != "::" && daddr_v6 != "::"{
            return format!(
                "socket-drop: time-{:#?} pid-{:<6} comm-{:<32} saddr-v6-{:<32} daddr-v6-{:<32}",
                now,
                event.pid,
                comm_str,
                saddr_v6,
                daddr_v6,
            )
        }
    }
    return format!(
        "无效地址"
    )
}

fn _handle_retransmit_event(event: tcp_retransmit_event) -> String{

    let now = SystemTime::now();
    let now: DateTime<Local> = now.into();
    let now = now.format("%H:%M:%S").to_string();

    let comm_str = std::str::from_utf8(&event.comm)
        .expect("Failed to get comm_str")
        .trim_end_matches(char::from(0));

    let family = match FAMILY16.get(&event.family) {
        Some(&x) => x,
        None => "?",
    };
    let state = match TCPSTATE.get(&event.state) {
        Some(&x) => x,
        None => "?",
    };

    if family == "IPV4"{
        let saddr_v4 = format!("{}",Ipv4Addr::from(event.saddr_v4));
        let daddr_v4 = format!("{}",Ipv4Addr::from(event.daddr_v4));
        return format!(
            "tcp-retransmit: time-{:#?} pid-{:<6} comm-{:<32} saddr-v4-{:<15} sport-{:<6} daddr-v4-{:<15} dport-{:<6} state-{:<13}",
            now,
            event.pid,
            comm_str,
            saddr_v4,
            event.sport,
            daddr_v4,
            event.dport,
            state,
        )
    } else if family == "IPV6" {
        let saddr_v6 = format!("{}",Ipv6Addr::from(event.saddr_v6));
        let daddr_v6 = format!("{}",Ipv6Addr::from(event.daddr_v6));
        return format!(
            "tcp-retransmit: time-{:#?} pid-{:<6} comm-{:<32} saddr-v6-{:<32} sport-{:<6} daddr-v6-{:<32} dport-{:<6} state-{:<13}",
            now,
            event.pid,
            comm_str,
            saddr_v6,
            event.sport,
            daddr_v6,
            event.dport,
            state,
        )
    }
    let saddr_v4 = format!("{}",Ipv4Addr::from(event.saddr_v4));
    let daddr_v4 = format!("{}",Ipv4Addr::from(event.daddr_v4));

    let saddr_v6 = format!("{}",Ipv6Addr::from(event.saddr_v6));
    let daddr_v6 = format!("{}",Ipv6Addr::from(event.daddr_v6));
    return format!(
        "tcp-retransmit: time-{:#?} pid-{:<6} comm-{:<32} family-{:<4} saddr-v4-{:<15} daddr-v4-{:<15} saddr-v6-{:<32} daddr-v6-{:<32} state-{:<13}",
        now,
        event.pid,
        comm_str,
        family,
        saddr_v4,
        daddr_v4,
        saddr_v6,
        daddr_v6,
        state,
    )
}