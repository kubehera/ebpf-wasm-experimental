use lazy_static::lazy_static;
use std::sync::Mutex;

use std::time::SystemTime;
use chrono::{DateTime, Local};

use plain::Plain;
use phf::phf_map;

mod capable;

use capable::*;

lazy_static! {
    static ref READ_BUF: Mutex<String> = Mutex::new(String::from("Hello, world!"));
    static ref WRITE_BUF: Mutex<Vec<u8>> = Mutex::new(vec![0u8;0]);
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

static CAPS: phf::Map<i32, &'static str> = phf_map! {
    0i32 => "CAP_CHOWN",
    1i32 => "CAP_DAC_OVERRIDE",
    2i32 => "CAP_DAC_READ_SEARCH",
    3i32 => "CAP_FOWNER",
    4i32 => "CAP_FSETID",
    5i32 => "CAP_KILL",
    6i32 => "CAP_SETGID",
    7i32 => "CAP_SETUID",
    8i32 => "CAP_SETPCAP",
    9i32 => "CAP_LINUX_IMMUTABLE",
    10i32 => "CAP_NET_BIND_SERVICE",
    11i32 => "CAP_NET_BROADCAST",
    12i32 => "CAP_NET_ADMIN",
    13i32 => "CAP_NET_RAW",
    14i32 => "CAP_IPC_LOCK",
    15i32 => "CAP_IPC_OWNER",
    16i32 => "CAP_SYS_MODULE",
    17i32 => "CAP_SYS_RAWIO",
    18i32 => "CAP_SYS_CHROOT",
    19i32 => "CAP_SYS_PTRACE",
    20i32 => "CAP_SYS_PACCT",
    21i32 => "CAP_SYS_ADMIN",
    22i32 => "CAP_SYS_BOOT",
    23i32 => "CAP_SYS_NICE",
    24i32 => "CAP_SYS_RESOURCE",
    25i32 => "CAP_SYS_TIME",
    26i32 => "CAP_SYS_TTY_CONFIG",
    27i32 => "CAP_MKNOD",
    28i32 => "CAP_LEASE",
    29i32 => "CAP_AUDIT_WRITE",
    30i32 => "CAP_AUDIT_CONTROL",
    31i32 => "CAP_SETFCAP",
    32i32 => "CAP_MAC_OVERRIDE",
    33i32 => "CAP_MAC_ADMIN",
    34i32 => "CAP_SYSLOG",
    35i32 => "CAP_WAKE_ALARM",
    36i32 => "CAP_BLOCK_SUSPEND",
    37i32 => "CAP_AUDIT_READ",
    38i32 => "CAP_PERFMON",
    39i32 => "CAP_BPF",
    40i32 => "CAP_CHECKPOINT_RESTORE",
};

unsafe impl Plain for capable_bss_types::event {}

#[no_mangle]
pub unsafe extern "C" fn run_handler(extra_fields: bool){

    let mut read = READ_BUF.lock().unwrap();
    let write = WRITE_BUF.lock().unwrap().to_owned();

    let mut event = capable_bss_types::event::default();
    plain::copy_from_bytes(&mut event, &write).expect("Data buffer was too short");
    let output_str = _handle_event(extra_fields, event);
    *read = output_str;
}

fn _handle_event(extra_fields: bool, event: capable_bss_types::event) -> String{

    //let now = Local::now().format("%H:%m:%S").to_string();
    let now = SystemTime::now();
    let now: DateTime<Local> = now.into();
    let now = now.format("%H:%M:%S").to_string();

    let comm_str = std::str::from_utf8(&event.comm)
        .unwrap()
        .trim_end_matches(char::from(0));
    let cap_name = match CAPS.get(&event.cap) {
        Some(&x) => x,
        None => "?",
    };
    if extra_fields {
        return format!(
            "{:#?} {:6} {:<6} {:<6} {:<16} {:<4} {:<20} {:<6} {}",
            now,
            event.uid,
            event.tgid,
            event.pid,
            comm_str,
            event.cap,
            cap_name,
            event.audit,
            event.insetid
        )
    }
    return format!(
        "{:#?} {:6} {:<6} {:<16} {:<4} {:<20} {:<6}",
        now, event.uid, event.tgid, comm_str, event.cap, cap_name, event.audit
    )
}