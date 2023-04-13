// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 BMC Software, Inc.
// Author Devasia Thomas <https://www.linkedin.com/in/devasiathomas/>
//
// Based on capable(8) by Brendan Gregg
use core::time::Duration;
//use std::str::FromStr;
use std::sync::Mutex;

use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::PerfBufferBuilder;
//use plain::Plain;
use std::fs;
use scopeguard::defer;
use std::path::Path;

use crate::wasm::WasmInstance;
use libbpf_rs::ObjectBuilder;


pub mod wasm;

//mod capable {
//    include!(concat!(env!("OUT_DIR"), "/capable.skel.rs"));
//}

//use capable::capable_rodata_types::uniqueness;
//use capable::*;

/*
impl FromStr for uniqueness {
    type Err = &'static str;
    fn from_str(unq_type: &str) -> Result<Self, Self::Err> {
        let unq_type_lower: &str = &unq_type.to_lowercase();
        match unq_type_lower {
            "off" => Ok(uniqueness::UNQ_OFF),
            "pid" => Ok(uniqueness::UNQ_PID),
            "cgroup" => Ok(uniqueness::UNQ_CGROUP),
            _ => Err("Use 1 for pid (default), 2 for cgroups"),
        }
    }
}
*/
/// Trace capabilities
#[derive(Debug, Copy, Clone, Parser)]
#[clap(name = "examples", about = "Usage instructions")]
struct Command {
    /// verbose: include non-audit checks
    #[clap(short, long)]
    verbose: bool,
    /// only trace `pid`
    #[clap(short, long, default_value = "0")]
    pid: u32,
    /// extra fields: Show TID and INSETID columns
    #[clap(short = 'x', long = "extra")]
    extra_fields: bool,
    /// don't repeat same info for the same `pid` or `cgroup`
    //#[clap(long = "unique", default_value = "off")]
    //unique_type: uniqueness,
    /// debug output for libbpf-rs
    #[clap(long)]
    debug: bool,
}

//unsafe impl Plain for capable_bss_types::event {}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn print_banner(extra_fields: bool) {
    #[allow(clippy::print_literal)]
    if extra_fields {
        println!(
            "{:9} {:6} {:6} {:6} {:16} {:4} {:20} {:6} {}",
            "TIME", "UID", "PID", "TID", "COMM", "CAP", "NAME", "AUDIT", "INSETID"
        );
    } else {
        println!(
            "{:9} {:6} {:6} {:16} {:4} {:20} {:6}",
            "TIME", "UID", "PID", "COMM", "CAP", "NAME", "AUDIT"
        );
    }
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<()> {

    let opts = Command::parse();

    //let obj_path = get_test_object_path("bpf/capable.bpf.o");
    let obj_path = Path::new("ebpf/src/bpf/capable.bpf.o");
    let mut builder = ObjectBuilder::default();
    if opts.debug {
        builder.debug(true);
    }
    let open_obj = builder.open_file(obj_path).expect("failed to open object");

    bump_memlock_rlimit()?;

    //Pass configuration to BPF

    //open_obj.rodata().tool_config.tgid = opts.pid; //tgid in kernel is pid in userland
    //open_obj.rodata().tool_config.verbose = opts.verbose;
    //open_obj.rodata().tool_config.unique_type = opts.unique_type;

    let mut skel = open_obj.load()?;
    let prog = skel
    .prog_mut("kprobe__cap_capable")
    .expect("failed to find program");
    println!("start attch prog in section:{}",prog.section());
    let mut link = prog.attach().expect("failed to attach prog");
    let path = "/sys/fs/bpf/kprobe__cap_capable-link";
    link.pin(path).expect("failed to pin prog");
    // Backup cleanup method in case test errors
    defer! {
        let _ = fs::remove_file(path);
    }

    print_banner(opts.extra_fields);


    let mut wasm_instance:WasmInstance<()> = WasmInstance::new();
    let handle_lock = Mutex::new(true);
    let handle_event = move |_cpu: i32, data: &[u8]| {
        let _ = handle_lock.lock();
        let mut extra_fields = 0;
        if opts.extra_fields{
            extra_fields = 1;
        }
        wasm_instance.write_data_to_wasm(data);
        wasm_instance.run(extra_fields);
        println!("{}",wasm_instance.read_from_wasm());
    };
    let map = skel.map_mut("events").expect("Failed to get perf-buffer map");

    let perf = PerfBufferBuilder::new(map)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
