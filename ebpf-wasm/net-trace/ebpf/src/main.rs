use core::time::Duration;
use std::sync::Mutex;

use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{PerfBufferBuilder,PerfBuffer,MapType};
use std::fs;
use scopeguard::defer;
use std::path::Path;

use crate::wasm::WasmInstance;
use libbpf_rs::{ObjectBuilder,Link};


pub mod wasm;

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

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<()> {

    bump_memlock_rlimit()?;
    let opts = Command::parse();

    let obj_path = Path::new("ebpf/src/bpf/nettrace.bpf.o");

    let mut builder = ObjectBuilder::default();
    if opts.debug {
        builder.debug(true);
    }
    let open_obj = builder.open_file(obj_path).expect("failed to open object");



    let mut obj = open_obj.load().expect("Failed to load object");
    let progs = obj.progs_iter_mut();
    

    let mut prognames:Vec<Link> = vec![];
   
    for prog in progs {

        println!("start attch prog in section:{}",prog.section());
        let link = prog.attach().expect("failed to attach prog");

        prognames.push(link);
    }

    let map = obj.map("socket_opts_events_queue").expect("Failed to get perf-buffer map");
    println!("get perf event map:{}",map.name());
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
        let res = wasm_instance.read_from_wasm();
        if !res.starts_with("内网访问地址") {
            println!("{}",res);
        }
    };

    println!("push perf event map:{}",map.name());
    let perf = PerfBufferBuilder::new(map)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build().expect("Failed to build");

    println!("poll for perf events buffer");
    loop{
        perf.poll(Duration::from_millis(100)).expect("Failed to poll ringbuf");
    }

}