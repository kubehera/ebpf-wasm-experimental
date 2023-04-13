use core::time::Duration;
use anyhow::{bail, Result};
use std::path::Path;
use std::fs;
use scopeguard::defer;
use libbpf_rs::PerfBufferBuilder;
use libbpf_rs::ObjectBuilder;

use plain::Plain;
mod execsnoop_h;
use execsnoop_h::event;

unsafe impl Plain for event {}
/*impl Default for [u8;7680] {
    fn default() -> Self {
        vec![0u8,7680]
    }
}*/


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

fn print_banner() {
    #[allow(clippy::print_literal)]
    println!(
        "{:16} {:6} {:3} {:1}",
        "COMM", "PID", "RET", "ARGS"
    );
}

fn _handle_event(event: event) {
    /*
    let mut wasm_instance:WasmInstance<()> = WasmInstance::new();

    let mut extra_fields = 0;
    if opts.extra_fields{
        extra_fields = 1;
    }

    wasm_instance.write_data_to_wasm(data);
    wasm_instance.run(extra_fields);
    println!("{}",wasm_instance.read_from_wasm()); */
    println!(
        "{} {:#?} {:#?}",
        std::str::from_utf8(&event.comm).unwrap(),event.pid,event.retval
    )
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}
fn main() -> Result<()> {
    let obj_path = Path::new("src/bpf/execsnoop.bpf.o");
    let mut builder = ObjectBuilder::default();
    builder.debug(true);
    let open_obj = builder.open_file(obj_path).expect("failed to open object");

    bump_memlock_rlimit()?;
    let mut skel = open_obj.load()?;
    let prog_exit = skel
    .prog_mut("tracepoint__syscalls__sys_exit_execve")
    .expect("failed to find program");

    println!("start attch prog in section:{}",prog_exit.section());
    let mut link = prog_exit.attach().expect("failed to attach prog");
    let path = "/sys/fs/bpf/exit-link";
    link.pin(path).expect("failed to pin prog");
    // Backup cleanup method in case test errors
    defer! {
        let _ = fs::remove_file(path);
    }

    let prog_enter = skel
    .prog_mut("tracepoint__syscalls__sys_enter_execve")
    .expect("failed to find program");
    println!("start attch prog in section:{}",prog_enter.section());
    let mut link = prog_enter.attach().expect("failed to attach prog");
    let path = "/sys/fs/bpf/enter-link";
    link.pin(path).expect("failed to pin prog");
    // Backup cleanup method in case test errors
    defer! {
        let _ = fs::remove_file(path);
    }

    print_banner();
    let handle_event = move |_cpu: i32, data: &[u8]| {
        //println!("{:#?}",data);
        let mut event:event = event::default();
        plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
        _handle_event(event);
        //_handle_event(opts, data);
    };
    /*
    for val in  skel.maps_iter() {
        println!("{:#?}",val);
    }*/
    let map = skel.map_mut("events").expect("Failed to get perf-buffer map");

   
    let perf = PerfBufferBuilder::new(map)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}