use core::time::Duration;
use anyhow::{bail, Result};
use std::path::Path;
use std::fs;
use std::os::fd::AsRawFd;
use std::{thread};
use scopeguard::defer;
use libbpf_rs::{Error,ObjectBuilder,MapFlags,Link,TcHookBuilder,TcHook,TC_INGRESS,TC_EGRESS};

use plain::Plain;
mod xdp_proxy;
use xdp_proxy::proxy_config_t;
mod net;
use net::get_mac;
use nix::errno::Errno::{EINVAL, ENOENT};


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

unsafe impl Plain for proxy_config_t {}

fn clear_clsact(fd: i32,index: i32) -> Result<()> {
    // Ensure clean clsact tc qdisc
    let mut destroyer = TcHook::new(fd);
    destroyer
        .ifindex(index)
        .attach_point(TC_EGRESS | TC_INGRESS);

    let res = destroyer.destroy();
    if let Err(Error::System(err)) = res {
        if err != -(ENOENT as i32) && err != -(EINVAL as i32) {
            return Ok(res?);
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let obj_path = Path::new("src/bpf/xdp-proxy.bpf.o");
    let mut builder = ObjectBuilder::default();
    builder.debug(true);
    let open_obj = builder.open_file(obj_path).expect("failed to open object");

    bump_memlock_rlimit()?;
    let mut skel = open_obj.load()?;


    let fd = skel.prog("tc_ingress").expect("get tc ingress program err").fd();
    let eth0_ifidx = nix::net::if_::if_nametoindex("eth0")? as i32;

    clear_clsact(fd,eth0_ifidx);
    //clear_clsact(fd_lo,lo_ifidx);
    let mut tc_builder = TcHookBuilder::new();
    tc_builder
        .fd(fd)
        .ifindex(eth0_ifidx)
        .replace(true)
        .handle(1)
        .priority(1);
    //clear_clsact(fd);
    let mut ingress = tc_builder.hook(TC_INGRESS);
    ingress.create();
    ingress.attach().expect("failed to attach tc ingress prog");


    let fd_lo = skel.prog("tc_ingress_lo").expect("get tc ingress lo program err").fd();
    let lo_ifidx = nix::net::if_::if_nametoindex("eth0")? as i32;

    let mut tc_lo_builder = TcHookBuilder::new();
    tc_lo_builder
        .fd(fd_lo)
        .ifindex(lo_ifidx)
        .replace(true)
        .handle(1)
        .priority(1);
    //clear_clsact(fd);
    let mut egress_lo = tc_lo_builder.hook(TC_EGRESS);
    egress_lo.create();
    egress_lo.attach().expect("failed to attach tc lo egress prog");







    let progs = skel.progs_iter_mut();

    let mut prognames:Vec<Link> = vec![];
    for prog in progs {
        //if prog.name() =="xdp_redirect"{
        //    let lo_ifidx = nix::net::if_::if_nametoindex("lo")? as i32;
        //    let link = prog.attach_xdp(lo_ifidx).expect("failed to attach xdp_redirect prog");
        //    prognames.push(link);
        //}

        //if prog.name() =="xdp_proxy"{
        //    let eth0_ifidx = nix::net::if_::if_nametoindex("eth0")? as i32;
        //    let link = prog.attach_xdp(eth0_ifidx).expect("failed to attach xdp_proxy prog");
        //    prognames.push(link);
        //}


        if prog.name() == "kprobe_tcp_recvmsg"{
            let link = prog.attach().expect("failed to attach recvmsg");
            prognames.push(link);
        }
        if prog.name() == "kprobe_sock_sendmsg"{
            let link = prog.attach().expect("failed to attach recvmsg");
            prognames.push(link);
        }
        if prog.name() == "tracepoint_skb_kfree_skb"{
            let link = prog.attach().expect("failed to attach tracepoint_skb_kfree_skb");
            prognames.push(link);
        }

        if prog.name() == "kprobe_sk_receive_skb"{
            let link = prog.attach().expect("failed to attach kprobe_sk_receive_skb");
            prognames.push(link);
        }

        if prog.name() == "kprobe_netif_rx"{
            let link = prog.attach().expect("failed to attach kprobe_netif_rx");
            prognames.push(link);
        }

        if prog.name() == "kprobe_ip_rcv"{
            let link = prog.attach().expect("failed to attach kprobe_ip_rcv");
            prognames.push(link);
        }

        if prog.name() == "kprobe_tcp_rcv"{
            let link = prog.attach().expect("failed to attach kprobe_tcp_rcv");
            prognames.push(link);
        }

        if prog.name() == "bpf_sockmap"{
            let path = Path::new("/sys/fs/cgroup/");
            let cgroup_file = std::fs::OpenOptions::new().read(true).open(path).expect("fail get cgroup file");
            let fd = cgroup_file.as_raw_fd();
            let link = prog.attach_cgroup(fd).expect("failed to attach bpf_sockmap");
            prognames.push(link);
        }

    }

    let eth0_if = nix::net::if_::if_nametoindex("eth0")? as u32;
    let lo_if = nix::net::if_::if_nametoindex("lo")? as u32;

    let map = skel.map_mut("proxy_config_map").expect("Failed to get proxy config map");
    let key = (0 as u64).to_ne_bytes();
    let config= &proxy_config_t {
        loadbalancer_port: 5000u16,
        loadbalancer_ip: 0x20011acu32,
        endpoint_ip: 0x20011acu32,
        endpoint_port: 80u16,
        ifindex: eth0_if,
        lo_ifindex: lo_if,
    };
    unsafe {
        let val = plain::as_bytes(config);
        map.update(&key, val, MapFlags::ANY).expect("Failed to update proxy config map");
    }

    loop {
        thread::sleep(Duration::from_millis(100));
    }
}