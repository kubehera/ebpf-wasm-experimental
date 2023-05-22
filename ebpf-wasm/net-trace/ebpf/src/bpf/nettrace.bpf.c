#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include "nettrace.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

static __always_inline void submit_new_connection(struct pt_regs* ctx, __u32 from_type, __u32 tgid, __u32 fd, __u64 start_nacs,
                                            struct sockaddr* addr, const struct socket* socket) {
    __u64 curr_nacs = bpf_ktime_get_ns();
    // active connection save
    struct active_connection_t con = {};
    con.pid = tgid;
    bpf_get_current_comm(&con.comm, sizeof(con.comm));
    con.sockfd = fd;
    con.role = CONNECTION_ROLE_TYPE_CLIENT;
    __u16 port;
    if (socket != NULL) {
        // only get from accept function(server side)
        struct sock* s;
        BPF_CORE_READ_INTO(&s, socket, sk);

        short unsigned int skc_family;
        BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
        con.socket_family = skc_family;
        if (con.socket_family == AF_INET) {
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
            con.upstream_port = port;
            BPF_CORE_READ_INTO(&con.upstream_addr_v4, s, __sk_common.skc_rcv_saddr);
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
            con.downstream_port = port;
            BPF_CORE_READ_INTO(&con.downstream_addr_v4, s, __sk_common.skc_daddr);
        } else if (con.socket_family == AF_INET6) {
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
            con.upstream_port = port;
            BPF_CORE_READ_INTO(&con.upstream_addr_v6, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
            con.downstream_port = port;
            BPF_CORE_READ_INTO(&con.downstream_addr_v6, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
       }
    } else if (addr != NULL) {
        con.socket_family = _(addr->sa_family);
        if (con.socket_family == AF_INET) {
            struct sockaddr_in *daddr = (struct sockaddr_in *)addr;
            bpf_probe_read(&con.upstream_addr_v4, sizeof(con.upstream_addr_v4), &daddr->sin_addr.s_addr);
            bpf_probe_read(&port, sizeof(con.upstream_port), &daddr->sin_port);
            con.upstream_port = port;
        } else if (con.socket_family == AF_INET6) {
            struct sockaddr_in6 *daddr = (struct sockaddr_in6 *)addr;
            bpf_probe_read(&con.upstream_addr_v6, sizeof(con.upstream_addr_v6), &daddr->sin6_addr);
            bpf_probe_read(&port, sizeof(con.upstream_port), &daddr->sin6_port);
            con.upstream_port = port;
        }
    }
    __u64 conid = gen_tgid_fd(tgid, fd);
    bpf_map_update_elem(&active_connection_map, &conid, &con, 0);

    if (con.socket_family != AF_INET && con.socket_family != AF_INET6) {
        return;
    }

    // event send/
    struct sock_opts_event opts_event = {};
    opts_event.type = from_type;
    opts_event.pid = tgid;
    bpf_get_current_comm(&opts_event.comm, sizeof(opts_event.comm));
    opts_event.sockfd = fd;
    opts_event.upstream_addr_v4 = con.upstream_addr_v4;
    memcpy(opts_event.upstream_addr_v6, con.upstream_addr_v6, 16*sizeof(__u8));
    opts_event.upstream_port = con.upstream_port;
    opts_event.downstream_addr_v4 = con.downstream_addr_v4;
    memcpy(opts_event.downstream_addr_v6, con.downstream_addr_v6, 16*sizeof(__u8));
    opts_event.downstream_port = con.downstream_port;
    opts_event.exe_time = curr_nacs - start_nacs;

    bpf_perf_event_output(ctx, &socket_opts_events_queue, BPF_F_CURRENT_CPU, &opts_event, sizeof(opts_event));

}

static __inline void process_connect(struct pt_regs* ctx, __u64 id, struct connect_args_t *connect_args) {
    int ret = PT_REGS_RC(ctx);
    if (ret < 0 && ret != -EINPROGRESS) {
        return;
    }
    if (connect_args->fd < 0) {
        return;
    }
    __u32 tgid = id >> 32;

    struct sock *sock = connect_args->sock;
    struct socket *s = _(sock->sk_socket);
    submit_new_connection(ctx, SOCKET_OPTS_TYPE_CONNECT, tgid, connect_args->fd, connect_args->start_nacs, connect_args->addr, s);
}

SEC("kprobe/__sys_connect")
int sys_connect(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct connect_args_t connect_args = {};
    connect_args.fd = PT_REGS_PARM1(ctx);
    connect_args.addr = (void *)PT_REGS_PARM2(ctx);
    connect_args.start_nacs = bpf_ktime_get_ns();
    bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
	return 0;
}

SEC("kretprobe/__sys_connect")
int sys_connect_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args;

    connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args) {
        process_connect(ctx, id, connect_args);
    }

    bpf_map_delete_elem(&conecting_args, &id);
	return 0;
}


SEC("tracepoint/tcp/tcp_retransmit_skb")
int tracepoint_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx){

    struct tcp_retransmit_event event = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event.pid = pid_tgid >> 32;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.type = 0;
	BPF_CORE_READ_INTO(&event.sport, ctx, sport);
	BPF_CORE_READ_INTO(&event.dport, ctx, dport);
	const struct sock *sk = ctx->skaddr;
	BPF_CORE_READ_INTO(&event.family, sk, __sk_common.skc_family);
	BPF_CORE_READ_INTO(&event.state, sk, __sk_common.skc_state);
	BPF_CORE_READ_INTO(&event.saddr_v4, ctx, saddr);
	BPF_CORE_READ_INTO(&event.daddr_v4, ctx, daddr);
	BPF_CORE_READ_INTO(&event.saddr_v6, ctx, saddr_v6);
	BPF_CORE_READ_INTO(&event.daddr_v6, ctx, daddr_v6);
	__u64 ret = bpf_perf_event_output(ctx, &tcp_retransmit_queue, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (ret != 0) {
        bpf_printk("write to tcp_retransmit queue failure:%d\n", ret);
    }
	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_synack")
int tracepoint_tcp_retransmit_synack(struct trace_event_raw_tcp_retransmit_synack *ctx){
    struct tcp_retransmit_event event = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event.pid = pid_tgid >> 32;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.type = 1;
	BPF_CORE_READ_INTO(&event.sport, ctx, sport);
	BPF_CORE_READ_INTO(&event.dport, ctx, dport);
	const struct sock *sk = ctx->skaddr;
	BPF_CORE_READ_INTO(&event.family, sk, __sk_common.skc_family);
	BPF_CORE_READ_INTO(&event.state, sk, __sk_common.skc_state);
	BPF_CORE_READ_INTO(&event.saddr_v4, ctx, saddr);
	BPF_CORE_READ_INTO(&event.daddr_v4, ctx, daddr);
	BPF_CORE_READ_INTO(&event.saddr_v6, ctx, saddr_v6);
	BPF_CORE_READ_INTO(&event.daddr_v6, ctx, daddr_v6);
	__u64 ret = bpf_perf_event_output(ctx, &tcp_retransmit_queue, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (ret != 0) {
        bpf_printk("write to tcp_retransmit queue failure:%d\n", ret);
    }
	return 0;
}

static __always_inline void __trace_drop(void *ctx, struct sock *sk, struct sk_buff *skb, __u16 reason)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sock_drop_event event = {};
	event.reason = reason;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	event.pid = pid_tgid >> 32;
    
	if (sk != NULL){
	    struct inet_sock *sockp = (struct inet_sock *)sk;
	    event.socket_family = BPF_CORE_READ(sk, __sk_common.skc_family);

	    BPF_CORE_READ_INTO(&event.ip_proto, sk, sk_protocol);
	    BPF_CORE_READ_INTO(&event.dport, sk, __sk_common.skc_dport);
	    BPF_CORE_READ_INTO(&event.sport, sockp, inet_sport);

	    switch (event.socket_family) {
	    case AF_INET:
	    	BPF_CORE_READ_INTO(&event.daddr_v4, sk, __sk_common.skc_daddr);
	    	BPF_CORE_READ_INTO(&event.saddr_v4, sk, __sk_common.skc_rcv_saddr);
	    	break;

	    case AF_INET6:
	    	BPF_CORE_READ_INTO(&event.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	    	BPF_CORE_READ_INTO(&event.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	    	break;
	    }

    }

	__u64 ret = bpf_perf_event_output(ctx, &socket_drop_queue, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (ret != 0) {
        bpf_printk("write to socket_drop queue failure:%d\n", ret);
    }
}

SEC("tracepoint/skb/kfree_skb")
int tracepoint_skb_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
	struct sk_buff *skb = ctx->skbaddr;
	struct sock *sk = BPF_CORE_READ(skb, sk);

   /* only query reason when it is available */
    __u16 reason;
    if (bpf_core_field_exists(ctx->reason))
    {
        reason = ctx->reason;
    }

    /* skip if the socket is not dropped ("reason" requires kernel >= 5.19) */
    if (bpf_core_field_exists(ctx->reason) && reason <= SKB_DROP_REASON_NOT_SPECIFIED)
    {
        return 0;
    }
    __trace_drop(ctx, sk, skb, reason);

	return 0;
}
