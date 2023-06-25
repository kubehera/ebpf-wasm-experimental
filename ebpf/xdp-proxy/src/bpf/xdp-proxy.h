#ifndef XDP_PROXY_H
#define XDP_PROXY_H

#define ETH_ALEN 6
#define ETH_HLEN	14		/* Total octets in header.	 */
#define AF_INET 2
#define AF_INET6	10	/* IP version 6			*/
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define TCP_MAX_BITS 1480
#define LOOPBACK_IFINDEX 1

#define EINVAL 22 /*invalid argument*/


#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4
#define TC_ACT_REDIRECT         7
 
 /* Current network namespace */
enum {
        BPF_F_CURRENT_NETNS             = (-1L),
};

const volatile __u32 local_ip = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct proxy_config_t);
} proxy_config_map SEC(".maps");

struct proxy_config_t {
    __u16 loadbalancer_port;
    __u32 loadbalancer_ip;
    __u32 endpoint_ip;
    __u16 endpoint_port;
    __u32 ifindex;
    __u32 lo_ifindex;
};

//struct {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__uint(max_entries, 10240);
//	__type(key, __u64);
//	__type(value, struct proxy_port_t);
//} proxy_port_map SEC(".maps");
//
//struct proxy_port_t {
//    __u16 client_port;
//    __u16 proxy_port;
//};

struct sock_drop_event {
    __u32 pid;
    __u32 socket_family;
    __u16 ip_proto;
    char comm[128];
    __u16 sport;
    __u16 dport;
    __u32 saddr_v4;
    __u32 daddr_v4;
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
	enum skb_drop_reason reason;
};

// Map for redirecting frames to another CPU
//struct {
//    __uint(type, BPF_MAP_TYPE_CPUMAP);
//    __uint(key_size, sizeof(u32));
//    __uint(value_size, sizeof(struct bpf_cpumap_val));
//    __uint(max_entries, MAX_CPUS);
//} cpu_redirect_map SEC(".maps");

//struct {
//	__uint(type, BPF_MAP_TYPE_XSKMAP);
//	__type(key, __u32);
//	__type(value, __u32);
//	__uint(max_entries, 64);
//} xsks_map SEC(".maps");


//static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb){
//    return (struct tcphdr *)((BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,transport_header)));
//}
//
//static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb){
//    return (struct iphdr *)(BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,network_header));
//}

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#endif