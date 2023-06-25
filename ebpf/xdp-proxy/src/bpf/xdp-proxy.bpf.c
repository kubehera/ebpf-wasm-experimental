#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include "xdp-proxy.h"
/*
        loadbalancer => 172.17.0.5(Hex 0x50011ac) => 02:42:ac:11:00:05
        endpoint1    => 172.17.0.2(Hex 0x20011ac) => 02:42:ac:11:00:02
        endpoint2    => 172.17.0.3(Hex 0x30011ac) => 02:42:ac:11:00:03
        clientip     => 172.17.0.4(Hex 0x40011ac) => 02:42:ac:11:00:04
*/

//__attribute__((always_inline))
//static  __u16 csum_fold_helper(__u64 csum){
//    int i;
//#pragma unroll
//    for (i = 0; i < 4; i++)
//    {
//        if (csum >> 16)
//            csum = (csum & 0xffff) + (csum >> 16);
//    }
//    return ~csum;
//}
//
//__attribute__((always_inline))
//static __u16 iph_csum(struct iphdr *iph){
//    iph->check = 0;
//    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
//    return csum_fold_helper(csum);
//}

//__attribute__((always_inline))
//static  __u16 ipv4_l4_csum(void* data_start, __u32 data_size, struct iphdr* iph,void *data_end) {
//    __u64 csum_buffer = 0;
//    __u16 *buf = (void *)data_start;
//
//    // Compute pseudo-header checksum
//    csum_buffer += (__u16)iph->saddr;
//    csum_buffer += (__u16)(iph->saddr >> 16);
//    csum_buffer += (__u16)iph->daddr;
//    csum_buffer += (__u16)(iph->daddr >> 16);
//    csum_buffer += (__u32)iph->protocol << 8;
//    csum_buffer += data_size;
//
//    // Compute checksum on udp/tcp header + payload
//    for (int i = 0; i < TCP_MAX_BITS; i += 2) {
//        if ((void *)(buf + 1) > data_end) {
//            break;
//        }
//        csum_buffer += *buf;
//        buf++;
//    }
//    if ((void *)buf + 1 <= data_end) {
//    // In case payload is not 2 bytes aligned
//        csum_buffer += *(__u8 *)buf;
//    }
//
//    return csum_fold_helper(csum_buffer);
//}

#define IPV4_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IPV4_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IPV4_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))

static __always_inline __u32 l4_checksum_rel_off(__u8 proto) {
  switch (proto) {
  case IPPROTO_TCP:
    return offsetof(struct tcphdr, check);

  case IPPROTO_UDP:
    return offsetof(struct udphdr, check);
  }
  return 0;
}

static __always_inline __u32 l4_checksum_off(__u8 proto, __u8 ihl) {
  return ETH_HLEN + ihl * 4 + l4_checksum_rel_off(proto);
}


static __always_inline int rewrite_ip(struct __sk_buff *skb, __u8 proto,__u8 ihl, 
                                      __be32 old_ip,__be32 new_ip, bool is_dest) {
  __u32 l4_cksm_off = l4_checksum_off(proto, ihl);
  // BPF_F_PSEUDO_HDR indicates the part we want to modify is part of the
  // pseudo header.
  __u32 l4flags = BPF_F_PSEUDO_HDR;
  if (proto == IPPROTO_UDP) {
    l4flags |= BPF_F_MARK_MANGLED_0;
  }

  int ret;

  if ((ret = bpf_l4_csum_replace(skb, l4_cksm_off, old_ip, new_ip,
                                 l4flags | sizeof(new_ip)))) {
    bpf_printk("bpf_l4_csum_replace: %d", ret);
    return ret;
  }

  if ((ret = bpf_l3_csum_replace(skb, IPV4_CSUM_OFF, old_ip, new_ip,
                                 sizeof(new_ip)))) {
    return ret;
  }
  // bpf_printk("%pI4 -> %pI4", &_old_ip, &_new_ip);

  ret = bpf_skb_store_bytes(skb, is_dest ? IPV4_DST_OFF : IPV4_SRC_OFF,
                            &new_ip, sizeof(new_ip), 0);
  if (ret) {
    bpf_printk("bpf_skb_store_bytes: %d", ret);
    return ret;
  }

  return 0;
}

static __always_inline int rewrite_port(struct __sk_buff *skb, __u8 proto,
                                        __u8 ihl, __be16 old_port,
                                        __be16 new_port, bool is_dest) {
  // Nothing to do.
  if (old_port == new_port) {
    return 0;
  }
  __u32 cksm_off = l4_checksum_off(proto, ihl), port_off = ETH_HLEN + ihl * 4;
  if (!cksm_off) {
    return -EINVAL;
  }
  __u32 l4flags = 0;
  switch (proto) {
  case IPPROTO_TCP:
    if (is_dest) {
      port_off += offsetof(struct tcphdr, dest);
    } else {
      port_off += offsetof(struct tcphdr, source);
    }
    break;

  case IPPROTO_UDP:
    if (is_dest) {
      port_off += offsetof(struct udphdr, dest);
    } else {
      port_off += offsetof(struct udphdr, source);
    }
    l4flags |= BPF_F_MARK_MANGLED_0;
    break;

  default:
    return -EINVAL;
  }

  // bpf_printk("%u -> %u", bpf_ntohs(old_port), bpf_ntohs(new_port));

  int ret;

    if ((ret = bpf_l4_csum_replace(skb, cksm_off, old_port, new_port,
                                   l4flags | sizeof(new_port)))) {
      bpf_printk("bpf_l4_csum_replace: %d", ret);
      return ret;
    }

  if ((ret = bpf_skb_store_bytes(skb, port_off, &new_port, sizeof(new_port),
                                 0))) {
    return ret;
  }
  return 0;
}














__attribute__((always_inline))
static void print_mac(__u32 ip,char *prefix ,unsigned char mac[ETH_ALEN]){
    bpf_printk("%u,%s %02x",ip,prefix,mac[0]);
    bpf_printk("%02x:%02x:%02x",mac[1],mac[2],mac[3]);
    bpf_printk("%02x:%02x",mac[4],mac[5]);
}

__attribute__((always_inline))
static int gen_mac(struct xdp_md *ctx, struct ethhdr *eth ,struct iphdr *iph,
                    __u32 ipv4_src, __u32 ipv4_dst){
  struct bpf_fib_lookup fib_params;
  memset(&fib_params, 0, sizeof(fib_params));

	fib_params.family	= AF_INET;
  fib_params.tos		= iph->tos;
  fib_params.l4_protocol	= iph->protocol;
  fib_params.sport	= 0;
  fib_params.dport	= 0;
  fib_params.tot_len	= bpf_ntohs(iph->tot_len);
  fib_params.ipv4_src	= ipv4_src;
  fib_params.ipv4_dst	= ipv4_dst;
  fib_params.ifindex = ctx->ingress_ifindex;

  //bpf_printk("%u,Look up from %u|%pI4n to %u|%pI4n",local_ip,
   //   ipv4_src,&ipv4_src,ipv4_dst,&ipv4_dst);
  int action = XDP_PASS;
  int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
  print_mac(local_ip,"origin--",eth->h_source);
  print_mac(local_ip,"to------",eth->h_dest);
  switch (rc) {
      case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
          memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
          memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
          action = XDP_TX;
          bpf_printk("%u,BPF_FIB_LKUP_RET_SUCCESS: %u, TX",local_ip,rc);
          break;
      case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
      case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
      case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
          action = XDP_DROP;
          bpf_printk("%u,BPF_FIB_LKUP_RET_UNREACHABLE: %u, DROP",local_ip,rc);
          break;
      case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
      case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
      case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
      case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
      case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
          bpf_printk("%u,BPF_FIB_LKUP_RET_NOT_FWDED: %u, PASS",local_ip,rc);
          break;
	}
  print_mac(local_ip,"now-----",eth->h_source);
  print_mac(local_ip,"to------",eth->h_dest);
  return action;
}

__attribute__((always_inline))
static int gen_tc_mac(struct __sk_buff *skb,u32 ifindex){
  struct bpf_fib_lookup fib_params = {};
  //memset(&fib_params, 0, sizeof(fib_params));


  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;
  // abort on illegal packets
  if (data + sizeof(struct ethhdr) > data_end) {
    bpf_printk("eth abort on illegal packets");
    return TC_ACT_SHOT;
  }

  struct iphdr *iph = data + sizeof(struct ethhdr);
  // abort on illegal packets
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
    bpf_printk("iph abort on illegal packets");
    return TC_ACT_SHOT;
  }


	fib_params.family	= AF_INET;
  fib_params.tos		= iph->tos;
  fib_params.l4_protocol	= iph->protocol;
  fib_params.sport	= 0;
  fib_params.dport	= 0;
  fib_params.tot_len	= bpf_ntohs(iph->tot_len);
  fib_params.ipv4_src	= iph->saddr;
  fib_params.ipv4_dst	= iph->daddr;
  fib_params.ifindex = ifindex;
  bpf_printk("ingress_ifindex: %d",ifindex);

  //bpf_printk("%u,Look up from %u|%pI4n to %u|%pI4n",local_ip,
   //   ipv4_src,&ipv4_src,ipv4_dst,&ipv4_dst);
  int action = TC_ACT_OK;
  int rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
  print_mac(local_ip,"origin--",eth->h_source);
  print_mac(local_ip,"to------",eth->h_dest);
  switch (rc) {
      case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
          memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
          memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
          action = TC_ACT_REDIRECT;
          bpf_printk("%u,BPF_FIB_LKUP_RET_SUCCESS: %u, TX",local_ip,rc);
          break;
      case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
      case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
      case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
          action = TC_ACT_SHOT;
          bpf_printk("%u,BPF_FIB_LKUP_RET_UNREACHABLE: %u, DROP",local_ip,rc);
          break;
      case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
      case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
      case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
      case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
      case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
          bpf_printk("%u,BPF_FIB_LKUP_RET_NOT_FWDED: %u, PASS",local_ip,rc);
          break;
      default:
        bpf_printk("%u,BPF_FIB_LKUP_RET_UNKNOWN: %d",local_ip,rc);
	}
  print_mac(local_ip,"now-----",eth->h_source);
  print_mac(local_ip,"to------",eth->h_dest);
  return action;
}

//SEC("xdp")
//int xdp_proxy(struct xdp_md *ctx) {
//  bpf_printk("hook on eth0");
//  void *data = (void *)(long)ctx->data;
//  void *data_end = (void *)(long)ctx->data_end;
//
//  struct ethhdr *eth = data;
//  // abort on illegal packets
//  if (data + sizeof(struct ethhdr) > data_end) {
//    bpf_printk("eth abort on illegal packets");
//    return XDP_ABORTED;
//  }
//
//  // do nothing for non-IP packets
//  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
//    bpf_printk("do nothing for non-IP packets");
//    return XDP_PASS;
//  }
//  bpf_printk("eth0 sadrr mac:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
//  bpf_printk("eth0 sadrr mac:%x:%x:%x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
//  bpf_printk("eth0 dadrr mac:%x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
//  bpf_printk("eth0 dadrr mac:%x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
//
//  struct iphdr *iph = data + sizeof(struct ethhdr);
//  // abort on illegal packets
//  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
//    bpf_printk("iph abort on illegal packets");
//    return XDP_ABORTED;
//  }
//
//  // do nothing for non-TCP packets
//  if (iph->protocol != IPPROTO_TCP) {
//    bpf_printk("do nothing for non-TCP packets");
//    return XDP_PASS;
//  }
//   __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);
//  if (tcp_len > TCP_MAX_BITS){
//        bpf_printk("Tcp_len %u larger than max , drop",tcp_len);
//        return XDP_DROP;
//  }
//
//  struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
//  // abort on illegal packets
//  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
//    return XDP_ABORTED;
//  }
//  bpf_printk("eth0 from %x:%d port\n", iph->saddr, bpf_ntohs(tcph->source));
//  bpf_printk("eth0 to %x:%d port\n", iph->daddr,bpf_ntohs(tcph->dest));
//
//  __u64 key = 0;
//  struct proxy_config_t *proxy_config;
//  proxy_config = bpf_map_lookup_elem(&proxy_config_map, &key);
//  if (proxy_config == NULL) {
//    bpf_printk("get proxy config is null");
//    return XDP_PASS;
//  }
//
//  if (tcph->dest == bpf_htons(proxy_config->endpoint_port) && iph->daddr == proxy_config->endpoint_ip) {
//    return XDP_TX;
//  }else{
//    if (tcph->source == bpf_htons(proxy_config->endpoint_port) && iph->saddr == proxy_config->endpoint_ip){
//        iph->saddr = 0x100007f;
//        iph->daddr = 0x100007f;
//        tcph->source = bpf_htons(proxy_config->loadbalancer_port);
//        //int action = XDP_PASS;
//        //action = gen_mac(ctx,eth,iph,iph->saddr,iph->daddr);
//        //memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
//        eth->h_source[0] = 0;
//        eth->h_source[1] = 0;
//        eth->h_source[2] = 0;
//        eth->h_source[3] = 0;
//        eth->h_source[4] = 0;
//        eth->h_source[5] = 0;
//        eth->h_dest[0] = 0;
//        eth->h_dest[1] = 0;
//        eth->h_dest[2] = 0;
//        eth->h_dest[3] = 0;
//        eth->h_dest[4] = 0;
//        eth->h_dest[5] = 0;
//         
//        // recalculate IP checksum
//        __sum16	ip_sum = iph->check;
//        iph->check = iph_csum(iph);
//        __sum16	tcp_sum = tcph->check;
//        // here is the problem
//        // return XDP_PASS;
//        tcph->check = ipv4_l4_csum(tcph, tcp_len, iph,data_end);
//        bpf_printk("new eth0 from %x:%d port\n", iph->saddr, bpf_ntohs(tcph->source));
//        bpf_printk("new eth0 to %x:%d port\n", iph->daddr,bpf_ntohs(tcph->dest));
//
//        //return action;
//        //return XDP_TX;
//        //if (bpf_map_lookup_elem(&xsks_map, &index))
//        //return bpf_redirect_map(&xsks_map, index, 0);
//        return bpf_redirect(LOOPBACK_IFINDEX, BPF_F_INGRESS);
//        //return bpf_redirect(proxy_config->ifindex, 0);
//        return XDP_PASS;
//    }
//    return XDP_PASS;
//  }
//}
//
//SEC("xdp")
//int xdp_redirect(struct xdp_md *ctx) {
//  bpf_printk("hook on lo");
//  void *data = (void *)(long)ctx->data;
//  void *data_end = (void *)(long)ctx->data_end;
//
//  struct ethhdr *eth = data;
//  // abort on illegal packets
//  if (data + sizeof(struct ethhdr) > data_end) {
//    bpf_printk("eth abort on illegal packets");
//    return XDP_ABORTED;
//  }
//
//  // do nothing for non-IP packets
//  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
//    bpf_printk("do nothing for non-IP packets");
//    return XDP_PASS;
//  }
//
//  struct iphdr *iph = data + sizeof(struct ethhdr);
//  // abort on illegal packets
//  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
//    bpf_printk("iph abort on illegal packets");
//    return XDP_ABORTED;
//  }
//
//  // do nothing for non-TCP packets
//  if (iph->protocol != IPPROTO_TCP) {
//    bpf_printk("do nothing for non-TCP packets");
//    return XDP_PASS;
//  }
//   __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);
//  if (tcp_len > TCP_MAX_BITS){
//        bpf_printk("Tcp_len %u larger than max , drop",tcp_len);
//        return XDP_DROP;
//  }
//
//  struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
//  // abort on illegal packets
//  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
//    return XDP_ABORTED;
//  }
//
//  //__u64 key = 80;
//
//  //  struct proxy_config_t *proxy_config;
//    //proxy_config = bpf_map_lookup_elem(&proxy_config_map, &key);
//
//  //if (proxy_config == NULL) {
//  //  return XDP_PASS;
//  //}
//  //bpf_printk("sadrr ip:%x\n", iph->saddr);
//  bpf_printk("lo sadrr mac:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
//  bpf_printk("lo sadrr mac:%x:%x:%x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
//  //bpf_printk("dadrr ip:%x\n", iph->daddr);
//  bpf_printk("lo dadrr mac:%x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
//  bpf_printk("lo dadrr mac:%x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
//  //if (iph->saddr == proxy_config->client_ip) {
//  //  iph->daddr = proxy_config->endpoint_ip;
//    // only need to update the last byte
//  //  memcpy(eth->h_dest, proxy_config->endpoint_mac, ETH_ALEN);
//
//  //} else {
//  //  iph->daddr = proxy_config->client_ip;
//  //  memcpy(eth->h_dest, proxy_config->client_mac, ETH_ALEN);
//  //}
//
//  // packet source is always LB itself
//  //iph->saddr = proxy_config->loadbalancer_ip;
//  //memcpy(eth->h_source, proxy_config->loadbalancer_mac, ETH_ALEN);
//
//  //bpf_printk("new sadrr ip:%x\n", iph->saddr);
//  //bpf_printk("new sadrr mac:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
//  //bpf_printk("new sadrr mac:%x:%x:%x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
//  //bpf_printk("new dadrr ip:%x\n", iph->daddr);
//  //bpf_printk("new dadrr mac:%x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
//  //bpf_printk("new dadrr mac:%x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
//
//int action = XDP_PASS;
//
//__u64 key = 0;
//struct proxy_config_t *proxy_config;
//proxy_config = bpf_map_lookup_elem(&proxy_config_map, &key);
//if (proxy_config == NULL) {
//  bpf_printk("get proxy config is null");
//  return XDP_PASS;
//}
//
//bpf_printk("lo from %x:%d port\n", iph->saddr, bpf_ntohs(tcph->source));
//bpf_printk("lo to %x:%d port\n", iph->daddr,bpf_ntohs(tcph->dest));
//if (tcph->dest == bpf_htons(proxy_config->loadbalancer_port)) {
//iph->saddr = 0x40011ac;
//iph->daddr = proxy_config->endpoint_ip;
//tcph->dest = bpf_htons(proxy_config->endpoint_port);
//action = gen_mac(ctx,eth,iph,iph->saddr,iph->daddr);
//
//  // recalculate IP checksum
//  __sum16	ip_sum = iph->check;
//  iph->check = iph_csum(iph);
//  __sum16	tcp_sum = tcph->check;
//  // here is the problem
//  // return XDP_PASS;
//  tcph->check = ipv4_l4_csum(tcph, tcp_len, iph,data_end);
//  // return action;
//  //bpf_printk("ip_sum from %u to %u,tcp_sum from %u to %u,action:%u",
//  //   ip_sum,iph->check,tcp_sum,tcph->check,action);
//  bpf_printk("new lo from %x:%d port\n", iph->saddr, bpf_ntohs(tcph->source));
//  bpf_printk("new lo to %x:%d port\n", iph->daddr,bpf_ntohs(tcph->dest));
//}
//if  (action == XDP_TX){
//  return bpf_redirect(proxy_config->ifindex, 0);
//}else{
//  return action;
//}
//  // send packet back to network stack
//}


SEC("kprobe/sock_sendmsg")
int kprobe_sock_sendmsg(struct pt_regs *ctx){
   struct socket * sock;
   sock = (struct socket * )PT_REGS_PARM1_CORE(ctx); 
   if (sock != NULL) {
       struct sock *sk;
       BPF_CORE_READ_INTO(&sk, sock, sk);
       if (sk != NULL) {
	        short unsigned int skc_family;
          skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
          if (skc_family == AF_INET){
             u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
             u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
             u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
             u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
             if (sport!=22 && dport!=22){
             bpf_printk("sendmsg local: %x->%d",saddr,sport);
             bpf_printk("sendmsg direct: %x->%d",daddr,dport);
             }
          }
       }
   }
	return 0;
}

SEC("kprobe/sock_recvmsg")
int kprobe_sock_recvmsg(struct pt_regs *ctx){
   struct socket * sock;
   sock = (struct socket * )PT_REGS_PARM1_CORE(ctx); 
   if (sock != NULL) {
       struct sock *sk;
       BPF_CORE_READ_INTO(&sk, sock, sk);
       if (sk != NULL) {
	        short unsigned int skc_family;
          skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
          if (skc_family == AF_INET){
             u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
             u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
             u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
             u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
             if (sport!=22 && dport!=22){
             bpf_printk("recvmsg local: %x->%d",saddr,sport);
             bpf_printk("recvmsg direct: %x->%d",daddr,dport);
             }
          }
       }
   }
	return 0;

}


SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx){
   struct socket * sock;
   sock = (struct socket * )PT_REGS_PARM1_CORE(ctx); 
   if (sock != NULL) {
       struct sock *sk;
       BPF_CORE_READ_INTO(&sk, sock, sk);
       if (sk != NULL) {
	        short unsigned int skc_family;
          skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
          if (skc_family == AF_INET){
             u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
             u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
             u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
             u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
             if (sport!=22 && dport!=22){
             bpf_printk("tcp recvmsg local: %x->%d",saddr,sport);
             bpf_printk("tcp recvmsg direct: %x->%d",daddr,dport);
             }
          }
       }
   }
	return 0;

}












SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
  // TODO: 添加套接字映射更新操作
  //struct sock_key key = {
  //.dip = skops->remote_ip4,
  //.sip = skops->local_ip4,
  //.sport = bpf_htonl(skops->local_port),
  //.dport = skops->remote_port,
  //.family = skops->family,
  //};
  bpf_printk("sockops local: %x->%d",skops->local_ip4,skops->local_port);
  bpf_printk("sockops remote: %x->%d",skops->remote_ip4,bpf_ntohl(skops->remote_port));
	return BPF_OK;

}

static inline void set_macs(struct __sk_buff *skb, char *mac)
{
	bpf_skb_store_bytes(skb, 0, mac, ETH_ALEN*2, 1);
}



SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
  bpf_printk("hook on tc eth0 ingress");

  // Initialize packet data.
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  struct ethhdr *eth = data;
  // abort on illegal packets
  if (data + sizeof(struct ethhdr) > data_end) {
    bpf_printk("eth abort on illegal packets");
    return TC_ACT_SHOT;
  }

  // do nothing for non-IP packets
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    bpf_printk("do nothing for non-IP packets");
    return TC_ACT_OK;
  }
  bpf_printk("eth0 sadrr mac:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
  bpf_printk("eth0 sadrr mac:%x:%x:%x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  bpf_printk("eth0 dadrr mac:%x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
  bpf_printk("eth0 dadrr mac:%x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

  struct iphdr *iph = data + sizeof(struct ethhdr);
  // abort on illegal packets
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
    bpf_printk("iph abort on illegal packets");
    return TC_ACT_SHOT;
  }

  // do nothing for non-TCP packets
  if (iph->protocol != IPPROTO_TCP) {
    bpf_printk("do nothing for non-TCP packets");
    return TC_ACT_OK;
  }
   __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);
  if (tcp_len > TCP_MAX_BITS){
    bpf_printk("Tcp_len %u larger than max , drop",tcp_len);
    return TC_ACT_SHOT;
  }

  struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  // abort on illegal packets
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
    return TC_ACT_SHOT;
  }
  bpf_printk("eth0 from %x:%d port\n", iph->saddr, bpf_ntohs(tcph->source));
  bpf_printk("eth0 to %x:%d port\n", iph->daddr,bpf_ntohs(tcph->dest));

  __u64 key = 0;
  struct proxy_config_t *proxy_config;
  proxy_config = bpf_map_lookup_elem(&proxy_config_map, &key);
  if (proxy_config == NULL) {
    bpf_printk("get proxy config is null");
    return TC_ACT_OK;
  }

  if (tcph->dest == bpf_htons(proxy_config->endpoint_port) && iph->daddr == proxy_config->endpoint_ip) {
    return TC_ACT_OK;
  }else{
    if (tcph->source == bpf_htons(proxy_config->endpoint_port) && iph->saddr == proxy_config->endpoint_ip){
        u8 ihl = iph->ihl;
        u32 daddr = BPF_CORE_READ(iph, daddr);
        u32 saddr = BPF_CORE_READ(iph, saddr);
        u16 lb_port = bpf_htons(proxy_config->loadbalancer_port);
        u16 sport = BPF_CORE_READ(tcph, source);
        //u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        int ret;
        ret = rewrite_ip(skb,IPPROTO_TCP,ihl,saddr,proxy_config->loadbalancer_ip,false);
        if(ret != 0){
          bpf_printk("rewrite saddr ip error: %d",ret);
          return TC_ACT_SHOT;
        }
        ret = rewrite_port(skb,IPPROTO_TCP,ihl,sport,lb_port,false);
        if(ret != 0){
          bpf_printk("rewrite_port error: %d",ret);
          return TC_ACT_SHOT;
        }
        int action =TC_ACT_OK ;
        action = gen_tc_mac(skb,proxy_config->ifindex);
       // int ret;
       // ret = rewrite_ip(skb,IPPROTO_TCP,ihl,saddr,0x100007f,false);
       // if(ret != 0){
       //   bpf_printk("rewrite saddr ip error: %d",ret);
       //   return TC_ACT_SHOT;
       // }
       // ret = rewrite_ip(skb,IPPROTO_TCP,ihl,daddr,0x100007f,true);
       // if(ret != 0){
       //   bpf_printk("rewrite daddr ip error: %d",ret);
       //   return TC_ACT_SHOT;
       // }
       // ret = rewrite_port(skb,IPPROTO_TCP,ihl,sport,lb_port,false);
       // if(ret != 0){
       //   bpf_printk("rewrite_port error: %d",ret);
       //   return TC_ACT_SHOT;
       // }

       // //iph->saddr = 0x100007f;
       // //iph->daddr = 0x100007f;
       // //tcph->source = bpf_htons(proxy_config->loadbalancer_port);
       // //int action = XDP_PASS;
       // //action = gen_mac(ctx,eth,iph,iph->saddr,iph->daddr);
       // //memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
       // char macs[ETH_ALEN*2]={0};
       // set_macs(skb,macs);
       // //eth->h_source[0] = 0;
       // //eth->h_source[1] = 0;
       // //eth->h_source[2] = 0;
       // //eth->h_source[3] = 0;
       // //eth->h_source[4] = 0;
       // //eth->h_source[5] = 0;
       // //eth->h_dest[0] = 0;
       // //eth->h_dest[1] = 0;
       // //eth->h_dest[2] = 0;
       // //eth->h_dest[3] = 0;
       // //eth->h_dest[4] = 0;
       // //eth->h_dest[5] = 0;
       //  
       //// // recalculate IP checksum
       //// __sum16	ip_sum = iph->check;
       //// iph->check = iph_csum(iph);
       //// __sum16	tcp_sum = tcph->check;
       //// // here is the problem
       //// // return XDP_PASS;
       //// tcph->check = ipv4_l4_csum(tcph, tcp_len, iph,data_end);
       //// bpf_printk("new eth0 from %x:%d port\n", iph->saddr, bpf_ntohs(tcph->source));
       //// bpf_printk("new eth0 to %x:%d port\n", iph->daddr,bpf_ntohs(tcph->dest));

       // //return action;
       // //return XDP_TX;
       // //if (bpf_map_lookup_elem(&xsks_map, &index))
       // //return bpf_redirect_map(&xsks_map, index, 0);
       // //return bpf_redirect(LOOPBACK_IFINDEX, BPF_F_INGRESS);
       // struct bpf_sock *sk; 
       // struct bpf_sock_tuple *tuple;
       // int tuple_len;
       // tuple_len = sizeof(tuple->ipv4);
       // tuple = (struct bpf_sock_tuple *)(void*)(long)(skb->data + IPV4_SRC_OFF);

       // if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       //    return TC_ACT_SHOT;
       // }

        /*sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
        if (sk != NULL){
            bpf_printk("get tcp socket addr src:%d -> dst:%d state:%d", sk->src_ip4,sk->dst_ip4,sk->state);
            bpf_printk("get tcp socket port src:%d -> dst:%d if:%d", sk->src_port,bpf_ntohs(sk->dst_port),sk->bound_dev_if);
            //BPF_TCP_LISTEN
            ret = bpf_sk_assign(skb, sk, 0);
            bpf_printk("return assign: %d",ret);
            int release_ret = bpf_sk_release(sk);
            bpf_printk("return release: %d",release_ret);
            return TC_ACT_OK;
            if(ret == 0){
            //if succedded forward to the stack
                return TC_ACT_OK;
            }
        }else{
            bpf_printk("get tcp socket is null");
        }*/
        //return bpf_redirect(LOOPBACK_IFINDEX, BPF_F_INGRESS);
        return bpf_redirect(proxy_config->ifindex, BPF_F_INGRESS);
    }
    return TC_ACT_OK;
  }
}

SEC("tc")
int tc_ingress_lo(struct __sk_buff *skb){
  bpf_printk("hook on tc lo egress");

  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  struct ethhdr *eth = data;
  // abort on illegal packets
  if (data + sizeof(struct ethhdr) > data_end) {
    bpf_printk("eth abort on illegal packets");
    return TC_ACT_SHOT;
  }

  // do nothing for non-IP packets
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    bpf_printk("do nothing for non-IP packets");
    return TC_ACT_OK;
  }

  struct iphdr *iph = data + sizeof(struct ethhdr);
  // abort on illegal packets
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
    bpf_printk("iph abort on illegal packets");
    return TC_ACT_SHOT;
  }

  // do nothing for non-TCP packets
  if (iph->protocol != IPPROTO_TCP) {
    bpf_printk("do nothing for non-TCP packets");
    return TC_ACT_OK;
  }

  struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  // abort on illegal packets
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
    return TC_ACT_SHOT;
  }

  //__u64 key = 80;

  //  struct proxy_config_t *proxy_config;
    //proxy_config = bpf_map_lookup_elem(&proxy_config_map, &key);

  //if (proxy_config == NULL) {
  //  return XDP_PASS;
  //}
  //bpf_printk("sadrr ip:%x\n", iph->saddr);
  bpf_printk("lo sadrr mac:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
  bpf_printk("lo sadrr mac:%x:%x:%x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  //bpf_printk("dadrr ip:%x\n", iph->daddr);
  bpf_printk("lo dadrr mac:%x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
  bpf_printk("lo dadrr mac:%x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
  //if (iph->saddr == proxy_config->client_ip) {
  //  iph->daddr = proxy_config->endpoint_ip;
    // only need to update the last byte
  //  memcpy(eth->h_dest, proxy_config->endpoint_mac, ETH_ALEN);

  //} else {
  //  iph->daddr = proxy_config->client_ip;
  //  memcpy(eth->h_dest, proxy_config->client_mac, ETH_ALEN);
  //}

  // packet source is always LB itself
  //iph->saddr = proxy_config->loadbalancer_ip;
  //memcpy(eth->h_source, proxy_config->loadbalancer_mac, ETH_ALEN);

  //bpf_printk("new sadrr ip:%x\n", iph->saddr);
  //bpf_printk("new sadrr mac:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
  //bpf_printk("new sadrr mac:%x:%x:%x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  //bpf_printk("new dadrr ip:%x\n", iph->daddr);
  //bpf_printk("new dadrr mac:%x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
  //bpf_printk("new dadrr mac:%x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

int action = TC_ACT_OK;

__u64 key = 0;
struct proxy_config_t *proxy_config;
proxy_config = bpf_map_lookup_elem(&proxy_config_map, &key);
if (proxy_config == NULL) {
  bpf_printk("get proxy config is null");
  return action;
}

bpf_printk("lo from %x:%d port\n", iph->saddr, bpf_ntohs(tcph->source));
bpf_printk("lo to %x:%d port\n", iph->daddr,bpf_ntohs(tcph->dest));
if (tcph->dest == bpf_htons(proxy_config->loadbalancer_port) && iph->daddr == proxy_config->loadbalancer_ip) {
//iph->saddr = 0x40011ac;
//iph->daddr = proxy_config->endpoint_ip;
u8 ihl = iph->ihl;
u32 daddr = BPF_CORE_READ(iph, daddr);
u32 saddr = BPF_CORE_READ(iph, saddr);
u32 endpoint_ip = proxy_config->endpoint_ip;
u16 endpoint_port = bpf_htons(proxy_config->endpoint_port);
u16 dport = BPF_CORE_READ(tcph, dest);
//u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
rewrite_ip(skb,IPPROTO_TCP,ihl,saddr,0x40011ac,false);
rewrite_ip(skb,IPPROTO_TCP,ihl,daddr,endpoint_ip,true);
rewrite_port(skb,IPPROTO_TCP,ihl,dport,endpoint_port,true);
//tcph->dest = bpf_htons(proxy_config->endpoint_port);

action = gen_tc_mac(skb,proxy_config->ifindex);

 // __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);
 // // recalculate IP checksum
 // __sum16	ip_sum = iph->check;
 // iph->check = iph_csum(iph);
 // __sum16	tcp_sum = tcph->check;
 // // here is the problem
 // tcph->check = ipv4_l4_csum(tcph, tcp_len, iph,data_end);
 // //bpf_printk("ip_sum from %u to %u,tcp_sum from %u to %u,action:%u",
 // //   ip_sum,iph->check,tcp_sum,tcph->check,action);
 // bpf_printk("new lo from %x:%d port\n", iph->saddr, bpf_ntohs(tcph->source));
 // bpf_printk("new lo to %x:%d port\n", iph->daddr,bpf_ntohs(tcph->dest));
 // bpf_printk("new lo sadrr mac:%x:%x:%x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
 // bpf_printk("new lo sadrr mac:%x:%x:%x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
 // bpf_printk("new lo dadrr mac:%x:%x:%x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
 // bpf_printk("new lo dadrr mac:%x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
 // if (action == TC_ACT_REDIRECT){
    return bpf_redirect(proxy_config->ifindex, 0);
    //return bpf_clone_redirect(skb,proxy_config->ifindex, 0);
  //}
}
return action;
//if  (action == XDP_TX){
//  return bpf_redirect(proxy_config->ifindex, 0);
//}else{
  //return action;
//}
  // send packet back to network stack
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


    bpf_printk("socker drop: saddr:%d -> daddr:%d\n", event.saddr_v4,event.daddr_v4);
    bpf_printk("socker drop: sport:%d -> dport:%d reason:%d\n", event.sport,event.dport,event.reason);
    }else{
    bpf_printk("socker drop: sock is null");
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


SEC("kprobe/__sk_receive_skb")
int kprobe_sk_receive_skb(struct pt_regs *ctx){
   struct socket * sock;
   sock = (struct socket * )PT_REGS_PARM1_CORE(ctx); 
   if (sock != NULL) {
       struct sock *sk;
       BPF_CORE_READ_INTO(&sk, sock, sk);
       if (sk != NULL) {
	        short unsigned int skc_family;
          skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
          if (skc_family == AF_INET){
             u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
             u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
             u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
             u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
             if (sport!=22 && dport!=22){
             bpf_printk("receive_skb local: %x->%d",saddr,sport);
             bpf_printk("receive_skb direct: %x->%d",daddr,dport);
             }
          }
       }
   }
	return 0;
}

SEC("kprobe/netif_rx")
int kprobe_netif_rx(struct pt_regs *ctx){
   struct sk_buff * skb;
   struct socket * sock;
   skb = (struct sk_buff * )PT_REGS_PARM1_CORE(ctx); 
   if (skb == NULL) {
    bpf_printk("tcp_rcv skb is null");
    return 0;
   }
   BPF_CORE_READ_INTO(&sock, skb, sk);
   if (sock == NULL) {
    bpf_printk("tcp_rcv sock is null");
    return 0;
   }
   struct sock *sk;
   BPF_CORE_READ_INTO(&sk, sock, sk);
   if (sk != NULL) {
	    short unsigned int skc_family;
      skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
      if (skc_family == AF_INET){
         u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
         u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
         u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
         u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
         if (sport!=22 && dport!=22){
         bpf_printk("netif_rx local: %x->%d",saddr,sport);
         bpf_printk("netif_rx direct: %x->%d",daddr,dport);
         }
      }
   }
	return 0;
}

SEC("kprobe/ip_rcv")
int kprobe_ip_rcv(struct pt_regs *ctx){
   struct sk_buff * skb;
   struct socket * sock;
   skb = (struct sk_buff * )PT_REGS_PARM1_CORE(ctx); 
   if (skb == NULL) {
    bpf_printk("tcp_rcv skb is null");
    return 0;
   }
   BPF_CORE_READ_INTO(&sock, skb, sk);
   if (sock == NULL) {
    bpf_printk("tcp_rcv sock is null");
    return 0;
   }
   struct sock *sk;
   BPF_CORE_READ_INTO(&sk, sock, sk);
   if (sk != NULL) {
	    short unsigned int skc_family;
      skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
      if (skc_family == AF_INET){
         u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
         u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
         u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
         u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
         if (sport!=22 && dport!=22){
         bpf_printk("ip_rcv local: %x->%d",saddr,sport);
         bpf_printk("ip_rcv direct: %x->%d",daddr,dport);
         }
      }
   }
	return 0;
}

SEC("kprobe/tcp_v4_rcv")
int kprobe_tcp_rcv(struct pt_regs *ctx){
   struct sk_buff * skb;
   struct socket * sock;
   skb = (struct sk_buff * )PT_REGS_PARM1_CORE(ctx); 
   if (skb == NULL) {
    bpf_printk("tcp_rcv skb is null");
    return 0;
   }


  struct iphdr *iph = (struct iphdr *)(BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,network_header));
  struct tcphdr *tcph = (struct tcphdr *)((BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,transport_header)));

  if (iph == NULL || tcph == NULL) {
    bpf_printk("tcp_rcv iph or tcph is null");
    return 0;
  }

  u32 saddr = BPF_CORE_READ(iph,saddr);
  u32 daddr = BPF_CORE_READ(iph,daddr);
  u32 sport = BPF_CORE_READ(tcph,source);
  u32 dport = BPF_CORE_READ(tcph,dest);
  u32 seq = BPF_CORE_READ(tcph,seq);
  u32 ack_seq = BPF_CORE_READ(tcph,ack_seq);
  u16 ip_check = BPF_CORE_READ(iph,check);
  u16 tcp_check = BPF_CORE_READ(tcph,check);
  if (bpf_ntohs(sport)==22 || bpf_ntohs(dport)==22){
    return 0;
  }
  bpf_printk("tcp_rcv local: %x->%d",saddr,bpf_ntohs(sport));
  bpf_printk("tcp_rcv direct: %x->%d",daddr,bpf_ntohs(dport));
  bpf_printk("tcp_rcv seq:%d ----- ack-seq:%d",bpf_ntohs(seq),bpf_ntohs(ack_seq));
  bpf_printk("tcp_rcv ip_check:%x ----- tcp_check:%x",ip_check,tcp_check);
  return 0;




   BPF_CORE_READ_INTO(&sock, skb, sk);
   if (sock == NULL) {
    bpf_printk("tcp_rcv sock is null");
    return 0;
   }
   struct sock *sk;
   BPF_CORE_READ_INTO(&sk, sock, sk);
   if (sk != NULL) {
	    short unsigned int skc_family;
      skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
      if (skc_family == AF_INET){
         u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
         u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
         u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
         u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
         if (sport!=22 && dport!=22){
         bpf_printk("tcp_rcv local: %x->%d",saddr,sport);
         bpf_printk("tcp_rcv direct: %x->%d",daddr,dport);
         }
      }
   }
	 return 0;
}

char _license[] SEC("license") = "GPL";