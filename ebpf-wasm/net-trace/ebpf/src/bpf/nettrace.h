/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include "vmlinux.h"

#ifndef NET_TRACE_H
#define NET_TRACE_H

#define EINPROGRESS 115 /* Operation now in progress */

/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/
#define AF_ROSE		11	/* Amateur Radio X.25 PLP	*/
#define AF_DECnet	12	/* Reserved for DECnet project	*/
#define AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
#define AF_SECURITY	14	/* Security callback pseudo AF */
#define AF_KEY		15      /* PF_KEY key management API */
#define AF_NETLINK	16
#define AF_ROUTE	AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET	17	/* Packet family		*/
#define AF_ASH		18	/* Ash				*/
#define AF_ECONET	19	/* Acorn Econet			*/
#define AF_ATMSVC	20	/* ATM SVCs			*/
#define AF_RDS		21	/* RDS sockets 			*/
#define AF_SNA		22	/* Linux SNA Project (nutters!) */
#define AF_IRDA		23	/* IRDA sockets			*/
#define AF_PPPOX	24	/* PPPoX sockets		*/
#define AF_WANPIPE	25	/* Wanpipe API Sockets */
#define AF_LLC		26	/* Linux LLC			*/
#define AF_CAN		29	/* Controller Area Network      */
#define AF_TIPC		30	/* TIPC sockets			*/
#define AF_BLUETOOTH	31	/* Bluetooth sockets 		*/
#define AF_IUCV		32	/* IUCV sockets			*/
#define AF_RXRPC	33	/* RxRPC sockets 		*/
#define AF_ISDN		34	/* mISDN sockets 		*/
#define AF_PHONET	35	/* Phonet sockets		*/
#define AF_IEEE802154	36	/* IEEE802154 sockets		*/
#define AF_CAIF		37	/* CAIF sockets			*/
#define AF_ALG		38	/* Algorithm sockets		*/
#define AF_NFC		39	/* NFC sockets			*/
#define AF_MAX		40	/* For now.. */
 
/* Protocol families, same as address families. */
#define PF_UNSPEC	AF_UNSPEC
#define PF_UNIX		AF_UNIX
#define PF_LOCAL	AF_LOCAL
#define PF_INET		AF_INET
#define PF_AX25		AF_AX25
#define PF_IPX		AF_IPX
#define PF_APPLETALK	AF_APPLETALK
#define	PF_NETROM	AF_NETROM
#define PF_BRIDGE	AF_BRIDGE
#define PF_ATMPVC	AF_ATMPVC
#define PF_X25		AF_X25
#define PF_INET6	AF_INET6
#define PF_ROSE		AF_ROSE
#define PF_DECnet	AF_DECnet
#define PF_NETBEUI	AF_NETBEUI
#define PF_SECURITY	AF_SECURITY
#define PF_KEY		AF_KEY
#define PF_NETLINK	AF_NETLINK
#define PF_ROUTE	AF_ROUTE
#define PF_PACKET	AF_PACKET
#define PF_ASH		AF_ASH
#define PF_ECONET	AF_ECONET
#define PF_ATMSVC	AF_ATMSVC
#define PF_RDS		AF_RDS
#define PF_SNA		AF_SNA
#define PF_IRDA		AF_IRDA
#define PF_PPPOX	AF_PPPOX
#define PF_WANPIPE	AF_WANPIPE
#define PF_LLC		AF_LLC
#define PF_CAN		AF_CAN
#define PF_TIPC		AF_TIPC
#define PF_BLUETOOTH	AF_BLUETOOTH
#define PF_IUCV		AF_IUCV
#define PF_RXRPC	AF_RXRPC
#define PF_ISDN		AF_ISDN
#define PF_PHONET	AF_PHONET
#define PF_IEEE802154	AF_IEEE802154
#define PF_CAIF		AF_CAIF
#define PF_ALG		AF_ALG
#define PF_NFC		AF_NFC
#define PF_MAX		AF_MAX



#define MAX_DATA_SIZE_BUF 1

// syscall:connect
struct connect_args_t {
    __u32 fd;
    struct sockaddr* addr;
    struct sock *sock;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct connect_args_t);
} conecting_args SEC(".maps");

// detect socket operation and send to the user space
#define SOCKET_OPTS_TYPE_CONNECT 1
#define SOCKET_OPTS_TYPE_ACCEPT  2
#define SOCKET_OPTS_TYPE_CLOSE   3
struct sock_opts_event {
    // connect, accept, close
    __u32 type;
    // process id
    __u32 pid;
    // process command line
    char comm[128];
    // socket file descriptor
    __u32 sockfd;
    // upstream(works on server and client side)
    __u32 upstream_addr_v4;
    __u8 upstream_addr_v6[16];
    __u32 upstream_port;
    // downstream(only works on server side)
    __u32 downstream_addr_v4;
    __u8 downstream_addr_v6[16];
    __u32 downstream_port;
    __u32 fix;
    __u64 exe_time;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} socket_opts_events_queue SEC(".maps");

#define CONNECTION_ROLE_TYPE_UNKNOWN 0
#define CONNECTION_ROLE_TYPE_CLIENT 1
#define CONNECTION_ROLE_TYPE_SERVER 2
struct active_connection_t {
    // process id
    __u32 pid;
    // process command line
    char comm[128];
    // socket file descriptor
    __u32 sockfd;
    // the type of role in current connection
    __u32 role;
    // socket type
    __u32 socket_family;
    // upstream(works on server and client side)
    __u32 upstream_addr_v4;
    __u8 upstream_addr_v6[16];
    __u32 upstream_port;
    // downstream(only works on server side)
    __u32 downstream_addr_v4;
    __u8 downstream_addr_v6[16];
    __u16 downstream_port;
    __u64 total_bytes;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct active_connection_t);
} active_connection_map SEC(".maps");
static __inline __u64 gen_tgid_fd(__u32 tgid, __u32 fd) {
  return ((__u64)tgid << 32) | fd;
}

// syscall:sendto
#define SOCK_DATA_FUNC_SENDTO 1
#define SOCK_DATA_FUNC_RECVFROM 2
#define SOCK_DATA_FUNC_READ 3
#define SOCK_DATA_FUNC_WRITE 4
#define SOCK_DATA_FUNC_WRITEV 5
#define SOCK_DATA_FUNC_SEND 6
#define SOCK_DATA_FUNC_SENDMSG 7
struct sock_data_args_t {
    __u32 func;
    __u32 fd;
    const char* buf;
    // Used to filter out read/write and readv/writev calls that are not to sockets.
    bool sock_event;
    const struct iovec* iov;
    size_t iovlen;
    __u64 start_nacs;
    __u32 rtt;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_data_args_t);
} writing_args SEC(".maps");

// socket write or receive data event, communicate with user space
#define SOCK_DATA_DIRECTION_INGRESS 1 //receive from
#define SOCK_DATA_DIRECTION_EGRESS 2  //write to
struct sock_data_event_t {
    __u32 pid;
    char comm[128];
    __u32 sockfd;
//    char buf[MAX_DATA_SIZE_BUF];
    __u32 buf_size;
    __u32 protocol_type;
    __u32 message_type;
    __u32 data_direction;
    __u64 exe_time;
    __u32 rtt;
    // socket type
    __u32 socket_family;
    // upstream(works on server and client side)
    __u32 upstream_addr_v4;
    __u8 upstream_addr_v6[16];
    __u32 upstream_port;
    // downstream(only works on server side)
    __u32 downstream_addr_v4;
    __u8 downstream_addr_v6[16];
    __u16 downstream_port;
    __u64 total_bytes;
    __u32 func;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct sock_data_event_t);
    __uint(max_entries, 1);
} sock_data_event_creator_map SEC(".maps");
static __inline struct sock_data_event_t* create_sock_data() {
    __u32 kZero = 0;
    struct sock_data_event_t* event = bpf_map_lookup_elem(&sock_data_event_creator_map, &kZero);
    if (event == NULL) {
        return NULL;
    }
    return event;
}
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} socket_data_events_queue SEC(".maps");

// syscall:close
struct sock_close_args_t {
    int fd;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_close_args_t);
} closing_args SEC(".maps");

// syscall:accept
struct accept_args_t {
    __u32 fd;
    struct sockaddr* addr;
    struct socket* socket;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct accept_args_t);
} accepting_args SEC(".maps");

#endif
