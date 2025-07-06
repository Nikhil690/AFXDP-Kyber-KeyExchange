#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// #include "vmlinux.h"

enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_L2TP = 115,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_RAW = 255,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};

// Map to store packet statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// AF_XDP socket map
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} qidconf_map SEC(".maps");

// Statistics indices
#define STAT_RX_PACKETS 0
#define STAT_TX_PACKETS 1
#define STAT_UDP_PACKETS 2
#define STAT_TCP_PACKETS 3

static __always_inline void update_stats(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&stats_map, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    int index = ctx->rx_queue_index;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;
    
    update_stats(STAT_RX_PACKETS);
    
    // Only process IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_ABORTED;
    
    // Check protocol and update stats
    // __u32 queue_index = 0;

    // __u32 *socket_fd = bpf_map_lookup_elem(&xsks_map, &queue_index);
    // if (!socket_fd) {
    //     char debug_msg3[] = "XDP: no socket in map\n";
    //     bpf_trace_printk(debug_msg3, sizeof(debug_msg3));
    //     return XDP_PASS;
    // }
    __u32 key = 0;
    __u32 *sock = bpf_map_lookup_elem(&xsks_map, &key);
    if (!sock) {
        bpf_printk("XDP: no socket in map\n");
    } else {
        bpf_printk("XDP: socket exists in map, key=0\n");
    }


    if (ip->protocol == IPPROTO_UDP) {
        update_stats(STAT_UDP_PACKETS);
        return XDP_PASS; // Pass UDP packets
    } else if (ip->protocol == IPPROTO_TCP) {
        update_stats(STAT_TCP_PACKETS);
        return XDP_PASS; // Pass TCP packets
        
    } else if (ip->protocol == IPPROTO_ICMP) {
        if (bpf_map_lookup_elem(&xsks_map, &index)){
            bpf_printk("Redirecting ICMP packet\n");
		    return bpf_redirect_map(&xsks_map, index, 0);
        }
        return XDP_PASS; // Pass ICMP packets
    } else {
        return XDP_PASS; // Pass other protocols
    }
}

char _license[] SEC("license") = "GPL";