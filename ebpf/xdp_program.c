#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// #include "vmlinux.h"

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
    if (ip->protocol == 17) {
        update_stats(STAT_UDP_PACKETS);
        return XDP_PASS; // Pass UDP packets
    } else if (ip->protocol == 6) {
        update_stats(STAT_TCP_PACKETS);
        return XDP_PASS; // Pass TCP packets
    } else if (ip->protocol == 1) {
        // Only handle UDP, TCP, and ICMP
        int ret = bpf_redirect_map(&xsks_map, 0, 0);
    } else {
        return XDP_PASS; // Pass other protocols
    }
}

char _license[] SEC("license") = "GPL";