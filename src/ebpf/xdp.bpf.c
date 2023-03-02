#include "../vmlinux/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline int get_protocol(void* data){
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    switch(ip->protocol){
        case IPPROTO_TCP:
            return IPPROTO_TCP;
        case IPPROTO_UDP:
            return IPPROTO_UDP;
        default:
            return -1;
    }
}

SEC("xdp")
int xdp_receive(struct xdp_md *ctx){
    
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    unsigned int payload_size;
    struct ethhdr *eth = data;
    char *payload;
    struct tcphdr *tcp;
    struct iphdr *ip;
    
    //Bound checking the packet before operating with it
    //Otherwise the bpf verifier will complain
    if ((void *)eth + sizeof(struct ethhdr) > data_end){
        return XDP_PASS;
    }

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end){
        return XDP_PASS;
    }

    if (get_protocol(data) != IPPROTO_TCP){
        return XDP_PASS;
    }

    tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end){
        return XDP_PASS;
    }

    payload_size = bpf_ntohs(ip->tot_len) - (tcp->doff * 4) - (ip->ihl * 4);
    payload = (void *)tcp + tcp->doff*4;

    return XDP_DROP;
}