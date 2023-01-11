/*    Copyright (C) 2022  Robert Caamano   */
 /*
  *   This program redirects udp packets that match specific destination prefixes & src/dst ports
  *   to either openziti edge-router tproxy port or to a locally hosted openziti service socket
  *   depending on whether there is an existing egress socket. 
  *
  *   This program is free software: you can redistribute it and/or modify
  *   it under the terms of the GNU General Public License as published by
  *   the Free Software Foundation, either version 3 of the License, or
  *   (at your option) any later version.

  *   This program is distributed in the hope that it will be useful,
  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *   GNU General Public License for more details.
  *   see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bcc/bcc_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GENEVE_UDP_PORT         6081
#define GENEVE_VER              0
#define AWS_GNV_HDR_OPT_LEN     32 // Bytes
#define AWS_GNV_HDR_LEN         40 // Bytes
#define BPF_MAP_ID_GENEVE       1
#define BPF_MAX_ENTRIES         1
#define OPTIONS_LEVEL_SIZE      10 // characters long
#define DEBUG                   1
#define TRACE                   2
#define INFO                    0

struct options_key {
    char log_verbosity[OPTIONS_LEVEL_SIZE]; // [verbose]
};

struct options_tuple {
    int log_level; // [debug=1,trace=2,info=0]
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(id, BPF_MAP_ID_GENEVE);
    __uint(key_size, sizeof(struct options_key));
    __uint(value_size,sizeof(struct options_tuple));
    __uint(max_entries, BPF_MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} geneve_options_map SEC(".maps");

static inline struct options_tuple *get_options(struct options_key key){
    struct options_tuple *optt;
    optt = bpf_map_lookup_elem(&geneve_options_map, &key);
	return optt;
}

SEC("sk_skb")
int geneve(struct __sk_buff *skb) {
    __u8 proto = 0;
    int ret;
    
    /* Check Debug Settings */
    
    struct options_key key = {"verbose"};
    struct options_tuple *optt;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
        bpf_printk("ETH Header is invalid");
        return BPF_DROP;
	}
    /* get header */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
     /* ensure ip header is in packet bounds */
    if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
        bpf_printk("Outer IP Header is invalid");
        return BPF_DROP;
    }
    /* get ip protocol type */
    proto = iph->protocol;
    /* check if ip protocol is UDP */
    if (proto == IPPROTO_UDP) {
        /* check udp header */
        struct udphdr *udph = (struct udphdr *)(skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
            bpf_printk("Outer UDP Header is invalid");
            return BPF_DROP;
        }
        /* If geneve port 6081, then do geneve header verification */
        if (bpf_ntohs(udph->dest) == GENEVE_UDP_PORT){

            /* read receive geneve version and header length */
            __u8 *genhdr = (void *)(unsigned long)(skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
            if ((unsigned long)(genhdr + 1) > (unsigned long)skb->data_end){
                bpf_printk("Geneve Header is invalid");
                return BPF_DROP;
            }
            int gen_ver  = genhdr[0] & 0xC0 >> 6;
            int gen_hdr_len = genhdr[0] & 0x3F;
      
            if((optt = get_options(key))) {
                if (optt->log_level == DEBUG) {
                    bpf_printk("Debug Test %d", optt->log_level);
                    bpf_printk("Debug Test %s", key.log_verbosity);
                }
                if (optt->log_level == TRACE) {
                    bpf_printk("Trace Test %d", optt->log_level);
                    bpf_printk("Trace Test %s", key.log_verbosity);
                }
            }
            
            /* if the length is not equal to 32 bytes and version 0 */
            if ((gen_hdr_len != AWS_GNV_HDR_OPT_LEN / 4) || (gen_ver != GENEVE_VER)){
                bpf_printk("Error - Geneve header length:version %d:%d", gen_hdr_len * 4, gen_ver);
                return BPF_OK;
            }
            __s32 adjust_size = -(signed long)(sizeof(struct iphdr) + sizeof(struct udphdr) + AWS_GNV_HDR_LEN);
            /* Updating the skb to pop geneve header */
            ret = bpf_skb_adjust_room(skb, adjust_size, BPF_ADJ_ROOM_MAC, 0);
            if (ret) {
                bpf_printk("Error - Calling skb adjust room helper function.");
                return BPF_DROP;
            }
        }
    }
    return BPF_OK;
}
SEC("license") const char __license[] = "Dual BSD/GPL";