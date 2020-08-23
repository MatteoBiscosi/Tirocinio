#ifndef NDPILIGHT_SUPPORT_STRUCTS_H
#define NDPILIGHT_SUPPORT_STRUCTS_H

#include "ndpi_light_includes.h"



/* ********************************** */

struct ndpi_support {
    size_t hashed_index;
    void * tree_result;
    FlowInfo * flow_to_process;

    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

    const struct ndpi_ethhdr * ethernet;
    const struct ndpi_iphdr * ip;
    struct ndpi_ipv6hdr * ip6;

    uint64_t time_ms;
    const uint16_t eth_offset;
    uint16_t ip_offset;
    uint16_t ip_size;
    uint16_t type;

    const uint8_t * l4_ptr;
    uint16_t l4_len;
}; //20 bytes

/* ********************************** */

struct UDPHeader_s {
    uint32_t udp_src:16;
    uint32_t udp_dest:16;
    uint32_t udp_len:16;
    uint32_t udp_crc:16;
}; // 8 bytes

/* ********************************** */

struct TCPHeader_s {
    uint32_t tcp_src:16;
    uint32_t tcp_dest:16;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint32_t reserved:4;
    uint32_t tcp_doff:4;
    uint32_t tcp_ec_ctl:8;
    uint32_t tcp_window:16;
    uint32_t tcp_crc:16;
    uint32_t tcp_urgp:16;
}; // 20 bytes

/* ********************************** */

struct ntpcap_ts_s {
    uint32_t sec;
    uint32_t usec;
};

/* ********************************** */

struct ntpcap_hdr_s {
    struct ntpcap_ts_s ts;
    uint32_t caplen;
    uint32_t wirelen;
};


#endif //NDPILIGHT_SUPPORT_STRUCTS_H


