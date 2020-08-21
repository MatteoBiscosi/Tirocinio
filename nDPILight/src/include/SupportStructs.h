#ifndef NDPILIGHT_SUPPORT_STRUCTS_H
#define NDPILIGHT_SUPPORT_STRUCTS_H

#include "ndpi_light_includes.h"



/* ********************************** */

struct IPv6Header_s {
    // Little endian encoding
    uint8_t ip_tclass1:4;
    uint8_t ip_v:4;
    uint8_t ip_flow1:4;
    uint8_t ip_tclass2:4;
    uint16_t ip_flow2;
    uint16_t ip_len;
    uint8_t ip_nexthdr;
    uint8_t ip_hoplim;
    uint32_t ip_src[4];
    uint32_t ip_dest[4];
}; // 40 bytes;

/* ********************************** */

struct IPv4Header_s {
    uint16_t ip_hl: 4;
    uint16_t ip_v: 4;
    uint16_t ip_tos: 8;
    uint16_t ip_len;
    uint32_t ip_id:16;
    uint32_t ip_frag_off:16;
    #define IP_DONT_FRAGMENT  0x4000
    #define IP_MORE_FRAGMENTS 0x2000
    uint32_t ip_ttl:8;
    uint32_t ip_prot:8;
    uint32_t ip_crc:16;
    uint32_t ip_src;
    uint32_t ip_dest;
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


