#ifndef NDPILIGHT_PACKET_INFO_H
#define NDPILIGHT_PACKET_INFO_H

#include "ndpi_light_includes.h"


class PacketInfo {
    public:
        size_t hashed_index;
        
        uint64_t time_ms;
        uint16_t eth_offset;
        uint16_t ip_offset;
        uint16_t ip_size;
        uint16_t type;
        
        struct ndpi_id_struct * ndpi_src;
        struct ndpi_id_struct * ndpi_dst;

        const struct ndpi_ethhdr * ethernet;
        const struct ndpi_iphdr * ip;
        struct ndpi_ipv6hdr * ip6;

        const uint8_t * l4_ptr;
        uint16_t l4_len;

        std::unordered_map<KeyInfo, FlowInfo, KeyHasher>::iterator tree_result;

        FlowInfo * flow_to_process;
        
    public:
        PacketInfo();
        ~PacketInfo();
};

#endif
