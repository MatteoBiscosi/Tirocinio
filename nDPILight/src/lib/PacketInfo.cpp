#include "ndpi_light_includes.h"


PacketInfo::PacketInfo() {
    hashed_index = 0;
        
    time_ms = 0;
    eth_offset = 0;
    ip_offset = 0;
    ip_size = 0;
    type = 0;
        
    ndpi_src = nullptr;
    ndpi_dst = nullptr;

    ethernet = nullptr;
    ip = nullptr;
    ip6 = nullptr;

    l4_ptr = nullptr;
    l4_len = 0;

    tree_result = nullptr;

    flow_to_process = nullptr;
}


PacketInfo::~PacketInfo() {}
