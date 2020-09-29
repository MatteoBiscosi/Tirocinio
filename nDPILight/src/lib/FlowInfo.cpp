//
// Created by matteo on 12/07/2020.
//
#include "ndpi_light_includes.h"




/* ********************************** */

FlowInfo::FlowInfo()
{
    flow_id = 0;
    packets_processed = 0;
    bytes_processed = 0;
    hashval = 0;
    total_l4_data_len = 0;
    src_port = 0;
    dst_port = 0;
}

/* ********************************** */

int FlowInfo::ipTupleToString(char * const src_addr_str, size_t src_addr_len,
                              char * const dst_addr_str, size_t dst_addr_len)
{
    switch (this->l3_type) {
        case L3_IP:
            return inet_ntop(AF_INET, (struct sockaddr_in *)&this->ip_tuple.v4.src,
                             src_addr_str, src_addr_len) != nullptr &&
                   inet_ntop(AF_INET, (struct sockaddr_in *)&this->ip_tuple.v4.dst,
                             dst_addr_str, dst_addr_len) != nullptr;
        case L3_IP6:
            return inet_ntop(AF_INET6, (struct sockaddr_in6 *)&this->ip_tuple.v6.src[0],
                             src_addr_str, src_addr_len) != nullptr &&
                   inet_ntop(AF_INET6, (struct sockaddr_in6 *)&this->ip_tuple.v6.dst[0],
                             dst_addr_str, dst_addr_len) != nullptr;
    }

    return 0;
}

/*  Getters and Setters  */
/* ********************************** */

void FlowInfo::setFlowL3Type(int const type)
{
    if(type == 4)
        this->l3_type = L3_IP;
    else
        this->l3_type = L3_IP6;
}

/* ********************************** */

int FlowInfo::getFlowL3Type()
{
    if(this->l3_type == L3_IP)
        return 4;
    else
        return 6;
}

/* ********************************** */
