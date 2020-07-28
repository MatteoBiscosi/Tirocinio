//
// Created by matteo on 12/07/2020.
//
#include "ndpi_light_includes.h"




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

/* ********************************** */

int FlowInfo::ipTuplesEqual(FlowInfo const * const B)
{
    if (this->l3_type == L3_IP && B->l3_type == L3_IP) {
        return this->ip_tuple.v4.src == B->ip_tuple.v4.src &&
               this->ip_tuple.v4.dst == B->ip_tuple.v4.dst;
    } else if (this->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
        return this->ip_tuple.v6.src[0] == B->ip_tuple.v6.src[0] &&
               this->ip_tuple.v6.src[1] == B->ip_tuple.v6.src[1] &&
               this->ip_tuple.v6.dst[0] == B->ip_tuple.v6.dst[0] &&
               this->ip_tuple.v6.dst[1] == B->ip_tuple.v6.dst[1];
    }
    return 0;
}

/* ********************************** */

int FlowInfo::ipTuplesCompare(FlowInfo const * const B)
{
    /*  IPv4    */
    if (this->l3_type == L3_IP && B->l3_type == L3_IP) {
        if (this->ip_tuple.v4.src < B->ip_tuple.v4.src ||
            this->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
        {
            /*  Minor   */
            return -1;
        }
        if (this->ip_tuple.v4.src > B->ip_tuple.v4.src ||
            this->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
        {
            /*  Major   */
            return 1;
        }
        /*  IPv6    */
    } else if (this->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
        if ((this->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] &&
             this->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1]) ||
            (this->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] &&
             this->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1]))
        {
            /*  Minor   */
            return -1;
        }
        if ((this->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] &&
             this->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1]) ||
            (this->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] &&
             this->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1]))
        {
            /*  Major   */
            return 1;
        }
    }
    /*  Port    */
    if (this->src_port < B->src_port ||
        this->dst_port < B->dst_port)
    {
        /*  Minor   */
        return -1;
    } else if (this->src_port > B->src_port ||
               this->dst_port > B->dst_port)
    {
        /*  Major   */
        return 1;
    }

    /*  Equals  */
    return 0;
}

/* ********************************** */
/*  Getters and Setters  */

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