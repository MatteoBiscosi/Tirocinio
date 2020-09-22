#ifndef NDPILIGHT_SUPPORT_STRUCTS_H
#define NDPILIGHT_SUPPORT_STRUCTS_H

#include "ndpi_light_includes.h"




typedef unsigned long long ticks;


/* ********************************** */

enum flow_l3_type {
        L3_IP, L3_IP6
};

/* ********************************** */

struct ports {
    uint16_t srcPort;
    uint16_t dstPort;
};

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

/* ********************************** */



#endif //NDPILIGHT_SUPPORT_STRUCTS_H


