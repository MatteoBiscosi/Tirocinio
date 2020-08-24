#ifndef NDPILIGHT_SUPPORT_STRUCTS_H
#define NDPILIGHT_SUPPORT_STRUCTS_H

#include "ndpi_light_includes.h"


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


