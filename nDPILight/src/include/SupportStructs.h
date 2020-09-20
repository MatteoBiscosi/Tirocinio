#ifndef NDPILIGHT_SUPPORT_STRUCTS_H
#define NDPILIGHT_SUPPORT_STRUCTS_H

#include "ndpi_light_includes.h"




typedef unsigned long long ticks;

/* ********************************** */

inline uint64_t fibonacci_hash(uint64_t hash) {
    return hash * 11400714819323198485llu;
};

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

struct KeyInfo {
    uint64_t hashval;
    flow_l3_type l3_type;

    union {
        struct {
            uint32_t src;
            uint32_t dst;
        } v4;
        struct {
            uint64_t src[2];
            uint64_t dst[2];
        } v6;
    } ip_tuple;

    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const KeyInfo &other) const {
        if(l3_type == L3_IP)
            return (hashval == other.hashval &&
                    ip_tuple.v4.src == other.ip_tuple.v4.src &&
                    ip_tuple.v4.dst == other.ip_tuple.v4.dst &&
                    src_port == other.src_port &&
                    dst_port == other.dst_port);
	else
	    return (hashval == other.hashval &&
                    ip_tuple.v6.src[0] == other.ip_tuple.v6.src[0] &&
		    ip_tuple.v6.src[1] == other.ip_tuple.v6.src[1] &&
                    ip_tuple.v6.dst[0] == other.ip_tuple.v6.dst[0] &&
                    ip_tuple.v6.dst[1] == other.ip_tuple.v6.dst[1] &&
                    src_port == other.src_port &&
                    dst_port == other.dst_port);
    };
};

/* ********************************** */

struct KeyHasher {
    std::uint64_t operator()(const KeyInfo& k) const {
        return (std::hash<uint64_t>()(fibonacci_hash(k.hashval)));
    }
};



#endif //NDPILIGHT_SUPPORT_STRUCTS_H


