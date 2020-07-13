//
// Created by matteo on 12/07/2020.
//

#ifndef NDPILIGHT_FLOW_INFO_H
#define NDPILIGHT_FLOW_INFO_H

#include <ndpi_light_includes.h>


class FlowInfo {
public:
    uint32_t flow_id;
    unsigned long long int packets_processed;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t hashval;

    enum flow_l3_type {
        L3_IP, L3_IP6
    };

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

    unsigned long long int total_l4_data_len;
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t is_midstream_flow:1;
    uint8_t flow_fin_ack_seen:1;
    uint8_t flow_ack_seen:1;
    uint8_t detection_completed:1;
    uint8_t tls_client_hello_seen:1;
    uint8_t tls_server_hello_seen:1;
    uint8_t reserved_00:2;
    uint8_t l4_protocol;

    struct ndpi_proto detected_l7_protocol;
    struct ndpi_proto guessed_protocol;

    struct ndpi_flow_struct * ndpi_flow;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

public:
    void infoFreer();
    int ipTupleToString(char * src_addr_str, size_t src_addr_len,
                           char * dst_addr_str, size_t dst_addr_len);
    int ipTuplesEqual(FlowInfo const * B);
    int ipTuplesCompare(FlowInfo const * B);
};

#endif //NDPILIGHT_FLOW_INFO_H
