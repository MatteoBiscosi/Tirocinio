#ifndef NDPILIGHT_FLOW_INFO_H
#define NDPILIGHT_FLOW_INFO_H

#include "ndpi_light_includes.h"



class FlowInfo {
public:
    uint32_t flow_id;
    unsigned long long int packets_processed;
    unsigned long long int bytes_processed;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t hashval;
    uint64_t second_hashval;

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
    uint8_t l4_protocol;
    uint8_t ended_dpi:1;

    struct ndpi_proto detected_l7_protocol;
    struct ndpi_proto guessed_protocol;

    struct ndpi_flow_struct * ndpi_flow;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

public:
    FlowInfo();

    bool operator==(const FlowInfo &other) const {
	return hashval == other.hashval;
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

    /**
     * Function used to convert this src_ip and this dst_ip to a String
     * and save them into src_addr_str and dst_addr_str respectively 
     *
     * @par    src_addr_str = string to save the src_ip
     * @par    dst_addr_str = string to save the dst_ip
     * @par    src_addr_len = length of the src address
     * @par    dst_addr_len = length of the dst address
     * @return 1 if the conversion was succesfull 0 otherwise
     *
     */
    int ipTupleToString(char * src_addr_str, size_t src_addr_len,
                        char * dst_addr_str, size_t dst_addr_len);

    /**
     * Getters and setters of this->flow.l3_type
     *
     */
    void setFlowL3Type(int A);
    int getFlowL3Type();
};


/**
 * Function used to clear dynamic memory allocated
 * by an element of type FlowInfo
 *
 * @par    node = pointer to an element of type FlowInfo
 *
 */
static void flowFreer(void * const node)
{
    FlowInfo * const flow = (FlowInfo *) node;

    if(flow == nullptr)
        return;

    if(flow->ndpi_dst != nullptr)
        ndpi_free(flow->ndpi_dst);
    if(flow->ndpi_src != nullptr)
        ndpi_free(flow->ndpi_src);
    if(flow->ndpi_flow != nullptr)
        ndpi_flow_free(flow->ndpi_flow);
    if(flow != nullptr)
        ndpi_free(flow);
}

struct KeyHasher {
    std::uint64_t operator()(const FlowInfo& k, const FlowInfo& k2) const {
        return (std::hash<uint64_t>()(k.hashval) + std::hash<uint64_t>()(k2.hashval));
    }

    std::uint64_t operator()(const FlowInfo& k) const {
        return (std::hash<uint64_t>()(k.hashval));
    }
};

#endif //NDPILIGHT_FLOW_INFO_H
