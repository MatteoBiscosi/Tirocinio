#ifndef NDPILIGHT_NT_DISSECTOR_H
#define NDPILIGHT_NT_DISSECTOR_H


#include "ndpi_light_includes.h"


class NtDissector : public PacketDissector{
    private:

    public:
	    void processPacket(void *, void *, void *);    

    private:
        int DumpL4(FlowInfo& flow,
                    Reader * & reader,
                    NtDyn1Descr_t* & pDyn1,
                    uint8_t* & packet,
                    size_t & hashed_index,
                    void * & tree_result,
                    FlowInfo * & flow_to_process,
                    struct ndpi_id_struct * & ndpi_src,
                    struct ndpi_id_struct * & ndpi_dst,
                    const struct ndpi_ethhdr * & ethernet,
                    const struct ndpi_iphdr * & ip,
                    struct ndpi_ipv6hdr * & ip6,
                    uint64_t & time_ms;
                    const uint16_t & eth_offset;
                    uint16_t & ip_offset;
                    uint16_t & ip_size;
                    uint16_t & type;
                    const uint8_t * & l4_ptr;
                    uint16_t & l4_len);
        int DumpIPv4(FlowInfo& flow,
                        Reader * & reader,
                        NtDyn1Descr_t* & pDyn1,
                        uint8_t* & packet,
                        size_t & hashed_index,
                        void * & tree_result,
                        FlowInfo * & flow_to_process,
                        struct ndpi_id_struct * & ndpi_src,
                        struct ndpi_id_struct * & ndpi_dst,
                        const struct ndpi_ethhdr * & ethernet,
                        const struct ndpi_iphdr * & ip,
                        struct ndpi_ipv6hdr * & ip6,
                        uint64_t & time_ms;
                        const uint16_t & eth_offset;
                        uint16_t & ip_offset;
                        uint16_t & ip_size;
                        uint16_t & type;
                        const uint8_t * & l4_ptr;
                        uint16_t & l4_len);
        int DumpIPv6(FlowInfo& flow,
                        Reader * & reader,
                        NtDyn1Descr_t* & pDyn1,
                        uint8_t* & packet,
                        size_t & hashed_index,
                        void * & tree_result,
                        FlowInfo * & flow_to_process,
                        struct ndpi_id_struct * & ndpi_src,
                        struct ndpi_id_struct * & ndpi_dst,
                        const struct ndpi_ethhdr * & ethernet,
                        const struct ndpi_iphdr * & ip,
                        struct ndpi_ipv6hdr * & ip6,
                        uint64_t & time_ms;
                        const uint16_t & eth_offset;
                        uint16_t & ip_offset;
                        uint16_t & ip_size;
                        uint16_t & type;
                        const uint8_t * & l4_ptr;
                        uint16_t & l4_len);
        int getDyn(NtNetBuf_t& hNetBuffer,
                    FlowInfo& flow,
                    Reader * & reader,
                    NtDyn1Descr_t* & pDyn1,
                    uint8_t* & packet,
                    size_t & hashed_index,
                    void * & tree_result,
                    FlowInfo * & flow_to_process,
                    struct ndpi_id_struct * & ndpi_src,
                    struct ndpi_id_struct * & ndpi_dst,
                    const struct ndpi_ethhdr * & ethernet,
                    const struct ndpi_iphdr * & ip,
                    struct ndpi_ipv6hdr * & ip6,
                    uint64_t & time_ms;
                    const uint16_t & eth_offset;
                    uint16_t & ip_offset;
                    uint16_t & ip_size;
                    uint16_t & type;
                    const uint8_t * & l4_ptr;
                    uint16_t & l4_len);
        
        int searchVal(Reader * & reader,
                            FlowInfo& flow,
                            void * & tree_result,
                            struct ndpi_ipv6hdr * & ip6,
                            size_t& hashed_index);
        int addVal(Reader * & reader,
                                FlowInfo& flow,
                                FlowInfo * & flow_to_process,
                                size_t& hashed_index,
                                struct ndpi_id_struct * & ndpi_src,
                                struct ndpi_id_struct * & ndpi_dst);
        void printFlowInfos(Reader * & reader,
                                        FlowInfo * & flow_to_process,
                                        const struct ndpi_iphdr * & ip,
                                        struct ndpi_ipv6hdr * & ip6,
                                        uint16_t& ip_size,
                                        struct ndpi_id_struct * & ndpi_src,
                                        struct ndpi_id_struct * & ndpi_dst,
                                        uint64_t& time_ms);

        void updateOldFlow(FlowInfo& flow,
                            Reader * & reader,
                            size_t & hashed_index,
                            void * & tree_result,
                            struct ndpi_ipv6hdr * & ip6);
        void createNewFlow(FlowInfo& flow,
                            Reader * & reader,
                            size_t & hashed_index,
                            FlowInfo * & flow_to_process,
                            struct ndpi_id_struct * & ndpi_src,
                            struct ndpi_id_struct * & ndpi_dst);
};



struct ntpcap_ts_s {
    uint32_t sec;
    uint32_t usec;
};

struct ntpcap_hdr_s {
    struct ntpcap_ts_s ts;
    uint32_t caplen;
    uint32_t wirelen;
};

#endif
