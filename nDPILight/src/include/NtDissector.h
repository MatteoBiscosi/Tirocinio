#ifndef NDPILIGHT_NT_DISSECTOR_H
#define NDPILIGHT_NT_DISSECTOR_H


#include "ndpi_light_includes.h"


class NtDissector : public PacketDissector{
    private:
        NtDyn1Descr_t* pDyn1;
        uint8_t* packet;

        size_t hashed_index = 0;
        void * tree_result = nullptr;
        FlowInfo * flow_to_process = nullptr;

        struct ndpi_id_struct * ndpi_src = nullptr;
        struct ndpi_id_struct * ndpi_dst = nullptr;

        const struct ndpi_ethhdr * ethernet = nullptr;
        const struct ndpi_iphdr * ip = nullptr;
        struct ndpi_ipv6hdr * ip6 = nullptr;

        uint64_t time_ms = 0;
        const uint16_t eth_offset = 0;
        uint16_t ip_offset = 0;
        uint16_t ip_size = 0;
        uint16_t type = 0;

        const uint8_t * l4_ptr = nullptr;
        uint16_t l4_len = 0;

    public:
	    void processPacket(void *, void *, void *);    

    private:
        int DumpL4(FlowInfo& flow,
                    Reader * & reader);
        int DumpIPv4(FlowInfo& flow,
                        Reader * & reader);
        int DumpIPv6(FlowInfo& flow,
                        Reader * & reader);
        int getDyn(NtNetBuf_t& hNetBuffer,
                    FlowInfo& flow,
                    Reader * & reader);
        
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
