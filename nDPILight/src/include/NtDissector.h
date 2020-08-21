#ifndef NDPILIGHT_NT_DISSECTOR_H
#define NDPILIGHT_NT_DISSECTOR_H


#include "ndpi_light_includes.h"


class NtDissector : public PacketDissector{
    public:
	    void processPacket(void *, void *, void *);    
	
    private:
        /*
         *  Function used to parse and update l4 infos
         */
        int DumpL4(FlowInfo& flow,
                    const uint8_t * & l4_ptr);

        /*
         *  Parse ipv4 packets
         */
        int DumpIPv4(FlowInfo& flow,
                        NtDyn1Descr_t* & pDyn1,
                        uint8_t* & packet,
                        const struct ndpi_ethhdr * & ethernet,
                        const struct ndpi_iphdr * & ip,
                        struct ndpi_ipv6hdr * & ip6,
                        const uint16_t & eth_offset,
                        uint16_t & ip_offset,
                        uint16_t & ip_size,
                        uint16_t & type,
                        const uint8_t * & l4_ptr,
                        uint16_t & l4_len);

        /*
         *  Parse ipv6 packets
         */
        int DumpIPv6(FlowInfo& flow,
                        NtDyn1Descr_t* & pDyn1,
                        uint8_t* & packet,
                        const struct ndpi_ethhdr * & ethernet,
                        const struct ndpi_iphdr * & ip,
                        struct ndpi_ipv6hdr * & ip6,
                        const uint16_t & eth_offset,
                        uint16_t & ip_offset,
                        uint16_t & ip_size,
                        uint16_t & type,
                        const uint8_t * & l4_ptr,
                        uint16_t & l4_len);

        /*
         *  Get the dynamic descriptor of the packet
         *  and parse packets using DumpIPv6 and DumpIPv4
         */
        int getDyn(NtNetBuf_t& hNetBuffer,
                    FlowInfo& flow,
                    NtDyn1Descr_t* & pDyn1,
                    uint8_t* & packet,
                    const struct ndpi_ethhdr * & ethernet,
                    const struct ndpi_iphdr * & ip,
                    struct ndpi_ipv6hdr * & ip6,
                    const uint16_t & eth_offset,
                    uint16_t & ip_offset,
                    uint16_t & ip_size,
                    uint16_t & type,
                    const uint8_t * & l4_ptr,
                    uint16_t & l4_len);
        
        /*  
         *  Calculate flow hash for btree find, search(insert)
         */
        int searchVal(NapatechReader * & reader,
                        FlowInfo& flow,
                        void * & tree_result,
                        size_t& hashed_index);

        /*  
         *  Add a new flow to the tree  
         */                
        int addVal(NapatechReader * & reader,
                        FlowInfo& flow,
                        FlowInfo * & flow_to_process,
                        size_t& hashed_index,
                        struct ndpi_id_struct * & ndpi_src,
                        struct ndpi_id_struct * & ndpi_dst);

        /*  
         *  Prints all flow's infos  
         */                
        void printFlowInfos(NapatechReader * & reader,
                                        FlowInfo * & flow_to_process,
                                        const struct ndpi_iphdr * & ip,
                                        struct ndpi_ipv6hdr * & ip6,
                                        uint16_t& ip_size,
                                        struct ndpi_id_struct * & ndpi_src,
                                        struct ndpi_id_struct * & ndpi_dst,
                                        uint64_t& time_ms);
};

#endif
