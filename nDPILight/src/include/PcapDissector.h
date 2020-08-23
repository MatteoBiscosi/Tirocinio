#ifndef NDPILIGHT_PCAP_DISSECTOR_H
#define NDPILIGHT_PCAP_DISSECTOR_H


#include "ndpi_light_includes.h"


class PcapDissector : public PacketDissector {
    public:
        void parsePacket(FlowInfo flow
                            Reader * & const args,
                            void * header_tmp,
                            void * packet_tmp,
                            struct ndpi_support & pkt_infos);
    private:
        /*  
         *  Process datalink layer  
         */
        int processL2(PcapReader * reader,
                    pcap_pkthdr const * header,
                    uint8_t const * packet,
                    uint16_t& type,
                    uint16_t& ip_size,
                    uint16_t& ip_offset,
                    const uint16_t& eth_offset,
                    const struct ndpi_ethhdr * & ethernet);

        /*  
         *  Set l2 infos
         */
        int setL2Ip(pcap_pkthdr const * header,
                    uint8_t const * packet,
                    uint16_t& type,
                    uint16_t& ip_size,
                    uint16_t& ip_offset,
                    const struct ndpi_iphdr * & ip,
                    struct ndpi_ipv6hdr * & ip6);

        /*  
         *  Process level3 of the packet 
         */
        int processL3(FlowInfo& flow,
                    pcap_pkthdr const * header,
                    uint8_t const * packet,
                    uint16_t& type,
                    uint16_t& ip_size,
                    uint16_t& ip_offset,
                    const struct ndpi_iphdr * & ip,
                    struct ndpi_ipv6hdr * & ip6,
                    const uint8_t * & l4_ptr,
                    uint16_t& l4_len);

        /*  
         *  Process level 4 of the packet 
         */
        int processL4(FlowInfo& flow,
                    pcap_pkthdr const * header,
                    uint8_t const * packet,
                    const uint8_t * & l4_ptr,
                    uint16_t& l4_len);

        /*  
         *  Calculate flow hash for btree find, search(insert)
         */
        int searchVal(PcapReader * & reader,
                    FlowInfo& flow,
                    void * & tree_result,
                    struct ndpi_ipv6hdr * & ip6,
                    size_t& hashed_index);

        /*  
         *  Add a new flow to the tree  
         */
        int addVal(PcapReader * & reader,
                    FlowInfo& flow,
                    FlowInfo * & flow_to_process,
                    size_t& hashed_index,
                    struct ndpi_id_struct * & ndpi_src,
                    struct ndpi_id_struct * & ndpi_dst);
};

extern PacketDissector * pkt_parser;

/*  
 *  Function called for every packet  
 */
static void process_helper(uint8_t * const args,
                           pcap_pkthdr const * const header,
                           uint8_t const * const packet)
{
    pkt_parser->processPacket(args, (void *) header, (void *) packet);
};

#endif
