#ifndef NDPILIGHT_PCAP_DISSECTOR_H
#define NDPILIGHT_PCAP_DISSECTOR_H


#include "ndpi_light_includes.h"


class PcapDissector : public PacketDissector {
    public:
        int parsePacket(FlowInfo & flow,
                            Reader * & args,
                            void * header_tmp,
                            void * packet_tmp,
                            struct ndpi_support & pkt_infos) override;
    private:
        /*  
         *  Process datalink layer  
         */
        int processL2(PcapReader * reader,
                    pcap_pkthdr const * header,
                    uint8_t const * packet,
                    struct ndpi_support & pkt_infos);

        /*  
         *  Set l2 infos
         */
        int setL2Ip(pcap_pkthdr const * header,
                    uint8_t const * packet,
                    struct ndpi_support & pkt_infos);

        /*  
         *  Process level3 of the packet 
         */
        int processL3(FlowInfo& flow,
                    pcap_pkthdr const * header,
                    uint8_t const * packet,
                    struct ndpi_support & pkt_infos);

        /*  
         *  Process level 4 of the packet 
         */
        int processL4(FlowInfo& flow,
                    pcap_pkthdr const * header,
                    uint8_t const * packet,
                    struct ndpi_support & pkt_infos);
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
