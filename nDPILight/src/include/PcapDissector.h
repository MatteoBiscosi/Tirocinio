#ifndef NDPILIGHT_PCAP_DISSECTOR_H
#define NDPILIGHT_PCAP_DISSECTOR_H


#include "ndpi_light_includes.h"


class PcapDissector : public PacketDissector {
    public:
	PcapDissector(char *log_path, const char *type) : PacketDissector(log_path, type) {};
	PcapDissector(const char *type) : PacketDissector(type) {};        

        int parsePacket(FlowInfo & flow,
                            Reader * & args,
                            void * header_tmp,
                            void * packet_tmp,
                            PacketInfo & pkt_infos) override;
	/**
         * Print packets and bytes received
         */
        void printBriefInfos(Reader *reader) override;	
    private:
        /**  
         * Process datalink layer  
         */
        int processL2(PcapReader * reader,
                    pcap_pkthdr const * header,
                    uint8_t const * packet,
                    PacketInfo & pkt_infos);

        /**
         * Set l2 infos
         */
        int setL2Ip(pcap_pkthdr const * header,
                    uint8_t const * packet,
                    PacketInfo & pkt_infos);

        /**  
         * Process level3 of the packet 
         */
        int processL3(FlowInfo& flow,
                    pcap_pkthdr const * header,
                    uint8_t const * packet,
                    PacketInfo & pkt_infos);

        /**
         * Process level 4 of the packet 
         */
        int processL4(FlowInfo& flow,
                    pcap_pkthdr const * header,
                    uint8_t const * packet,
                    PacketInfo & pkt_infos);
};

/**
 * Function called for each packet by pcap_loop
 *
 * @par    args   = pointer to Reader
 * @par    header = pointer to the header of the packet
 * @par    packet = pointer to the packet
 *
 */
static void process_helper(uint8_t * const args,
                           pcap_pkthdr const * const header,
                           uint8_t const * const packet)
{
    PcapReader * reader = (PcapReader *) args;
    reader->getParser()->processPacket(args, (void *) header, (void *) packet);
};

#endif
