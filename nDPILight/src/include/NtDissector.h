#ifndef NDPILIGHT_NT_DISSECTOR_H
#define NDPILIGHT_NT_DISSECTOR_H


#include "ndpi_light_includes.h"


class NtDissector : public PacketDissector{
    public:
	virtual int parsePacket(FlowInfo & flow,
                                Reader * &args,
                                void * header_tmp,
                                void * packet_tmp,
                                struct ndpi_support & pkt_infos) override;    
	
    private:
        /*
         *  Function used to parse and update l4 infos
         */
        int DumpL4(FlowInfo& flow,
                    struct ndpi_support& pkt_infos);

        /*
         *  Parse ipv4 packets
         */
        int DumpIPv4(FlowInfo& flow,
                        NtDyn1Descr_t* & pDyn1,
                        uint8_t* & packet,
                        struct ndpi_support& pkt_infos);

        /*
         *  Parse ipv6 packets
         */
        int DumpIPv6(FlowInfo& flow,
                        NtDyn1Descr_t* & pDyn1,
                        uint8_t* & packet,
                        struct ndpi_support& pkt_infos);

        /*
         *  Get the dynamic descriptor of the packet
         *  and parse packets using DumpIPv6 and DumpIPv4
         */
        int getDyn(NtNetBuf_t& hNetBuffer,
                    FlowInfo& flow,
                    NtDyn1Descr_t* & pDyn1,
                    struct ndpi_support& pkt_infos);
};

#endif
