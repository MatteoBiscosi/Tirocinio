#ifndef NDPILIGHT_NT_DISSECTOR_H
#define NDPILIGHT_NT_DISSECTOR_H


#include "ndpi_light_includes.h"


class NtDissector : public PacketDissector{
    public:
        NtDissector(char *log_path, const char *type) : PacketDissector(log_path, type) {};
        NtDissector(const char *type) : PacketDissector(type) {};	
        int parsePacket(FlowInfo & flow,
                            Reader * &args,
                            void * header_tmp,
                            void * packet_tmp,
                            PacketInfo & pkt_infos) override;    
	
	/**
         * Print packets and bytes received
         */
        void printBriefInfos(Reader *reader) override;
    private:

        /**
         * Parse ipv4 packets
         */
        int DumpIPv4(Reader * & reader,
                        FlowInfo& flow,
                        NtDyn1Descr_t* & pDyn1,
                        uint8_t* & packet,
                        PacketInfo& pkt_infos);

        /**
         * Parse ipv6 packets
         */
        int DumpIPv6(Reader * & reader,
                        FlowInfo& flow,
                        NtDyn1Descr_t* & pDyn1,
                        uint8_t* & packet,
                        PacketInfo& pkt_infos);

};

#endif
