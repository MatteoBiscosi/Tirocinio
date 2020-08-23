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
};

#endif
