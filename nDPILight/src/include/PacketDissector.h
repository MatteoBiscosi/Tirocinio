#ifndef NDPILIGHT_PACKET_DISSECTOR_H
#define NDPILIGHT_PACKET_DISSECTOR_H


#include "ndpi_light_includes.h"


class PacketDissector {
    public:

        CaptureStats captured_stats;

    public:
	/*  
         *  This function is called every time a new packets appears;
         *  it process all the packets, adding new flows, updating infos, ecc.  
         */
        virtual void processPacket(void * args,
                                    void * header,
                                    void * packet);
};


#endif
