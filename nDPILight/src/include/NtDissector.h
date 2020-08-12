#ifndef NDPILIGHT_NT_DISSECTOR_H
#define NDPILIGHT_NT_DISSECTOR_H


#include "ndpi_light_includes.h"


class NtDissector : PacketDissector{
    private:
        NtDyn1Descr_t* pDyn1;
        uint8_t* packet;

    public:
	void processPacket(void *, void *, void *);    

    private:
	void DumpL4(NtDyn1Descr_t * &);
	void DumpIPv4(NtDyn1Descr_t * &);
	void DumpIPv6(NtDyn1Descr_t * &);
	void getDyn(NtNetBuf_s * &);
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
