#ifndef NDPILIGHT_NAPATECH_READER_H
#define NDPILIGHT_NAPATECH_READER_H


#include "ndpi_light_includes.h"



class NapatechReader : public Reader {
public:

    const char *file_or_device = nullptr;

private:
    int status = 0;
    uint8_t adapterNo = 0;
    NtFlowAttr_t flowAttr;
    NtFlowStream_t flowStream;
    unsigned long long int idCounter = 0;
    unsigned long long int streamId = 1;
   

    NtConfigStream_t hCfgStream;
    NtNetStreamRx_t hNetRx;

    unsigned long long int pktCounter = 0;

public:
    explicit NapatechReader();
    explicit NapatechReader(char const * dst);

    int startRead() = 0;
    int initFileOrDevice() = 0;
    void stopRead() = 0;
    int checkEnd() = 0;

    void printStats() = 0;
    void newPacket(pcap_pkthdr const * const header) = 0;
    int newFlow(FlowInfo * & flow_to_process) = 0;

private:
    int handleErrorStatus(int status, const char* message);
    int ntplCall(NtConfigStream_t& hCfgStream, const char* str);

    int setFilters();
    int setFlow();
    int setStream();
    void getDyn(NtNetBuf_t& hNetBuffer);

    void DumpL4(NtDyn1Descr_t *pDyn1);
    void DumpIPv4(NtDyn1Descr_t *pDyn1);
    void DumpIPv6(NtDyn1Descr_t *pDyn1);
};

/* ********************************** */

struct IPv6Header_s {
    // Little endian encoding
    uint8_t ip_tclass1:4;
    uint8_t ip_v:4;
    uint8_t ip_flow1:4;
    uint8_t ip_tclass2:4;
    uint16_t ip_flow2;
    uint16_t ip_len;
    uint8_t ip_nexthdr;
    uint8_t ip_hoplim;
    uint32_t ip_src[4];
    uint32_t ip_dest[4];
}; // 40 bytes;

/* ********************************** */

struct IPv4Header_s {
    uint16_t ip_hl: 4;
    uint16_t ip_v: 4;
    uint16_t ip_tos: 8;
    uint16_t ip_len;
    uint32_t ip_id:16;
    uint32_t ip_frag_off:16;
    #define IP_DONT_FRAGMENT  0x4000
    #define IP_MORE_FRAGMENTS 0x2000
    uint32_t ip_ttl:8;
    uint32_t ip_prot:8;
    uint32_t ip_crc:16;
    uint32_t ip_src;
    uint32_t ip_dest;
}; //20 bytes

/* ********************************** */

struct UDPHeader_s {
    uint32_t udp_src:16;
    uint32_t udp_dest:16;
    uint32_t udp_len:16;
    uint32_t udp_crc:16;
}; // 8 bytes

/* ********************************** */

struct TCPHeader_s {
    uint32_t tcp_src:16;
    uint32_t tcp_dest:16;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint32_t reserved:4;
    uint32_t tcp_doff:4;
    uint32_t tcp_ec_ctl:8;
    uint32_t tcp_window:16;
    uint32_t tcp_crc:16;
    uint32_t tcp_urgp:16;
}; // 20 bytes


#endif //NDPILIGHT_NAPATECH_READER_H
