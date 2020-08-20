#ifndef NDPILIGHT_NAPATECH_READER_H
#define NDPILIGHT_NAPATECH_READER_H


#include "ndpi_light_includes.h"




extern PacketDissector * pkt_parser;
extern Trace * tracer;


class NapatechReader : public Reader {
public:

    const char *file_or_device = nullptr;

private:
    bool newFlow;
    uint8_t adapterNo;
    NtFlowAttr_t flowAttr;

    NtNetStreamRx_t hNetRxAny;
    NtNetBuf_t hNetBufferAny;

    NtNetStreamRx_t hNetRxUnh;
    NtNetBuf_t hNetBufferUnh;

    NtConfigStream_t hCfgStream;

    NtFlowStream_t * flowStream;

    uint64_t last_idle_scan_time = 0;
    uint64_t last_time = 0;
    size_t idle_scan_index = 0;
    size_t max_idle_scan_index = 0;

    unsigned long long int last_packets_scan = 0;    

    unsigned long long int cur_active_flows = 0;
    unsigned long long int total_active_flows = 0;
    
    unsigned long long int cur_idle_flows = 0;
    unsigned long long int total_idle_flows = 0;

public:
    explicit NapatechReader();
    explicit NapatechReader(char const * dst);

    int startRead() override;
    int initFileOrDevice() override;
    void stopRead() override;
    int checkEnd() override;

    void printStats() override;
    void newPacket(void * header) override;
    int newFlow(FlowInfo * & flow_to_process) override;
    
    /*      Getters and setters       */
    void incrTotalIdleFlows();
    void incrCurIdleFlows();
    uint64_t getLastTime();
    void **getNdpiFlowsIdle();    
    unsigned long long int getCurIdleFlows();
    unsigned long long int getTotalIdleFlows();
    void setNewFlow(bool flow) { newFlow = flow; };
    bool getNewFlow() { return newFlow; };
private:
    void checkForIdleFlows();

    int initInfos();
    int initModule();
    int initConfig(NtFlowAttr_t& flowAttr,
                    NtFlowStream_t& flowStream,
                    NtConfigStream_t& hCfgStream);
    void openStreams();

    void taskReceiverMiss(const char* streamName, uint32_t streamId);
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

/* ********************************** */


#endif //NDPILIGHT_NAPATECH_READER_H
