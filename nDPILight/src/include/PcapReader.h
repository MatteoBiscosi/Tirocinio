//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_PCAP_READER_H
#define NDPILIGHT_PCAP_READER_H

#include "ndpi_light_includes.h"

extern PacketDissector pkt_parser;
extern Trace *tracer;

/*
 * ****** HAVE TO THINK IF IT'S NEEDED DYNAMIC ALLOCATION OR NOT ******
 */

class PcapReader : public Reader {
public:
    const char *file_or_device;

private:
    unsigned long long int packets_processed = 0;
    unsigned long long int total_l4_data_len = 0;

    uint64_t last_idle_scan_time = 0;
    uint64_t last_time = 0;

    unsigned long long int cur_active_flows = 0;
    unsigned long long int total_active_flows = 0;

    
    unsigned long long int cur_idle_flows = 0;
    unsigned long long int total_idle_flows = 0;

    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

public:
    explicit PcapReader();
    explicit PcapReader(char const * dst);
    explicit PcapReader(char const * dst, int error_or_eof);

    ~PcapReader();

    void printInfos() override;
    int initFileOrDevice() override;
    int checkEnd() override;

    int startRead() override;
    void stopRead() override;

    
    void newPacket(pcap_pkthdr const * const header) override;
    int newFlow(FlowInfo * & flow_to_process) override;
    void incrL4Ctrs(uint16_t& l4_len) override;

    //Getters and setters
    void incrTotalIdleFlows();
    void incrCurIdleFlows();

    uint64_t getLastTime();
    void **getNdpiFlowsIdle();
    unsigned long long int getCurIdleFlows();
    unsigned long long int getTotalIdleFlows();

private:
    void checkForIdleFlows();
    int initModule();
    int initInfos();
};

#endif //NDPILIGHT_PCAP_READER_H
