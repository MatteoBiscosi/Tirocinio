//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_PCAP_READER_H
#define NDPILIGHT_PCAP_READER_H

#include <ndpi_light_includes.h>
#include "FlowInfo.h"
#include "Reader.h"
#include "ReaderThread.h"

/*
 * ****** HAVE TO THINK IF IT'S NEEDED DYNAMIC ALLOCATION OR NOT ******
 */

class PcapReader : public Reader {
public:
    const char *file_or_device;
    pcap_t *pcap_handle = nullptr;
    int error_or_eof = 0;

private:
    unsigned long long int packets_captured = 0;
    unsigned long long int packets_processed = 0;
    unsigned long long int total_l4_data_len = 0;
    unsigned long long int detected_flow_protocols = 0;

    uint64_t last_idle_scan_time = 0;
    uint64_t last_time = 0;

    void **ndpi_flows_active = nullptr;
    unsigned long long int max_active_flows = 0;
    unsigned long long int cur_active_flows = 0;
    unsigned long long int total_active_flows = 0;

    void **ndpi_flows_idle = nullptr;
    unsigned long long int max_idle_flows = 0;
    unsigned long long int cur_idle_flows = 0;
    unsigned long long int total_idle_flows = 0;

    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    struct ndpi_detection_module_struct * ndpi_struct = nullptr;

public:
    explicit PcapReader();
    explicit PcapReader(char const * dst);
    explicit PcapReader(char const * dst, int error_or_eof);

    ~PcapReader();

    void printInfos() override;
    int initFileOrDevice() override;
    void freeReader() override;
    int checkEnd() override;

    int startRead() override;
    void stopRead() override;

    void processPacket(uint8_t * args,
                        pcap_pkthdr const * header,
                        uint8_t const * packet);


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
    int processL2(pcap_pkthdr const * header,
                   uint8_t const * packet,
                   uint16_t& type,
                   uint16_t& ip_size,
                   uint16_t& ip_offset,
                   const uint16_t& eth_offset,
                   const struct ndpi_ethhdr * & ethernet);

    int setL2Ip(pcap_pkthdr const * header,
                 uint8_t const * packet,
                 uint16_t& type,
                 uint16_t& ip_size,
                 uint16_t& ip_offset,
                 const struct ndpi_iphdr * & ip,
                 struct ndpi_ipv6hdr * & ip6);

    int processL3(FlowInfo& flow,
                  pcap_pkthdr const * header,
                  uint8_t const * packet,
                  uint16_t& type,
                  uint16_t& ip_size,
                  uint16_t& ip_offset,
                  const struct ndpi_iphdr * & ip,
                  struct ndpi_ipv6hdr * & ip6,
                  const uint8_t * & l4_ptr,
                  uint16_t& l4_len);

    int processL4(FlowInfo& flow,
                  pcap_pkthdr const * header,
                  uint8_t const * packet,
                  const uint8_t * & l4_ptr,
                  uint16_t& l4_len);

    int searchVal(FlowInfo& flow,
                  void * & tree_result,
                  struct ndpi_ipv6hdr * & ip6,
                  size_t& hashed_index,
                  int& direction_changed);

    int addVal(FlowInfo& flow,
               FlowInfo * & flow_to_process,
               size_t& hashed_index,
               struct ndpi_id_struct * & ndpi_src,
               struct ndpi_id_struct * & ndpi_dst);

    void printFlowInfos(FlowInfo * & flow_to_process,
                        const struct ndpi_iphdr * & ip,
                        struct ndpi_ipv6hdr * & ip6,
                        uint16_t& ip_size,
                        struct ndpi_id_struct * & ndpi_src,
                        struct ndpi_id_struct * & ndpi_dst,
                        uint64_t& time_ms);
};

static uint32_t flow_id = 0;

#endif //NDPILIGHT_PCAP_READER_H
