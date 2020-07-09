//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_PCAP_READER_H
#define NDPILIGHT_PCAP_READER_H

#include <ndpi_light_includes.h>

/*
 * ****** HAVE TO THINK IF IT'S NEEDED DYNAMIC ALLOCATION OR NOT ******
 */

class PcapReader : Reader {
public:
    const char *file_or_device;
    pcap_t *pcap_handle;


private:
    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_l4_data_len;
    unsigned long long int detected_flow_protocols;

    uint64_t last_idle_scan_time;
    uint64_t last_time;

    void **ndpi_flows_active;
    unsigned long long int max_active_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int total_active_flows;

    void **ndpi_flows_idle;
    unsigned long long int max_idle_flows;
    unsigned long long int cur_idle_flows;
    unsigned long long int total_idle_flows;

    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    struct ndpi_init_detection_module *ndpi_struct;

public:
    explicit PcapReader();
    explicit PcapReader(char const * dst);

    int initFileOrDevice();
    int prova();

private:
    int init_module();
    int init_infos();
};


#endif //NDPILIGHT_PCAP_READER_H
