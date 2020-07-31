#ifndef NDPILIGHT_CAPTURE_STATS_H
#define NDPILIGHT_CAPTURE_STATS_H

#include "ndpi_light_includes.h"


class CaptureStats {
    public:

        unsigned long long int packets_captured = 0;
        unsigned long long int discarded_bytes = 0;
        unsigned long long int ip_pkts = 0;
        unsigned long long int ip_bytes = 0;
        unsigned long long int tcp_pkts = 0;
        unsigned long long int udp_pkts = 0;
        
        unsigned long long int total_flows_captured = 0;

        struct timeval pcap_start {0, 0}, pcap_end {0, 0};

        unsigned long long int packets_processed = 0;
        unsigned long long int total_l4_data_len = 0;
        unsigned long long int total_wire_bytes = 0;

        unsigned long long int detected_flow_protocols = 0;
        unsigned long long int guessed_flow_protocols = 0;
        unsigned long long int unclassified_flow_protocols = 0;

        uint16_t* protos_cnt;
}; 



#endif //NDPILIGHT_CAPTURE_STATS_H