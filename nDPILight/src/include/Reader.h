//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_READER_H
#define NDPILIGHT_READER_H

#include "ndpi_light_includes.h"



class Reader {
public:
    uint8_t error_or_eof = 0;

    pcap_t *pcap_handle = nullptr;

    uint16_t * protos_cnt;
    
    void **ndpi_flows_active = nullptr;
    unsigned long long int max_active_flows = 0;

    void **ndpi_flows_idle = nullptr;
    unsigned long long int max_idle_flows = 0;

    unsigned long long int detected_flow_protocols = 0;
    unsigned long long int guessed_flow_protocols = 0;
    unsigned long long int unclassified_flow_protocols = 0;

    struct ndpi_detection_module_struct * ndpi_struct = nullptr;
public:
    virtual ~Reader() {};

    virtual void printStats() = 0;
    virtual void newPacket(pcap_pkthdr const * const header) = 0;
    virtual int startRead() = 0;
    virtual int initFileOrDevice() = 0;
    virtual void stopRead() = 0;
    virtual int checkEnd() = 0;
    virtual int newFlow(FlowInfo * & flow_to_process) = 0;
    virtual void incrL4Ctrs(uint16_t& l4_len) = 0;
};


void ndpi_idle_scan_walker(void const * const A, 
                            ndpi_VISIT which, 
                            int depth, 
                            void * const user_data);

int ndpi_workflow_node_cmp(void const * const A, 
                            void const * const B);                 


#endif //NDPILIGHT_READER_H
