//
// Created by matteo on 08/07/2020.
//

#ifndef NDPIREVISION_WORKFLOW_H
#define NDPIREVISION_WORKFLOW_H


#include <iostream>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <unistd.h>


#define MAX_FLOW_ROOTS_PER_THREAD 2048
#define MAX_IDLE_FLOWS_PER_THREAD 64
/*
 * ***** What's tick resolution???? *****
 */
#define TICK_RESOLUTION 1000
#define MAX_READER_THREADS 4
#define IDLE_SCAN_PERIOD 10000 /* msec */
#define MAX_IDLE_TIME 300000 /* msec */
#define INITIAL_THREAD_HASH 0x03dd018b

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP  0x0806
#endif


class nDPI_reader_thread {
    public:
        nDPI_workflow * workflow;
        pthread_t thread_id;
        int array_index;
};



#ifdef VERBOSE
static void print_packet_info(struct nDPI_reader_thread const * const reader_thread,
                              struct pcap_pkthdr const * const header,
                              uint32_t l4_data_len,
                              struct nDPI_flow_info const * const flow);
#endif


/*
 * Global variable list
 */

static int reader_thread_count = MAX_READER_THREADS;
static uint32_t flow_id = 0;


#endif //NDPIREVISION_WORKFLOW_H
