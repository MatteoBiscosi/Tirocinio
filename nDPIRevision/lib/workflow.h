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
#include "flow.cpp"


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



/*
 * Global variable list
 */

static int reader_thread_count = MAX_READER_THREADS;
static uint32_t flow_id = 0;



/*
 * Interface issue, how do i implement that?
 */
class nDPI_workflow_if {
public:
    static void free_workflow(nDPI_workflow **const workflow);
    static nDPI_workflow *init_workflow(char const *const file_or_device);
    static void check_for_idle_flows(nDPI_workflow *const workflow);
    static void ndpi_idle_scan_walker(void const *const A,
                                        ndpi_VISIT which,
                                        int depth,
                                        void *const user_data);

};

#endif //NDPIREVISION_WORKFLOW_H
