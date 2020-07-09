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
