//
// Created by matteo on 08/07/2020.
//

#ifndef NDPIREVISION_FLOW_H
#define NDPIREVISION_FLOW_H


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



enum nDPI_l3_type {
    L3_IP, L3_IP6
};


#endif //NDPIREVISION_FLOW_H
