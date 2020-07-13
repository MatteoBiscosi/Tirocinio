//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_NDPI_LIGHT_INCLUDES_H
#define NDPILIGHT_NDPI_LIGHT_INCLUDES_H

#include <iostream>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <algorithm>
#include <memory>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <unistd.h>
#include <atomic>
#include <reader.h>
#include <pcap_reader.h>
#include <napatech_reader.h>
#include <reader_thread.h>
#include <flow_info.h>
//#include <ndpi_main.h>


#define MAX_FLOW_ROOTS_PER_THREAD 2048
#define MAX_IDLE_FLOWS_PER_THREAD 64
#define INITIAL_THREAD_HASH 0x03dd018b
#define TICK_RESOLUTION 1000
#define IDLE_SCAN_PERIOD 10000 /* msec */
#define MAX_IDLE_TIME 300000 /* msec */

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP  0x0806
#endif




#endif //NDPILIGHT_NDPI_LIGHT_INCLUDES_H