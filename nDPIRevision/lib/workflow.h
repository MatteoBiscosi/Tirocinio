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


/*
 * Struct list
 */

enum nDPI_l3_type {
    L3_IP, L3_IP6
};

struct nDPI_flow_info {
    uint32_t flow_id{};
    unsigned long long int packets_processed{};
    uint64_t first_seen{};
    uint64_t last_seen{};
    uint64_t hashval{};

    enum nDPI_l3_type l3_type;
    union {
        struct {
            uint32_t src;
            uint32_t dst;
        } v4;
        struct {
            uint64_t src[2];
            uint64_t dst[2];
        } v6;
    } ip_tuple{};

    unsigned long long int total_l4_data_len{};
    uint16_t src_port{};
    uint16_t dst_port{};

    uint8_t is_midstream_flow:1;
    uint8_t flow_fin_ack_seen:1;
    uint8_t flow_ack_seen:1;
    uint8_t detection_completed:1;
    uint8_t tls_client_hello_seen:1;
    uint8_t tls_server_hello_seen:1;
    uint8_t reserved_00:2;
    uint8_t l4_protocol{};

    struct ndpi_proto detected_l7_protocol;
    struct ndpi_proto guessed_protocol;

    struct ndpi_flow_struct * ndpi_flow{};
    struct ndpi_id_struct * ndpi_src{};
    struct ndpi_id_struct * ndpi_dst{};
};


struct nDPI_workflow {
    pcap_t * pcap_handle;

    uint8_t error_or_eof:1;

    //Unused elements
    uint8_t reserved_00:7;
    uint8_t reserved_01[3];

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_l4_data_len;
    unsigned long long int detected_flow_protocols;

    uint64_t last_idle_scan_time;
    uint64_t last_time;

    void ** ndpi_flows_active;
    unsigned long long int max_active_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int total_active_flows;

    void ** ndpi_flows_idle;
    unsigned long long int max_idle_flows;
    unsigned long long int cur_idle_flows;
    unsigned long long int total_idle_flows;

    struct ndpi_detection_module_struct * ndpi_struct;
};


struct nDPI_reader_thread {
    struct nDPI_workflow * workflow;
    pthread_t thread_id;
    int array_index;
};


/*
 * Function list
 */

static void free_workflow(struct nDPI_workflow ** workflow);
static struct nDPI_workflow * init_workflow(char const * file_or_device);


static void ndpi_flow_info_freer(void * node);
static int ip_tuple_to_string(struct nDPI_flow_info const * flow,
                              char * src_addr_str, size_t src_addr_len,
                              char * dst_addr_str, size_t dst_addr_len);
static int ip_tuples_equal(struct nDPI_flow_info const * A,
                           struct nDPI_flow_info const * B);
static int ip_tuples_compare(struct nDPI_flow_info const * A,
                             struct nDPI_flow_info const * B);
static void ndpi_idle_scan_walker(void const * A,
                                  ndpi_VISIT which,
                                  int depth,
                                  void * user_data);
static int ndpi_workflow_node_cmp(void const * A, void const * B);


static void check_for_idle_flows(struct nDPI_workflow * workflow);

static void ndpi_process_packet(uint8_t * args,
                                struct pcap_pkthdr const * header,
                                uint8_t const * packet);

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
