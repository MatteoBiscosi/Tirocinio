//
// Created by matteo on 07/07/2020 at 9:15.
//
#include <iostream>
#include <csignal>
#include <cstdio>
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

/*
 * Define list
 */
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
    uint32_t flow_id;
    unsigned long long int packets_processed;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t hashval;

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
    } ip_tuple;

    unsigned long long int total_l4_data_len;
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t is_midstream_flow:1;
    uint8_t flow_fin_ack_seen:1;
    uint8_t flow_ack_seen:1;
    uint8_t detection_completed:1;
    uint8_t tls_client_hello_seen:1;
    uint8_t tls_server_hello_seen:1;
    uint8_t reserved_00:2;
    uint8_t l4_protocol;

    struct ndpi_proto detected_l7_protocol;
    struct ndpi_proto guessed_protocol;

    struct ndpi_flow_struct * ndpi_flow;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;
};

struct nDPI_workflow {
    pcap_t * pcap_handle;

    uint8_t error_or_eof:1;
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
static int setup_reader_threads(char const * const file_or_device);
static int start_reader_threads(void);
static int stop_reader_threads(void);


static void free_workflow(struct nDPI_workflow ** const workflow);
static struct nDPI_workflow * init_workflow(char const * const file_or_device);


static void ndpi_flow_info_freer(void * const node);
static int ip_tuple_to_string(struct nDPI_flow_info const * const flow,
                              char * const src_addr_str, size_t src_addr_len,
                              char * const dst_addr_str, size_t dst_addr_len);
static int ip_tuples_equal(struct nDPI_flow_info const * const A,
                           struct nDPI_flow_info const * const B);
static int ip_tuples_compare(struct nDPI_flow_info const * const A,
                             struct nDPI_flow_info const * const B);
static void ndpi_idle_scan_walker(void const * const A,
                                  ndpi_VISIT which,
                                  int depth,
                                  void * const user_data);
static int ndpi_workflow_node_cmp(void const * const A, void const * const B);


static void check_for_idle_flows(struct nDPI_workflow * const workflow);
static int processing_threads_error_or_eof(void);
static void break_pcap_loop(struct nDPI_reader_thread * const reader_thread);
static void run_pcap_loop(struct nDPI_reader_thread const * const reader_thread);
static void * processing_thread(void * const ndpi_thread_arg);
static void ndpi_process_packet(uint8_t * const args,
                                struct pcap_pkthdr const * const header,
                                uint8_t const * const packet);


static void sighandler(int signum);


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
static struct nDPI_reader_thread reader_threads[MAX_READER_THREADS] = {};
static int main_thread_shutdown = 0;
static uint32_t flow_id = 0;


/*
 * Main function
 */
int main(int argc, char **argv)
{
    /*
     * UNNEEDED CHECK, CONTROL LATER ***********
     */
    if (argc == 0) {
        return 1;
    }

    std::cout << "usage: " << argv[0] <<"[PCAP-FILE-OR-INTERFACE]\n"
              <<"----------------------------------\n"
              << "nDPI version: %s\n" << ndpi_revision()
              << " API version: %u\n" << ndpi_get_api_version()
              << "----------------------------------\n";


    /*
     * Startup functions, in case of unexpected error the program will terminate
     */
    if (setup_reader_threads((argc >= 2 ? argv[1] : nullptr)) != 0) {
        std::cerr << argv[0] << ": setup_reader_threads failed\n";
        return 1;
    }

    if (start_reader_threads() != 0) {
        std::cerr << argv[0] << ": start_reader_threads failed\n";
        return 1;
    }

    //Adding signals to sighandler
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    //Waiting for terminate request
    while (main_thread_shutdown == 0 && processing_threads_error_or_eof() == 0) {
        sleep(1);
    }

    //Shutting down all the threads
    if (main_thread_shutdown == 0 && stop_reader_threads() != 0) {
        std::cerr << argv[0] << "%s: stop_reader_threads failed\n";
        return 1;
    }

    return 0;
}


/*
 ******************* Sighandler *******************
 */


static void sighandler(int signum)
{
    std::cerr << "Received SIGNAL " << signum << "\n";

    if (main_thread_shutdown == 0) {
        main_thread_shutdown = 1;
        if (stop_reader_threads() != 0) {
            std::cerr << "Failed to stop reader threads!\n";
            exit(EXIT_FAILURE);
        }
    } else {
        std::cerr << "Reader threads are already shutting down, please be patient.\n";
    }
}


/*
 ******************* Reader_threads *******************
 */


static int setup_reader_threads(char const * const file_or_device)
/*
 * Initialize the various workflows and the capture device/file
 */
{
    char const * file_or_default_device;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    /*
     * Needed check? Cannot modify reader_thread_count before this function call
     */
    if (reader_thread_count > MAX_READER_THREADS) {
        return 1;
    }

    //Setting up the capture device
    if (file_or_device == nullptr) {
        //Standard capture device

        /*
         * pcap_lookupdev DEPRECATED !!!!! check pcap_findalldevs
         */

        file_or_default_device = pcap_lookupdev(pcap_error_buffer);
        if (file_or_default_device == NULL) {
            std::cerr << "pcap_lookupdev error: " << pcap_error_buffer << "\n";
            return 1;
        }
    } else {
        //Requested capture device
        file_or_default_device = file_or_device;
    }

    for (int i = 0; i < reader_thread_count; ++i) {
        reader_threads[i].workflow = init_workflow(file_or_default_device);
        if (reader_threads[i].workflow == nullptr) {
            //Error during setup
            return 1;
        }
    }

    return 0;
}


static int start_reader_threads(void)
/*
 * Initialize the sigmask and the reader_thread threads
 */
{
    sigset_t thread_signal_set, old_signal_set;

    //Setting up the sigmask
    sigfillset(&thread_signal_set);
    sigdelset(&thread_signal_set, SIGINT);
    sigdelset(&thread_signal_set, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &thread_signal_set, &old_signal_set) != 0) {
        std::cerr << "Error pthread_sigmask: " << strerror(errno) << "\n";
        return 1;
    }

    //Setting up the reader_thread threads
    for (int i = 0; i < reader_thread_count; ++i) {
        reader_threads[i].array_index = i;

        if (reader_threads[i].workflow == nullptr) {
            //no more threads should be started
            break;
        }

        if (pthread_create(&reader_threads[i].thread_id, NULL,
                           processing_thread, &reader_threads[i]) != 0)
        {
            std::cerr << "Error pthread_create: " << strerror(errno) << "\n";
            return 1;
        }
    }

    if (pthread_sigmask(SIG_BLOCK, &old_signal_set, nullptr) != 0) {
        std::cerr << "Error pthread_sigmask: " << strerror(errno) << "\n";
        return 1;
    }

    return 0;
}


static int stop_reader_threads(void)
/*
 * Used to stop the various reader_thread
 */
{
    unsigned long long int total_packets_processed = 0;
    unsigned long long int total_l4_data_len = 0;
    unsigned long long int total_flows_captured = 0;
    unsigned long long int total_flows_idle = 0;
    unsigned long long int total_flows_detected = 0;

    for (int i = 0; i < reader_thread_count; ++i) {
        break_pcap_loop(&reader_threads[i]);
    }

    std::cout << "------------------------------------ Stopping reader threads\n";

    //Printing the flows/threads results
    for (int i = 0; i < reader_thread_count; ++i) {
        if (reader_threads[i].workflow == nullptr) {
            continue;
        }

        total_packets_processed += reader_threads[i].workflow->packets_processed;
        total_l4_data_len += reader_threads[i].workflow->total_l4_data_len;
        total_flows_captured += reader_threads[i].workflow->total_active_flows;
        total_flows_idle += reader_threads[i].workflow->total_idle_flows;
        total_flows_detected += reader_threads[i].workflow->detected_flow_protocols;

        std::cout << "Stopping Thread " << reader_threads[i].array_index
                  << ", processed " << reader_threads[i].workflow->packets_processed
                  << " packets, " << reader_threads[i].workflow->total_l4_data_len
                  << " bytes, total flows: " << reader_threads[i].workflow->total_active_flows
                  << ", idle flows: " << reader_threads[i].workflow->total_idle_flows
                  << ", detected flows: " << reader_threads[i].workflow->detected_flow_protocols << "\n";
    }

    //Total packets captured: same value for all threads as packet2thread distribution happens later
    /*
     * ************* why total packets capture is only the packets captured by the first reader_threads???? ***********
     */
    std::cout << "Total packets captured.: " << reader_threads[0].workflow->packets_captured << "\n";
    std::cout << "Total packets processed: " << total_packets_processed << "\n";
    std::cout << "Total layer4 data size.: " << total_l4_data_len << "\n";
    std::cout << "Total flows captured...: " << total_flows_captured << "\n";
    std::cout << "Total flows timed out..: " << total_flows_idle << "\n";
    std::cout << "Total flows detected...: " << total_flows_detected << "\n";

    for (int i = 0; i < reader_thread_count; ++i) {
        if (reader_threads[i].workflow == nullptr) {
            continue;
        }

        if (pthread_join(reader_threads[i].thread_id, nullptr) != 0) {
            std::cerr << "Error pthread_join: " << strerror(errno) << "\n";
        }

        free_workflow(&reader_threads[i].workflow);
    }

    return 0;
}


/*
 ******************* Workflow *******************
 */


static struct nDPI_workflow * init_workflow(char const * const file_or_device)
/*
 * Initializer of nDPI_workflow struct
 */
{
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    struct nDPI_workflow * workflow = (struct nDPI_workflow *) ndpi_calloc(1, sizeof(*workflow));

    if (workflow == nullptr) {
        return nullptr;
    }

    if (access(file_or_device, R_OK) != 0 && errno == ENOENT) {
        //trying to open a device
        workflow->pcap_handle = pcap_open_live(file_or_device, /* 1536 */ 65535, 1, 250, pcap_error_buffer);
    } else {
        //if opening the device fails, try to open a saved capture file
        workflow->pcap_handle = pcap_open_offline_with_tstamp_precision(file_or_device, PCAP_TSTAMP_PRECISION_MICRO,
                                                                        pcap_error_buffer);
    }

    //if both opening fails, return an error
    if (workflow->pcap_handle == nullptr) {
        std:cerr << "error during pcap_open_live / pcap_open_offline_with_tstamp_precision: "
                 << pcap_error_buffer << "\n";
        free_workflow(&workflow);
        return nullptr;
    }

    //Init the detection module
    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (workflow->ndpi_struct == nullptr) {
        //Error while initializing the detection module
        free_workflow(&workflow);
        return nullptr;
    }

    //Init the active flows per thread
    workflow->total_active_flows = 0;
    workflow->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
    if (workflow->ndpi_flows_active == nullptr) {
        //Error while initializing the flows
        free_workflow(&workflow);
        return nullptr;
    }

    //Init the idle flows per thread
    workflow->total_idle_flows = 0;
    workflow->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
    workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
    if (workflow->ndpi_flows_idle == nullptr) {
        free_workflow(&workflow);
        return nullptr;
    }

    //Init the protocol bitmask
    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
    ndpi_finalize_initalization(workflow->ndpi_struct);

    return workflow;
}


static void free_workflow(struct nDPI_workflow ** const workflow)
/*
 *  "Destructor" of nDPI_workflow struct
 */
{
    struct nDPI_workflow * const w = *workflow;

    if (w == nullptr) {
        return;
    }

    //Closing the capture file/device
    if (w->pcap_handle != nullptr) {
        pcap_close(w->pcap_handle);
        w->pcap_handle = nullptr;
    }

    //Exiting the detection module
    if (w->ndpi_struct != nullptr) {
        ndpi_exit_detection_module(w->ndpi_struct);
    }

    //Freeing the various flows
    for(size_t i = 0; i < w->max_active_flows; i++) {
        ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_freer);
    }
    ndpi_free(w->ndpi_flows_active);
    ndpi_free(w->ndpi_flows_idle);
    ndpi_free(w);
    *workflow = NULL;
}


static void ndpi_flow_info_freer(void * const node)
//Frees infos about the flow of node
{
    struct nDPI_flow_info * const flow = (struct nDPI_flow_info *)node;

    ndpi_free(flow->ndpi_dst);
    ndpi_free(flow->ndpi_src);
    ndpi_flow_free(flow->ndpi_flow);
    ndpi_free(flow);
}


/*
 ******************* Threads *******************
 */


static int processing_threads_error_or_eof(void)
/*
 * Checking if all threads ended their works and returning 0 otherwise
 */
{
    for (int i = 0; i < reader_thread_count; ++i) {
        if (reader_threads[i].workflow->error_or_eof == 0) {
            return 0;
        }
    }
    return 1;
}


static void * processing_thread(void * const ndpi_thread_arg)
//Sets the thread and calls for the starts of the pcap_loop
{
    struct nDPI_reader_thread const * const reader_thread =
            (struct nDPI_reader_thread *)ndpi_thread_arg;

    std::cout << "Starting ThreadID " << reader_thread->array_index << "\n";
    run_pcap_loop(reader_thread);

    //Error in pcap_loop, terminating the thread
    reader_thread->workflow->error_or_eof = 1;
    return nullptr;
}


static void run_pcap_loop(struct nDPI_reader_thread const * const reader_thread)
//Starts the pcap_loop
{
    if (reader_thread->workflow != nullptr &&
        reader_thread->workflow->pcap_handle != nullptr) {

        /*
         * ********** how does he know that reader_thread has exactly 8 bits????? *********
         */
        if (pcap_loop(reader_thread->workflow->pcap_handle, -1,
                      &ndpi_process_packet, (uint8_t *)reader_thread) == PCAP_ERROR) {
            //Error while processing the packets
            std::cerr << "Error while reading pcap file: '"
                      << pcap_geterr(reader_thread->workflow->pcap_handle)
                      << "'\n";
            reader_thread->workflow->error_or_eof = 1;
        }
    }
}


static void break_pcap_loop(struct nDPI_reader_thread * const reader_thread)
//Breaks pcap_loop
{
    if (reader_thread->workflow != nullptr &&
        reader_thread->workflow->pcap_handle != nullptr)
    {
        pcap_breakloop(reader_thread->workflow->pcap_handle);
    }
}


static int ip_tuple_to_string(struct nDPI_flow_info const * const flow,
                              char * const src_addr_str, size_t src_addr_len,
                              char * const dst_addr_str, size_t dst_addr_len)
//Converts the ip tuple into strings
{
    switch (flow->l3_type) {
        case L3_IP:
            //IPv4
            return inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.src,
                             src_addr_str, src_addr_len) != nullptr &&
                   inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.dst,
                             dst_addr_str, dst_addr_len) != nullptr;
        case L3_IP6:
            //IPv6
            return inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0],
                             src_addr_str, src_addr_len) != nullptr &&
                   inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0],
                             dst_addr_str, dst_addr_len) != nullptr;
    }

    return 0;
}

#ifdef VERBOSE
static void print_packet_info(struct nDPI_reader_thread const * const reader_thread,
                              struct pcap_pkthdr const * const header,
                              uint32_t l4_data_len,
                              struct nDPI_flow_info const * const flow)
{
    struct nDPI_workflow const * const workflow = reader_thread->workflow;
    char src_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char dst_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char buf[256];
    int used = 0, ret;

    ret = snprintf(buf, sizeof(buf), "[%8llu, %d, %4u] %4u bytes: ",
                   workflow->packets_captured, reader_thread->array_index,
                   flow->flow_id, header->caplen);
    if (ret > 0) {
        used += ret;
    }

    if (ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str)) != 0) {
        ret = snprintf(buf + used, sizeof(buf) - used, "IP[%s -> %s]", src_addr_str, dst_addr_str);
    } else {
        ret = snprintf(buf + used, sizeof(buf) - used, "IP[ERROR]");
    }
    if (ret > 0) {
        used += ret;
    }

    switch (flow->l4_protocol) {
        case IPPROTO_UDP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> UDP[%u -> %u, %u bytes]",
                           flow->src_port, flow->dst_port, l4_data_len);
            break;
        case IPPROTO_TCP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> TCP[%u -> %u, %u bytes]",
                           flow->src_port, flow->dst_port, l4_data_len);
            break;
        case IPPROTO_ICMP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> ICMP");
            break;
        case IPPROTO_ICMPV6:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> ICMP6");
            break;
        case IPPROTO_HOPOPTS:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> ICMP6 Hop-By-Hop");
            break;
        default:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> Unknown[0x%X]", flow->l4_protocol);
            break;
    }
    if (ret > 0) {
        used += ret;
    }

    printf("%.*s\n", used, buf);
}
#endif

static int ip_tuples_equal(struct nDPI_flow_info const * const A,
                           struct nDPI_flow_info const * const B)
//Defines the "equal" for a tuple
{
    /*
     * ********** POSSIBLE ERROR? WHY B->L3_TYPE == L3_IP6???? SHOULDN'T BE L3_IP???? **********
     */
    if (A->l3_type == L3_IP && B->l3_type == L3_IP6) {
        //IPv4
        return A->ip_tuple.v4.src == B->ip_tuple.v4.src &&
               A->ip_tuple.v4.dst == B->ip_tuple.v4.dst;
    } else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
        //IPv6
        return A->ip_tuple.v6.src[0] == B->ip_tuple.v6.src[0] &&
               A->ip_tuple.v6.src[1] == B->ip_tuple.v6.src[1] &&
               A->ip_tuple.v6.dst[0] == B->ip_tuple.v6.dst[0] &&
               A->ip_tuple.v6.dst[1] == B->ip_tuple.v6.dst[1];
    }
    return 0;
}

static int ip_tuples_compare(struct nDPI_flow_info const * const A,
                             struct nDPI_flow_info const * const B)
{
    /*
     * ************** SAME ERROR AS ABOVE?????? L3_IP6 ????? ***************
     */
    if (A->l3_type == L3_IP && B->l3_type == L3_IP6) {
        if (A->ip_tuple.v4.src < B->ip_tuple.v4.src ||
            A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
        {
            return -1;
        }
        if (A->ip_tuple.v4.src > B->ip_tuple.v4.src ||
            A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
        {
            return 1;
        }
    } else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
        if ((A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] &&
             A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1]) ||
            (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] &&
             A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1]))
        {
            return -1;
        }
        if ((A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] &&
             A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1]) ||
            (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] &&
             A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1]))
        {
            return 1;
        }
    }
    if (A->src_port < B->src_port ||
        A->dst_port < B->dst_port)
    {
        return -1;
    } else if (A->src_port > B->src_port ||
               A->dst_port > B->dst_port)
    {
        return 1;
    }
    return 0;
}


static void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    struct nDPI_workflow * const workflow = (struct nDPI_workflow *)user_data;
    struct nDPI_flow_info * const flow = *(struct nDPI_flow_info **)A;

    (void)depth;

    if (workflow == NULL || flow == NULL) {
        return;
    }

    if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD) {
        return;
    }

    /*
     * ************* RECHECK WHAT THIS FUNCTION DOES ********************
     */
    if (which == ndpi_preorder || which == ndpi_leaf) {
        if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
            flow->last_seen + MAX_IDLE_TIME < workflow->last_time)
        {
            char src_addr_str[INET6_ADDRSTRLEN+1];
            char dst_addr_str[INET6_ADDRSTRLEN+1];
            ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
            workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
            workflow->total_idle_flows++;
        }
    }
}


static int ndpi_workflow_node_cmp(void const * const A, void const * const B) {
//Function used to compare two nodes of the btree
    struct nDPI_flow_info const * const flow_info_a = (struct nDPI_flow_info *)A;
    struct nDPI_flow_info const * const flow_info_b = (struct nDPI_flow_info *)B;

    if (flow_info_a->hashval < flow_info_b->hashval) {
        return(-1);
    } else if (flow_info_a->hashval > flow_info_b->hashval) {
        return(1);
    }

    /* Flows have the same hash */
    if (flow_info_a->l4_protocol < flow_info_b->l4_protocol) {
        return(-1);
    } else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol) {
        return(1);
    }

    if (ip_tuples_equal(flow_info_a, flow_info_b) != 0 &&
        flow_info_a->src_port == flow_info_b->src_port &&
        flow_info_a->dst_port == flow_info_b->dst_port)
    {
        return(0);
    }

    return ip_tuples_compare(flow_info_a, flow_info_b);
}


static void check_for_idle_flows(struct nDPI_workflow * const workflow)
//Checks all the nodes, if they became idle from the last check or not
//If yes, it frees them
{
    if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time) {
        for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index) {
            ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);

            while (workflow->cur_idle_flows > 0) {
                struct nDPI_flow_info * const f =
                        (struct nDPI_flow_info *)workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
                if (f->flow_fin_ack_seen == 1) {
                    printf("Free fin flow with id %u\n", f->flow_id);
                } else {
                    printf("Free idle flow with id %u\n", f->flow_id);
                }
                ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index],
                             ndpi_workflow_node_cmp);
                ndpi_flow_info_freer(f);
                workflow->cur_active_flows--;
            }
        }

        workflow->last_idle_scan_time = workflow->last_time;
    }
}


static void ndpi_process_packet(uint8_t * const args,
                                struct pcap_pkthdr const * const header,
                                uint8_t const * const packet)
/*
 * Function called for each packets, updates the infos
 */
{
    struct nDPI_reader_thread * const reader_thread =
            (struct nDPI_reader_thread *)args;
    struct nDPI_workflow * workflow;
    struct nDPI_flow_info flow = {};

    size_t hashed_index;
    void * tree_result;
    struct nDPI_flow_info * flow_to_process;

    int direction_changed = 0;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

    const struct ndpi_ethhdr * ethernet;
    const struct ndpi_iphdr * ip;
    struct ndpi_ipv6hdr * ip6;

    uint64_t time_ms;
    const uint16_t eth_offset = 0;
    uint16_t ip_offset;
    uint16_t ip_size;

    const uint8_t * l4_ptr = NULL;
    uint16_t l4_len = 0;

    uint16_t type;

    // generated with `dd if=/dev/random bs=1024 count=1 |& hd'
    int thread_index = INITIAL_THREAD_HASH;

    if (reader_thread == nullptr) {
        return;
    }
    workflow = reader_thread->workflow;

    if (workflow == nullptr) {
        return;
    }

    workflow->packets_captured++;
    time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
    workflow->last_time = time_ms;

    check_for_idle_flows(workflow);

    /* process datalink layer */
    switch (pcap_datalink(workflow->pcap_handle)) {
        case DLT_NULL:
            //Loopback
            if (ntohl(*((uint32_t *)&packet[eth_offset])) == 0x00000002) {
                type = ETH_P_IP;
            } else {
                type = ETH_P_IPV6;
            }
            ip_offset = 4 + eth_offset;
            break;
        case DLT_EN10MB:
            //Ethernet
            if (header->len < sizeof(struct ndpi_ethhdr)) {
                std::cerr << "[" << workflow->packets_captured << ", "
                          << reader_thread->array_index
                          << "] Ethernet packet too short - skipping\n";

                return;
            }

            //Checking header protocol
            ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
            ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
            type = ntohs(ethernet->h_proto);
            switch (type) {
                case ETH_P_IP: /* IPv4 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                        std::cerr << "[" << workflow->packets_captured
                                  <<", " << reader_thread->array_index
                                  << "] IP packet too short - skipping\n";
                        return;
                    }
                    break;
                case ETH_P_IPV6: /* IPV6 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                        std::cerr << "[" << workflow->packets_captured
                                  <<", " << reader_thread->array_index
                                  << "] IP6 packet too short - skipping\n";
                        return;
                    }
                    break;
                case ETH_P_ARP: /* ARP */
                    return;
                default:
                    std::cerr << "[" << workflow->packets_captured
                              <<", " << reader_thread->array_index
                              << "] Unknown Ethernet packet with type "
                              << type << " - skipping\n";
                    return;
            }
            break;
        default:
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] Captured non IP/Ethernet packet with datalink type "
                      << pcap_datalink(workflow->pcap_handle)
                      << " - skipping\n";
            return;
    }

    if (type == ETH_P_IP) {
        //IpV4
        ip = (struct ndpi_iphdr *)&packet[ip_offset];
        ip6 = nullptr;
    } else if (type == ETH_P_IPV6) {
        //IpV6
        ip = nullptr;
        ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    } else {
        //not IpV4 nor IpV6
        std::cerr << "[" << workflow->packets_captured
                  <<", " << reader_thread->array_index
                  << "] Captured non IPv4/IPv6 packet with type "
                  << type
                  << " - skipping\n";
        return;
    }
    ip_size = header->len - ip_offset;

    if (type == ETH_P_IP && header->len >= ip_offset) {
        if (header->caplen < header->len) {
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] Captured packet size is smaller than packet size: "
                      << header->caplen << " < "
                      << header->len << "\n";
            /*
             * ************ MISS RETURN????? ***************
             */
        }
    }

    /* process layer3 e.g. IPv4 / IPv6 */
    if (ip != nullptr && ip->version == 4) {
        //IPv4
        if (ip_size < sizeof(*ip)) {
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] Packet smaller than IP4 header length: "
                      << ip_size << " < "
                      << sizeof(*ip) << "\n";
            return;
        }

        flow.l3_type = L3_IP;
        if (ndpi_detection_get_l4((uint8_t*)ip, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
        {
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] nDPI IPv4/L4 payload detection failed, L4 length: "
                      << ip_size - sizeof(*ip) << "\n";
            return;
        }

        flow.ip_tuple.v4.src = ip->saddr;
        flow.ip_tuple.v4.dst = ip->daddr;
        uint32_t min_addr = (flow.ip_tuple.v4.src > flow.ip_tuple.v4.dst ?
                             flow.ip_tuple.v4.dst : flow.ip_tuple.v4.src);
        thread_index = min_addr + ip->protocol;

    } else if (ip6 != NULL) {
        //IPv6
        if (ip_size < sizeof(ip6->ip6_hdr)) {
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] Packet smaller than IP6 header length: "
                      << ip_size << " < "
                      << sizeof(ip6->ip6_hdr) << "\n";
            return;
        }

        flow.l3_type = L3_IP6;
        if (ndpi_detection_get_l4((uint8_t*)ip6, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
        {
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] nDPI IPv6/L4 payload detection failed, L4 length: "
                      << ip_size - sizeof(*ip6) << "\n";
            return;
        }

        /*
         * ****************** WHY 2 SRC AND DST ADDRESS???? ****************************
         */
        flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
        uint64_t min_addr[2];
        if (flow.ip_tuple.v6.src[0] > flow.ip_tuple.v6.dst[0] &&
            flow.ip_tuple.v6.src[1] > flow.ip_tuple.v6.dst[1])
        {
            min_addr[0] = flow.ip_tuple.v6.dst[0];
            min_addr[1] = flow.ip_tuple.v6.dst[0];
        } else {
            min_addr[0] = flow.ip_tuple.v6.src[0];
            min_addr[1] = flow.ip_tuple.v6.src[0];
        }
        thread_index = min_addr[0] + min_addr[1] + ip6->ip6_hdr.ip6_un1_nxt;
    } else {
        std::cerr << "[" << workflow->packets_captured
                  <<", " << reader_thread->array_index
                  << "] Non IP/IPv6 protocol detected: "
                  << type << "\n";
        return;
    }

    /* process layer4 e.g. TCP / UDP */
    if (flow.l4_protocol == IPPROTO_TCP) {
        //TCP
        const struct ndpi_tcphdr * tcp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] Malformed TCP packet, packet size smaller than expected: "
                      << header->len << " < "
                      << (l4_ptr - packet) + sizeof(struct ndpi_tcphdr) << "\n";
            return;
        }

        //Checking if the packet is a mid-stream/begin-stream or fin packet
        tcp = (struct ndpi_tcphdr *)l4_ptr;
        flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
        flow.flow_ack_seen = tcp->ack;
        flow.src_port = ntohs(tcp->source);
        flow.dst_port = ntohs(tcp->dest);

    } else if (flow.l4_protocol == IPPROTO_UDP) {
        //UDP
        const struct ndpi_udphdr * udp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_udphdr)) {
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] Malformed UDP packet, packet size smaller than expected: "
                      << header->len << " < "
                      << (l4_ptr - packet) + sizeof(struct ndpi_udphdr) << "\n";
            return;
        }

        udp = (struct ndpi_udphdr *)l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);
    }

    /* distribute flows to threads while keeping stability (same flow goes always to same thread) */
    thread_index += (flow.src_port < flow.dst_port ? flow.dst_port : flow.src_port);
    thread_index %= reader_thread_count;
    if (thread_index != reader_thread->array_index) {
        return;
    }
    workflow->packets_processed++;
    workflow->total_l4_data_len += l4_len;

#ifdef VERBOSE
    print_packet_info(reader_thread, header, l4_data_len, &flow);
#endif

    /* calculate flow hash for btree find, search(insert) */
    if (flow.l3_type == L3_IP) {
        if (ndpi_flowv4_flow_hash(flow.l4_protocol, flow.ip_tuple.v4.src, flow.ip_tuple.v4.dst,
                                  flow.src_port, flow.dst_port, 0, 0,
                                  (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
        {
            flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst; // fallback
        }
    } else if (flow.l3_type == L3_IP6) {
        if (ndpi_flowv6_flow_hash(flow.l4_protocol, &ip6->ip6_src, &ip6->ip6_dst,
                                  flow.src_port, flow.dst_port, 0, 0,
                                  (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
        {
            flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
            flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
        }
    }
    flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

    hashed_index = flow.hashval % workflow->max_active_flows;
    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
    if (tree_result == nullptr) {
        /* flow not found in btree: switch src <-> dst and try to find it again */
        uint64_t orig_src_ip[2] = { flow.ip_tuple.v6.src[0], flow.ip_tuple.v6.src[1] };
        uint64_t orig_dst_ip[2] = { flow.ip_tuple.v6.dst[0], flow.ip_tuple.v6.dst[1] };
        uint16_t orig_src_port = flow.src_port;
        uint16_t orig_dst_port = flow.dst_port;

        flow.ip_tuple.v6.src[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.src[1] = orig_dst_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_src_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_src_ip[1];
        flow.src_port = orig_dst_port;
        flow.dst_port = orig_src_port;

        tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
        if (tree_result != nullptr) {
            direction_changed = 1;
        }

        flow.ip_tuple.v6.src[0] = orig_src_ip[0];
        flow.ip_tuple.v6.src[1] = orig_src_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_dst_ip[1];
        flow.src_port = orig_src_port;
        flow.dst_port = orig_dst_port;
    }

    if (tree_result == nullptr) {
        /* flow still not found, must be new */
        if (workflow->cur_active_flows == workflow->max_active_flows) {
            //Error, max active flows reached
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] max flows to track reached: "
                      << workflow->max_active_flows << ", idle "
                      << workflow->cur_idle_flows << "\n";
            return;
        }

        flow_to_process = (struct nDPI_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
        if (flow_to_process == nullptr) {
            //Error, used all the memory available
            std::cerr << "[" << workflow->packets_captured
                      <<", " << reader_thread->array_index
                      << "] Not enough memory for flow info\n";
            return;
        }

        //Updating infos and creating the necessary structs for the new flow
        workflow->cur_active_flows++;
        workflow->total_active_flows++;
        memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
        flow_to_process->flow_id = flow_id++;

        flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
        if (flow_to_process->ndpi_flow == nullptr) {
            std::cerr << "[" << workflow->packets_captured
                      << ", " << reader_thread->array_index
                      << ", " << flow_to_process->flow_id
                      << "] Not enough memory for flow struct\n";
            return;
        }
        memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

        flow_to_process->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
        if (flow_to_process->ndpi_src == nullptr) {
            std::cerr << "[" << workflow->packets_captured
                      << ", " << reader_thread->array_index
                      << ", " << flow_to_process->flow_id
                      << "] Not enough memory for src id struct\n";
            return;
        }

        flow_to_process->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
        if (flow_to_process->ndpi_dst == NULL) {
            std::cerr << "[" << workflow->packets_captured
                      << ", " << reader_thread->array_index
                      << ", " << flow_to_process->flow_id
                      << "] Not enough memory for dst id struct\n";
            return;
        }

        //Successfully added the new flow
        std::cout << "[" << workflow->packets_captured
                  << ", " << thread_index
                  << ", " << flow_to_process->flow_id
                  << "] new " << (flow_to_process->is_midstream_flow != 0 ? "midstream-" : "")
                  << "flow\n";

        if (ndpi_tsearch(flow_to_process, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == nullptr) {
            /* Possible Leak, but should not happen as we'd abort earlier. */
            return;
        }

        ndpi_src = flow_to_process->ndpi_src;
        ndpi_dst = flow_to_process->ndpi_dst;
    } else {
        //updating the old flow
        flow_to_process = *(struct nDPI_flow_info **)tree_result;

        if (direction_changed != 0) {
            ndpi_src = flow_to_process->ndpi_dst;
            ndpi_dst = flow_to_process->ndpi_src;
        } else {
            ndpi_src = flow_to_process->ndpi_src;
            ndpi_dst = flow_to_process->ndpi_dst;
        }
    }

    flow_to_process->packets_processed++;
    flow_to_process->total_l4_data_len += l4_len;
    /* update timestamps, important for timeout handling */
    if (flow_to_process->first_seen == 0) {
        flow_to_process->first_seen = time_ms;
    }
    flow_to_process->last_seen = time_ms;
    /* current packet is an TCP-ACK? */
    flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0) {
        flow_to_process->flow_fin_ack_seen = 1;
        std::cout << "[" << workflow->packets_captured
                  << ", " << thread_index
                  << ", " << flow_to_process->flow_id
                  << "] end of flow\n";
        return;
    }

    /*
     * This example tries to use maximum supported packets for detection:
     * for uint8: 0xFF
     */

    /*
     * *************** WHAT'S 0xFF???? *******************
     */
    if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFF) {
        return;
    } else if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFE) {
        /* last chance to guess something, better then nothing */
        uint8_t protocol_was_guessed = 0;
        flow_to_process->guessed_protocol =
                ndpi_detection_giveup(workflow->ndpi_struct,
                                      flow_to_process->ndpi_flow,
                                      1, &protocol_was_guessed);
        if (protocol_was_guessed != 0) {
            std::cout << "[" << workflow->packets_captured
                      << ", " << reader_thread->array_index
                      << ", " << flow_to_process->flow_id
                      << "][GUESSED] protocol: "
                      << ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.master_protocol)
                      << " | app protocol: "
                      << ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.app_protocol)
                      << " | category: "
                      << ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.category)
                      << "\n";
        } else {
            std::cout << "[" << workflow->packets_captured
                      << ", " << reader_thread->array_index
                      << ", " << flow_to_process->flow_id
                      << "][FLOW NOT CLASSIFIED]\n";
        }
    }

    flow_to_process->detected_l7_protocol =
            ndpi_detection_process_packet(workflow->ndpi_struct, flow_to_process->ndpi_flow,
                                          ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6,
                                          ip_size, time_ms, ndpi_src, ndpi_dst);

    if (ndpi_is_protocol_detected(workflow->ndpi_struct,
                                  flow_to_process->detected_l7_protocol) != 0 &&
        flow_to_process->detection_completed == 0)
    {
        if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
            flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            flow_to_process->detection_completed = 1;
            workflow->detected_flow_protocols++;
            std::cout << "[" << workflow->packets_captured
                      << ", " << reader_thread->array_index
                      << ", " << flow_to_process->flow_id
                      << "][DETECTED] protocol: "
                      << ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol)
                      << " | app protocol: "
                      << ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol)
                      << " | category: "
                      << ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.category)
                      << "\n";
        }
    }

    if (flow_to_process->ndpi_flow->num_extra_packets_checked <
        flow_to_process->ndpi_flow->max_extra_packets_to_check)
    {
        /*
         * Your business logic starts here.
         *
         * This example does print some information about
         * TLS client and server hellos if available.
         *
         * You could also use nDPI's built-in json serialization
         * and send it to a high-level application for further processing.
         *
         * EoE - End of Example
         */

        if (flow_to_process->detected_l7_protocol.master_protocol == NDPI_PROTOCOL_TLS ||
            flow_to_process->detected_l7_protocol.app_protocol == NDPI_PROTOCOL_TLS)
        {
            if (flow_to_process->tls_client_hello_seen == 0 &&
                flow_to_process->ndpi_flow->l4.tcp.tls.hello_processed != 0)
            {
                uint8_t unknown_tls_version = 0;
                std::cout << "[" << workflow->packets_captured
                          << ", " << reader_thread->array_index
                          << ", " << flow_to_process->flow_id
                          << "][TLS-CLIENT-HELLO] version: "
                          << ndpi_ssl_version2str(flow_to_process->ndpi_flow->protos.stun_ssl.ssl.ssl_version,
                                                  &unknown_tls_version)
                          << " | sni: "
                          << flow_to_process->ndpi_flow->protos.stun_ssl.ssl.client_requested_server_name
                          << " | alpn: "
                          << (flow_to_process->ndpi_flow->protos.stun_ssl.ssl.alpn != NULL ?
                              flow_to_process->ndpi_flow->protos.stun_ssl.ssl.alpn : "-")
                          << "\n";

                flow_to_process->tls_client_hello_seen = 1;
            }
            if (flow_to_process->tls_server_hello_seen == 0 &&
                flow_to_process->ndpi_flow->l4.tcp.tls.certificate_processed != 0)
            {
                uint8_t unknown_tls_version = 0;
                //std::cout << "[" << workflow->packets_captured
                //        << ", " << reader_thread->array_index
                //        << ", " << flow_to_process->flow_id
                //        << "][TLS-SERVER-HELLO] version: "
                //        << nndpi_ssl_version2str(flow_to_process->ndpi_flow->protos.stun_ssl.ssl.ssl_version,
                //                                 &unknown_tls_version)
                //        << " | common-name(s): "
                //        << flow_to_process->ndpi_flow->protos.stun_ssl.ssl.server_names_len
                //        << "issuer: "
                //        << flow_to_process->ndpi_flow->protos.stun_ssl.ssl.server_names
                //        << " | subject: "
                //        <<
                //        << "\n";
                /*
                 * ************************ HOW DO I USE THE %.*s IN C++ ******************************
                 */
                printf("[%8llu, %d, %4d][TLS-SERVER-HELLO] version: %s | common-name(s): %.*s | "
                       "issuer: %s | subject: %s\n",
                       workflow->packets_captured,
                       reader_thread->array_index,
                       flow_to_process->flow_id,
                       ndpi_ssl_version2str(flow_to_process->ndpi_flow->protos.stun_ssl.ssl.ssl_version,
                                            &unknown_tls_version),
                       flow_to_process->ndpi_flow->protos.stun_ssl.ssl.server_names_len,
                       flow_to_process->ndpi_flow->protos.stun_ssl.ssl.server_names,
                       (flow_to_process->ndpi_flow->protos.stun_ssl.ssl.issuerDN != NULL ?
                        flow_to_process->ndpi_flow->protos.stun_ssl.ssl.issuerDN : "-"),
                       (flow_to_process->ndpi_flow->protos.stun_ssl.ssl.subjectDN != NULL ?
                        flow_to_process->ndpi_flow->protos.stun_ssl.ssl.subjectDN : "-"));
                flow_to_process->tls_server_hello_seen = 1;
            }
        }
    }
}