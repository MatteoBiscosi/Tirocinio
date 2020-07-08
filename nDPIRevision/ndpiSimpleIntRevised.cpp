//
// Created by matteo on 07/07/2020 at 9:15.
//
#include <iostream>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <algorithm>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <unistd.h>
#include "lib/workflow.h"


/*
 * Function list
 */

static int setup_reader_threads(char const * file_or_device);
static int start_reader_threads();
static int stop_reader_threads();

static void sighandler(int signum);

static int processing_threads_error_or_eof();
static void break_pcap_loop(struct nDPI_reader_thread * reader_thread);
static void run_pcap_loop(struct nDPI_reader_thread const * reader_thread);
static void * processing_thread(void * ndpi_thread_arg);

static char * check_args(int &argc, char ** argv);
static bool find_help(char ** begin, char ** end, const std::string& option);


/*
 * Global variable list
 */

static struct nDPI_reader_thread reader_threads[MAX_READER_THREADS] = {};
static int main_thread_shutdown = 0;




int main(int argc, char **argv)
{
    /*
     * UNNEEDED CHECK, CONTROL LATER ***********
     */
    if (argc == 0) {
        return 1;
    }

    std::cout <<"----------------------------------\n"
              << "nDPI version: %s\n" << ndpi_revision()
              << " API version: %u\n" << ndpi_get_api_version()
              << "----------------------------------\n";

    char *dst = nullptr;

    if((dst = check_args(argc, argv)) == nullptr) {
        return 0;
    }

    /*
     * Startup functions, in case of unexpected error the program will terminate
     */
    if (setup_reader_threads((dst)) != 0) {
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
        if (file_or_default_device == nullptr) {
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


static int start_reader_threads()
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

        if (pthread_create(&reader_threads[i].thread_id, nullptr,
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


static int stop_reader_threads()
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
 ******************* Threads *******************
 */


static int processing_threads_error_or_eof()
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
/*
 * Sets the thread and calls for the starts of the pcap_loop
 */
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


static bool find_help(char ** begin, char ** end, const std::string& option)
{
    return std::find(begin, end, option) != end;
}


static char * check_args(int &argc, char ** argv) {
    int opt;
    char * dst;

    if(find_help(argv, argv + argc, "-h")) {
        std::cout << "usage: " << argv[0] << "[-d PCAP-FILE-OR-INTERFACE]\n";
        return nullptr;
    }

    while((opt = getopt(argc, argv, "d:")) != -1) {
        switch (opt) {
            case 'd':
                dst = optarg;
                break;
            default:
                std::cerr << "Option not valid, to check usage: " << argv[0] << " -h\n";
                return nullptr;
        }
    }

    return dst;
}