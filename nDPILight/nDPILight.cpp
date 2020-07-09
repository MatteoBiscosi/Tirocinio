#include <ndpi_light_includes.h>
/*
 * ******** Need to revise includes *********
 */
using namespace std;



ReaderThread reader_thread;
atomic_int8_t main_thread_shutdown {0};






static bool find_help(char ** begin, char ** end, const std::string& option)
/*  Function used to find if help is an option requested    */
{
    return find(begin, end, option) != end;
}

/* ********************************** */

static char * check_args(int &argc, char ** argv)
/*  Parsing of input args   */
{
    int opt;
    char * dst = nullptr;

    /*  In case of -h arg, print infos and terminate    */
    if(find_help(argv, argv + argc, "-h")) {
        cout << "nDPILight -i <file|device> \n"
             << "Usage:\n"
             << "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a\n"
             << "                            | device for live capture (comma-separated list)\n";
        return nullptr;
    }

    while((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
            case 'i':
                dst = optarg;
                break;
            default:
                cerr << "Option not valid, to check usage: " << argv[0] << " -h\n";
                return nullptr;
        }
    }

    /*  Device or File needed   */
    if(dst == nullptr) {
        cerr << "Error: no device or file specified, please check -h";
    }

    return dst;
}

/* ********************************** */

static int setup_pcap(char const * const file_or_device)
/*  Setup the reader_thread */
{
    PcapReader reader {file_or_device};

    reader_thread.pcp_rdr = reader;
    reader_thread.pcp_rdr.initFileOrDevice();

    return 0;
}

/* ********************************** */

static int setup_reader(char const * const file_or_device)
/*
 * ********** WHEN NAPATECH IS READY, NEED TO ADD THE CHECK AND SWITCH BETWEEN NAPATECH AND PCAP **********
 */
{
    /*
     * if(file_or_device != napatech) {
     *      setup_pcap();
     * }
     * else {
     *      setup_napatech();
     * }
     */

    if(setup_pcap(file_or_device) != 0) {
        return -1;
    }

    return 0;
}

/* ********************************** */

static int start_reader(void)
/*  Setting up the bitmask needed for the sighandler and starting the worker thread */
{
    sigset_t thread_signal_set, old_signal_set;

    sigfillset(&thread_signal_set);
    sigdelset(&thread_signal_set, SIGINT);
    sigdelset(&thread_signal_set, SIGTERM);

    if (pthread_sigmask(SIG_BLOCK, &thread_signal_set, &old_signal_set) != 0) {
        cerr << "Error pthread_sigmask: " << strerror(errno) << "\n";
        return -1;
    }

    /*  Run necessary threads to monitor flows  */
    if (pthread_create(&reader_thread.thread_id, nullptr,
                       processing_thread, nullptr) != 0) {
        cerr << "Error pthread_create: " << strerror(errno) << "\n";
        return -1;
    }

    /* ******* POSSIBLE LOOP NEEDED IN THE FUTURE ******* */
    //
    //for (int i = 0; i < reader_thread_count; ++i) {
    //    reader_threads[i].array_index = i;

    //    if (reader_threads[i].workflow == NULL) {
            /* no more threads should be started */
    //        break;
    //    }

    //    if (pthread_create(&reader_threads[i].thread_id, NULL,
    //                       processing_thread, &reader_threads[i]) != 0)
    //   {
    //        fprintf(stderr, "pthread_create: %s\n", strerror(errno));
    //        return 1;
    //    }
    //}

    if (pthread_sigmask(SIG_BLOCK, &old_signal_set, nullptr) != 0) {
        cerr << "Error pthread_sigmask: " << strerror(errno) << "\n";
        return -1;
    }

    return 0;
}

/* ********************************** */

static void sighandler(int signum)
{
    fprintf(stderr, "Received SIGNAL %d\n", signum);

    if (main_thread_shutdown == 0) {
        main_thread_shutdown = 1;
        if (stop_reader_threads() != 0) {
            fprintf(stderr, "Failed to stop reader threads!\n");
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "Reader threads are already shutting down, please be patient.\n");
    }
}

/* ********************************** */

int main(int argc, char * argv[])
{
    cout << "\t-----------------------------\n"
         << "\tWELCOME TO NDPI LIGHT VERSION\n"
         << "\t-----------------------------\n\n";

//    cout << "----------------------------------\n"
//         << "nDPI version: %s\n" << ndpi_revision()
//        << " API version: %u\n" << ndpi_get_api_version()
//         << "----------------------------------\n";

    char *dst;

    /*  Args check  */
    if((dst = check_args(argc, argv)) == nullptr) {
        return 0;
    }


    /*  Setting up and starting the worker thread   */
    if(setup_reader(dst) != 0) {
        cerr << "nDPILight initialization failed\n";
        return 1;
    }

    if(start_reader() != 0) {
        cerr << "nDPILight initialization failed\n";
        return 1;
    }

    /*  Setting up the sighandler bitmask   */
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);


    while (main_thread_shutdown == 0 && processing_threads_error_or_eof() == 0) {
        sleep(1);
    }

    if (main_thread_shutdown == 0 && stop_reader_threads() != 0) {
        fprintf(stderr, "%s: stop_reader_threads\n", argv[0]);
        return 1;
    }

    return 0;
}



/* ************* NEED TO CHECK THESE ************** */

/*
static int processing_threads_error_or_eof(void)
{
    for (int i = 0; i < reader_thread_count; ++i) {
        if (reader_threads[i].workflow->error_or_eof == 0) {
            return 0;
        }
    }
    return 1;
}

static int stop_reader_threads(void)
{
    unsigned long long int total_packets_processed = 0;
    unsigned long long int total_l4_data_len = 0;
    unsigned long long int total_flows_captured = 0;
    unsigned long long int total_flows_idle = 0;
    unsigned long long int total_flows_detected = 0;

    for (int i = 0; i < reader_thread_count; ++i) {
        break_pcap_loop(&reader_threads[i]);
    }

    printf("------------------------------------ Stopping reader threads\n");

    for (int i = 0; i < reader_thread_count; ++i) {
        if (reader_threads[i].workflow == NULL) {
            continue;
        }

        total_packets_processed += reader_threads[i].workflow->packets_processed;
        total_l4_data_len += reader_threads[i].workflow->total_l4_data_len;
        total_flows_captured += reader_threads[i].workflow->total_active_flows;
        total_flows_idle += reader_threads[i].workflow->total_idle_flows;
        total_flows_detected += reader_threads[i].workflow->detected_flow_protocols;

        printf("Stopping Thread %d, processed %10llu packets, %12llu bytes, total flows: %8llu, "
               "idle flows: %8llu, detected flows: %8llu\n",
               reader_threads[i].array_index, reader_threads[i].workflow->packets_processed,
               reader_threads[i].workflow->total_l4_data_len, reader_threads[i].workflow->total_active_flows,
               reader_threads[i].workflow->total_idle_flows, reader_threads[i].workflow->detected_flow_protocols);
    }
    /* total packets captured: same value for all threads as packet2thread distribution happens later */
/*
    printf("Total packets captured.: %llu\n",
           reader_threads[0].workflow->packets_captured);
    printf("Total packets processed: %llu\n", total_packets_processed);
    printf("Total layer4 data size.: %llu\n", total_l4_data_len);
    printf("Total flows captured...: %llu\n", total_flows_captured);
    printf("Total flows timed out..: %llu\n", total_flows_idle);
    printf("Total flows detected...: %llu\n", total_flows_detected);

    for (int i = 0; i < reader_thread_count; ++i) {
        if (reader_threads[i].workflow == NULL) {
            continue;
        }

        if (pthread_join(reader_threads[i].thread_id, NULL) != 0) {
            fprintf(stderr, "pthread_join: %s\n", strerror(errno));
        }

        free_workflow(&reader_threads[i].workflow);
    }

    return 0;
}

 */