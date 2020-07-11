#include <ndpi_light_includes.h>
/*
 * ******** Need to revise includes *********
 */
using namespace std;



ReaderThread reader_thread;
atomic_int8_t terminate_thread {0};






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
    reader_thread.reader_type = 1;
    reader_thread.pcp_rdr.initFileOrDevice();

    return 0;
}

/* ********************************** */

static void break_pcap()
{
    switch (reader_thread.reader_type) {
        case 1:
            if (reader_thread.pcp_rdr.pcap_handle != nullptr) {
                pcap_breakloop(reader_thread.pcp_rdr.pcap_handle);
                reader_thread.pcp_rdr.pcap_handle = nullptr;
            }
            break;
        case 0:
            break;
    }

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

static void * run_reader(void * const tmp)
/*  Reader run function, it calls for the pcap_loop */
{
    cout << "Starting reader, Thread id: " << reader_thread.thread_id << "\n";

    switch (reader_thread.reader_type) {
        case 0:
            //Napatech
            break;
        case 1:
            //Pcap
            if(reader_thread.pcp_rdr.pcap_handle != nullptr) {
                if (pcap_loop(reader_thread.pcp_rdr.pcap_handle, -1,
                              &reader_thread.pcp_rdr.process_packet, nullptr) == PCAP_ERROR) {

                    cerr << "Error while reading using Pcap: "
                         << pcap_geterr(reader_thread.pcp_rdr.pcap_handle) << "\n";

                    reader_thread.pcp_rdr.error_or_eof = 1;
                }
            }
            break;
    }
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
                       run_reader, nullptr) != 0) {
        cerr << "Error pthread_create: " << strerror(errno) << "\n";
        return -1;
    }

    if (pthread_sigmask(SIG_BLOCK, &old_signal_set, nullptr) != 0) {
        cerr << "Error pthread_sigmask: " << strerror(errno) << "\n";
        return -1;
    }

    return 0;
}

/* ********************************** */

static int stop_reader(void)
/*  Stop the reader_thread, it means that the program is gonna terminate soon   */
{
    break_pcap();

    cout << "\t------ Stopping reader ------\t\n";

    switch (reader_thread.reader_type) {
        case 0:
            break;
        case 1:
            std::cout << "\tStopping Thread " << reader_thread.thread_id << "\n";
            reader_thread.pcp_rdr.printInfos();
            break;
    }

    if (pthread_join(reader_thread.thread_id, NULL) != 0) {
        cerr << "Error in pthread_join: " << strerror(errno) << "\n";
    }

    switch (reader_thread.reader_type) {
        case 0:
            break;
        case 1:
            reader_thread.pcp_rdr.freeReader();
            break;
    }

    return 0;
}

/* ********************************** */

static void sighandler(int signum)
/*  signal handler, set up with SIGINT and SIGTERM  */
{
    cerr << "Received SIGNAL " << signum << "\n";

    if (terminate_thread == 0) {
        terminate_thread = 1;

        if (stop_reader() != 0) {
            cerr << "Failed to stop reader threads!\n";
            exit(EXIT_FAILURE);
        }
    } else {
        cerr << "Reader threads are already shutting down, please be patient.\n";
    }
}

/* ********************************** */

static int check_error_or_eof(void)
/*  Checks if eof is reached in case of a Pcap file */
{
    //Napatech
    if(reader_thread.reader_type == 0) {

    }
    //Pcap
    else {
        if(reader_thread.pcp_rdr.error_or_eof == 0) {
            return 0;
        }
    }

    return -1;
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


    /*  have to find a better way of doing this job */
    while (terminate_thread == 0 && check_error_or_eof() == 0) {
        sleep(1);
    }

    if (terminate_thread == 0 && stop_reader() != 0) {
        cerr << "nDPILight: stop_reader\n";
        return 1;
    }

    return 0;
}
