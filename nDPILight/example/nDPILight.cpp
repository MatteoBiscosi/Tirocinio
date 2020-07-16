#include <ndpi_light_includes.h>
#include <reader_thread.h>
#include <pcap_reader.h>
#include <csignal>
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
        cerr << "Error: no device or file specified, please check -h\n";
    }

    return dst;
}

/* ********************************** */

static int setup_pcap(char const * const file_or_device)
/*  Setup the reader_thread */
{
    reader_thread.reader_type = 1;
    PcapReader *tmp = new PcapReader(file_or_device);
    reader_thread.rdr = tmp;

    reader_thread.rdr->initFileOrDevice();

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

static void * run_reader(void * const tmp)
/*  Reader run function, it calls for the pcap_loop */
{
    cout << "Starting reader, Thread id: " << reader_thread.thread_id << "\n";

    reader_thread.rdr->startRead();

    return nullptr;
}

/* ********************************** */

static int start_reader()
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

static int stop_reader()
/*  Stop the reader_thread, it means that the program is gonna terminate soon   */
{
    reader_thread.rdr->stopRead();

    cout << "\nStopping reader,";

    cout << "Thread id: " << reader_thread.thread_id << "\n";

    if (pthread_join(reader_thread.thread_id, nullptr) != 0) {
        cerr << "Error in pthread_join: " << strerror(errno) << "\n";
    }

    reader_thread.rdr->printInfos();

    delete(reader_thread.rdr);

    return 0;
}

/* ********************************** */

static void sighandler(int signum)
/*  signal handler, set up with SIGINT and SIGTERM  */
{
    cerr << "\n\nReceived SIGNAL " << signum << "\n";

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

static int check_error_or_eof()
/*  Checks if eof is reached in case of a Pcap file */
{
    if(reader_thread.rdr != nullptr) {
        if (reader_thread.rdr->checkEnd() == 0)
            return 0;
    }

    return -1;
}

/* ********************************** */

int main(int argc, char * argv[])
{
    cout << "\t----------------------------------------\n"
         << "\tWELCOME TO NDPI LIGHT VERSION\n"
         << "\tnDPI version: " << ndpi_revision() << "\n"
         << "\tAPI version : " << ndpi_get_api_version() << "\n"
         << "\t----------------------------------------\n\n";

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


    cout << "Setup reader finished\n";

    if(start_reader() != 0) {
        cerr << "nDPILight initialization failed\n";
        return 1;
    }
    cout << "Start reader finished\n";

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