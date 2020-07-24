#include "ndpi_light_includes.h"



using namespace std;



Trace *tracer;
ReaderThread reader_thread;
int terminate_thread {0};
PacketDissector pkt_parser;


static bool find_help(char ** begin, char ** end, const std::string& option)
/*  Function used to find if help is an option requested    */
{
    return find(begin, end, option) != end;
}

/* ********************************** */

static char * check_args(int &argc, char ** argv)
/*  Parsing of input args   */
{
    int opt, tracelvl;
    char * dst = nullptr;

    /*  In case of -h arg, print infos and terminate    */
    if(find_help(argv, argv + argc, "-h")) {
        cout << "nDPILight -i <file|device> [-t <tracelevel>]\n"
             << "Usage:\n"
             << "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a\n"
             << "                            | device for live capture (comma-separated list)\n"
             << "  -t <tracelevel>           | Specify a trace level between 1 ad 6 (standard trace level is 2)\n";
        return nullptr;
    }

    while((opt = getopt(argc, argv, "i:t:")) != -1) {
        switch (opt) {
            case 't':
                tracelvl = atoi(optarg);

                if(tracelvl > 6 || tracelvl < 1) {
                    tracer->traceEvent(0, "Error: invalid trace level, please check -h\n");
                    exit(1);
                }

                if(tracelvl <= 4) {
                    tracer->set_trace_level(tracelvl);
                }
                else if(tracelvl == 5) {
                    tracer->set_trace_level(6);
                }
                else {
                    tracer->set_trace_level(9);
                }
                
                break;

            case 'i':
                dst = optarg;
                break;            

            default:
                tracer->traceEvent(0, "Option not valid, to check usage: %s\n", argv[0]);
                return nullptr;
        }
    }

    /*  Device or File needed   */
    if(dst == nullptr) {
        tracer->traceEvent(0, "Error: no device or file specified, please check -h\n");
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

    if(reader_thread.rdr->initFileOrDevice() == -1)
        return -1;

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
    tracer->traceEvent(2, "Starting reader, Thread id: %d\r\n\r\n", reader_thread.thread_id);

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
        tracer->traceEvent(0, "Error pthread_sigmask: %d\n", strerror(errno));
        return -1;
    }

    /*  Run necessary threads to monitor flows  */
    if (pthread_create(&reader_thread.thread_id, nullptr,
                       run_reader, nullptr) != 0) {
        tracer->traceEvent(0, "Error pthread_create: %d\n", strerror(errno));
        return -1;
    }

    if (pthread_sigmask(SIG_BLOCK, &old_signal_set, nullptr) != 0) {
        tracer->traceEvent(0, "Error pthread_sigmask: %d\n", strerror(errno));
        return -1;
    }

    return 0;
}

/* ********************************** */

static int stop_reader()
/*  Stop the reader_thread, it means that the program is gonna terminate soon   */
{
    reader_thread.rdr->stopRead();

    tracer->traceEvent(1, "Stopping reader, Thread id: %d\n", reader_thread.thread_id);

    struct timespec abstime;

    clock_gettime(CLOCK_REALTIME, &abstime);
    abstime.tv_sec += 10; 

    if (pthread_timedjoin_np(reader_thread.thread_id, nullptr, &abstime) != 0) {
        tracer->traceEvent(0, "Error in pthread_join: %d; Forcing termination\n", strerror(errno));
        reader_thread.rdr->printInfos();
        pcap_close(reader_thread.rdr->pcap_handle);
        return -1;
    }

    reader_thread.rdr->printInfos();

    if(reader_thread.reader_type == 1 && reader_thread.rdr != nullptr)
        delete(reader_thread.rdr);

    return 0;
}

/* ********************************** */

static void sighandler(int signum)
/*  signal handler, set up with SIGINT and SIGTERM  */
{
    tracer->traceEvent(1, "Received SIGNAL %d\n", signum);

    if (terminate_thread == 0) {
        terminate_thread = 1;        

        if (stop_reader() != 0) {
            tracer->traceEvent(0, "Failed to stop reader threads!\n");
            exit(EXIT_FAILURE);
        }
    } else {
        tracer->traceEvent(2, "Reader threads are already shutting down, please be patient.\n");
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
    cout << "-------------------------------------------------\n"
         << "\tWELCOME TO NDPI LIGHT VERSION\n"
         << "\tnDPI version: " << ndpi_revision() << "\n"
         << "\tAPI version : " << ndpi_get_api_version() << "\n"
         << "-------------------------------------------------\n\n";


    char *dst;
    tracer = new Trace();

    /*  Args check  */
    if((dst = check_args(argc, argv)) == nullptr) {
        return 0;
    }


    /*  Setting up and starting the worker thread   */
    if(setup_reader(dst) != 0) {
        tracer->traceEvent(0, "nDPILight initialization failed\n");
        return 1;
    }


    if(start_reader() != 0) {
        tracer->traceEvent(0, "nDPILight initialization failed\n");
        return 1;
    }

    /*  Setting up the sighandler bitmask   */
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);


    /*  have to find a better way of doing this job */
    while (terminate_thread == 0 && check_error_or_eof() == 0) {
        sleep(3);
    }

    if (terminate_thread == 0 && stop_reader() != 0) {
        tracer->traceEvent(2, "nDPILight: stop_reader\n");
        return 1;
    }

    delete(tracer);

    return 0;
}