#include "ndpi_light_includes.h"



using namespace std;



Trace *tracer;
ReaderThread reader_thread;
int terminate_thread {0};
int generate_logs {0};
PacketDissector * pkt_parser;
uint32_t mask;



static bool find_help(char ** begin, char ** end, const string& option)
/*  Function used to find if help is an option requested    */
{
    return find(begin, end, option) != end;
}

static bool starts_with(const char *file_or_device, const char *marker)
/*  Function used to know if file_or_device is a nt or not  */
{ 
   if(strstr(file_or_device, marker) == file_or_device)
        return true;
    else
        return false;
}

static int dirExists(const char* const path)
{
    struct stat info;

    int statRC = stat( path, &info );
    if( statRC != 0 )
    {
        if (errno == ENOENT)  { return 0; } // something along the path does not exist
        if (errno == ENOTDIR) { return 0; } // something in path prefix is not a dir
        return -1;
    }

    return ( info.st_mode & S_IFDIR ) ? 1 : 0;
}

/* ********************************** */

static int parseMask(char * tmp)
/*  Parsing option for setting risk mask's bits */
{    
        if(!strcmp(tmp, "URL_POSSIBLE_XSS"))
            NDPI_SET_BIT(mask, 1);
        else if(!strcmp(tmp, "URL_POSSIBLE_SQL_INJECTION"))
            NDPI_SET_BIT(mask, 2);
        else if(!strcmp(tmp, "URL_POSSIBLE_RCE_INJECTION"))
            NDPI_SET_BIT(mask, 3);
        else if(!strcmp(tmp, "BINARY_APPLICATION_TRANSFER"))
            NDPI_SET_BIT(mask, 4);
        else if(!strcmp(tmp, "KNOWN_PROTOCOL_ON_NON_STANDARD_PORT"))
            NDPI_SET_BIT(mask, 5);
        else if(!strcmp(tmp, "TLS_SELFSIGNED_CERTIFICATE"))
            NDPI_SET_BIT(mask, 6);
        else if(!strcmp(tmp, "NDPI_TLS_OBSOLETE_VERSION"))
            NDPI_SET_BIT(mask, 7);
	else if(!strcmp(tmp, "TLS_WEAK_CIPHER"))
            NDPI_SET_BIT(mask, 8);
        else if(!strcmp(tmp, "TLS_CERTIFICATE_EXPIRED"))
            NDPI_SET_BIT(mask, 9);
        else if(!strcmp(tmp, "TLS_CERTIFICATE_MISMATCH"))
            NDPI_SET_BIT(mask, 10);
        else if(!strcmp(tmp, "HTTP_SUSPICIOUS_USER_AGENT"))
            NDPI_SET_BIT(mask, 11);
        else if(!strcmp(tmp, "HTTP_NUMERIC_IP_HOST"))
            NDPI_SET_BIT(mask, 12);
        else if(!strcmp(tmp, "HTTP_SUSPICIOUS_URL"))
            NDPI_SET_BIT(mask, 13);
        else if(!strcmp(tmp, "HTTP_SUSPICIOUS_HEADER"))
            NDPI_SET_BIT(mask, 14);
        else if(!strcmp(tmp, "TLS_NOT_CARRYING_HTTPS"))
            NDPI_SET_BIT(mask, 15);
        else if(!strcmp(tmp, "SUSPICIOUS_DGA_DOMAIN"))
            NDPI_SET_BIT(mask, 16);
        else if(!strcmp(tmp, "MALFORMED_PACKET"))
            NDPI_SET_BIT(mask, 17);
        else if(!strcmp(tmp, "SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER"))
            NDPI_SET_BIT(mask, 18);
        else if(!strcmp(tmp, "SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER"))
            NDPI_SET_BIT(mask, 19);
        else if(!strcmp(tmp, "SMB_INSECURE_VERSION"))
            NDPI_SET_BIT(mask, 20);
        else if(!strcmp(tmp, "TLS_SUSPICIOUS_ESNI_USAGE"))
            NDPI_SET_BIT(mask, 21);
        else if(!strcmp(tmp, "UNSAFE_PROTOCOL"))
            NDPI_SET_BIT(mask, 22);
        else if(!strcmp(tmp, "none")) {
            NDPI_BITMASK_RESET(mask);
	    return 1;
	}
	else
            return -1;	    

    return 0;
}

/* ********************************** */

static char * check_args(int &argc, char ** argv)
/*  Parsing of input args   */
{
    int opt, tracelvl;
    char * dst = nullptr;
    char * stringMask = nullptr; 

    /*  In case of -h arg, print infos and terminate    */
    if(find_help(argv, argv + argc, "-h")) {
        cout << "nDPILight -i <file|device> [-t <tracelevel>]\n"
             << "Usage:\n"
             << "  -i <file.pcap|device>       | Specify a pcap file/playlist to read packets from or a\n"
             << "                              | device for live capture (comma-separated list)\n"
             << "  -t <tracelevel>             | Specify a trace level between 1 ad 6 (standard trace level is 2)\n"
             << "  -r none|risk1|risk2[,...]   | Specify which situation is a risk (default is, each situation is a risk).\n"
             << "                              | Possible risks are: URL_POSSIBLE_XSS | URL_POSSIBLE_SQL_INJECTION | URL_POSSIBLE_RCE_INJECTION |\n"
             << "                              |                     BINARY_APPLICATION_TRANSFER | KNOWN_PROTOCOL_ON_NON_STANDARD_PORT |\n"
             << "                              |                     TLS_SELFSIGNED_CERTIFICATE | TLS_OBSOLETE_VERSION | TLS_WEAK_CIPHER |\n"
             << "                              |                     TLS_CERTIFICATE_EXPIRED | TLS_CERTIFICATE_MISMATCH | HTTP_SUSPICIOUS_USER_AGENT |\n"
             << "                              |                     HTTP_NUMERIC_IP_HOST | HTTP_SUSPICIOUS_URL | HTTP_SUSPICIOUS_HEADER |\n"
             << "                              |                     TLS_NOT_CARRYING_HTTPS | SUSPICIOUS_DGA_DOMAIN | MALFORMED_PACKET |\n"
             << "                              |                     SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER | SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER |\n"
             << "                              |                     SMB_INSECURE_VERSION | TLS_SUSPICIOUS_ESNI_USAGE | UNSAFE_PROTOCOL\n"
             << "  -v                          | Creates a log file about every flow after detecting level 7 protocol (by default\n"
             << "                              | it's created when a flow hits a risk specified with -r option)\n";
        return nullptr;
    }

    while((opt = getopt(argc, argv, "i:t:r:v")) != -1) {
        switch (opt) {
            case 't':
                tracelvl = atoi(optarg);

                if(tracelvl > 6 || tracelvl < 0) {
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

            case 'v':
                generate_logs = 1;
                break;

            case 'r': {
                if(optarg != nullptr) {
                        NDPI_BITMASK_RESET(mask);
                    }
                char *next;
                int index = optind - 1;
                    while(index < argc) {
                        next = strdup(argv[index]);
                        index++;
                        if(next[0] != '-') {
                int status = parseMask(next);
                            if(status == -1) {
                    tracer->traceEvent(0, "Risk parameter not valid, to check risk list: %s - h\n", argv[0]);
                    return nullptr;
                } else if(status == 1) {
                    break;
                }
                        }
                        else 
                            break;
                    }
		        optind = index - 1;
                break; 
	        }
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
    PcapReader *tmp = new PcapReader(file_or_device);
    reader_thread.initReader(tmp);

    pkt_parser = new PcapDissector();

    if(reader_thread.init() == -1)
        return -1;

    return 0;
}

/* ********************************** */

static int setup_napatech()
/*  Setup the reader_thread */
{
    NapatechReader *tmp = new NapatechReader();
    reader_thread.initReader(tmp);

    pkt_parser = new NtDissector();

    if(reader_thread.init() == -1)
        return -1;

    return 0;
}

/* ********************************** */

static int setup_reader(char const * const file_or_device)
{
    /*  Napatech    */
    if(starts_with(file_or_device, "nt")) {
        if(setup_napatech() != 0) {
            return -1;
        }
    }
    /*  Pcap    */
    else {
        if(setup_pcap(file_or_device) != 0) {
            return -1;
        }
    }

    return 0;
}

/* ********************************** */

static void * run_reader(void * const tmp)
/*  Reader run function, it calls for the pcap_loop */
{
    reader_thread.startRead();

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
    if (pthread_create(reader_thread.getThreadIdPtr(), nullptr,
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
    reader_thread.stopRead();

    tracer->traceEvent(1, "Stopping analysis\r\n\r\n");

    struct timespec abstime;

    clock_gettime(CLOCK_REALTIME, &abstime);
    abstime.tv_sec += 10; 

    if (pthread_timedjoin_np(reader_thread.getThreadId(), nullptr, &abstime) != 0) {
        tracer->traceEvent(0, "Error in pthread_join: %d; Forcing termination\n", strerror(errno));
        reader_thread.printStats();
        return -1;
    }

    reader_thread.printStats();

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
        tracer->traceEvent(2, "\tReader threads are already shutting down, please be patient.\n");
    }
}

/* ********************************** */

static int check_error_or_eof()
/*  Checks if eof is reached */
{
    if (reader_thread.getEof() == 0)
        return 0;

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
    NDPI_BITMASK_SET_ALL(mask);
    tracer = new Trace();

    if(dirExists("./logs") != 1) {
        tracer->traceEvent(0, "Couldn't find necessary directories, please do `make clean` and then do `make`\n", argv[0]);
        return -1;
    }

    if(dirExists("./logs/allarms") != 1) {
        tracer->traceEvent(0, "Couldn't find necessary directories, please do `make clean` and then do `make`\n", argv[0]);
        return -1;
    }

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

    sleep(2);
    /*  have to find a better way of doing this job */
    while (terminate_thread == 0 && check_error_or_eof() == 0) {
            pkt_parser->printBriefInfos(reader_thread.getReader());
	    sleep(1);
    }

    if (terminate_thread == 0 && stop_reader() != 0) {
        tracer->traceEvent(2, "\tnDPILight: stop_reader\n");
        return 1;
    }
    //delete(tracer);
	
    return 0;
}
