#include "ndpi_light_includes.h"



using namespace std;


static void printCustomStats();



Trace *tracer;
ReaderThread *reader_thread;

int terminate_thread {0};
int generate_logs {0};
int thread_number {1};

uint32_t mask;
char *log_path;
uint8_t type {0};

unsigned long long int previous_pkts = 0;
time_t time_start, time_end;
PROFILING_DECLARE(20 /* max number of sections */);



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
        cout << "nDPILight -i <file|device> [-t <tracelevel>] [-n <thread_number>] [-p <path>] [-v]\n"
             << "Usage:\n"
             << "  -i <file.pcap|device>       | Specify a pcap file/playlist to read packets from or a\n"
             << "                              | device for live capture (comma-separated list)\n"
             << "  -t <tracelevel>             | Specify a trace level between 1 ad 6 (standard trace level is 2)\n"
             << "  -n <thread_number>          | If this option is supported, specify the number of threads to be used to\n"
             << "                              | capture and process packets; the number must be betwenn 1 and 8.\n"
             << "  -r none|risk1|risk2[,...]   | Specify which situation is a risk (default is, each situation is a risk).\n"
             << "                              | Possible risks are: URL_POSSIBLE_XSS 			  | URL_POSSIBLE_SQL_INJECTION\n"
             << "                              |                     BINARY_APPLICATION_TRANSFER	          | KNOWN_PROTOCOL_ON_NON_STANDARD_PORT\n"
             << "                              |                     TLS_SELFSIGNED_CERTIFICATE 	          | TLS_OBSOLETE_VERSION\n"
             << "                              |                     TLS_CERTIFICATE_EXPIRED 		  | TLS_CERTIFICATE_MISMATCH\n"
             << "                              |                     HTTP_NUMERIC_IP_HOST 		  | HTTP_SUSPICIOUS_URL\n"
             << "                              |                     TLS_NOT_CARRYING_HTTPS 		  | SUSPICIOUS_DGA_DOMAIN\n"
             << "                              |                     SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER | SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER\n"
             << "                              |                     SMB_INSECURE_VERSION 		  | TLS_SUSPICIOUS_ESNI_USAGE\n"
             << "                              |                     URL_POSSIBLE_RCE_INJECTION            | TLS_WEAK_CIPHER \n"
             << "                              |                     MALFORMED_PACKET                      | HTTP_SUSPICIOUS_USER_AGENT\n"
             << "                              |                     UNSAFE_PROTOCOL                       | HTTP_SUSPICIOUS_HEADER\n"
             << "  -v                          | Creates a log file about every flow after detecting level 7 protocol (by default\n"
             << "                              | it's created when a flow hits a risk specified with -r option).\n"
             << "  -p                          | Specify the path to save log files; default is ./logs.\n";
        return nullptr;
    }

    while((opt = getopt(argc, argv, "n:p:i:t:r:v")) != -1) {
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

            case 'p':
                log_path = optarg;
                break;

            case 'n':
                thread_number = atoi(optarg);
                if(thread_number < 1 || thread_number > 8) {
                    tracer->traceEvent(0, "invalid thread number, please check -h for more infos\n");
                    return nullptr;
                }

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
    char interface[50];
    PcapReader *tmp;
    string type = "pcap";
 
    if(log_path == nullptr) {
        if(dirExists("./logs") != 1) {
            tracer->traceEvent(0, "Couldn't find necessary directories, please do `make clean` and then do `make`\n");
            return -1;
        }
	tracer->set_log_file("logs/pcap_log");	
    }
    else {
        if(dirExists(log_path) != 1) {
            tracer->traceEvent(0, "Couldn't find the directory inserted with -p option, please check the path\n");
            return -1;
        }
	strcat(log_path, "pcap_log");
	tracer->set_log_file(log_path);
    }

    if(starts_with(file_or_device, "pcap:")) {
	strcpy(interface, file_or_device + 5); 
    	tmp = new PcapReader(log_path, type.c_str(), interface);
    } else 
	tmp = new PcapReader(log_path, type.c_str(), file_or_device);
    reader_thread->initReader(tmp);

    if(reader_thread->init() == -1)
        return -1;

    return 0;
}

/* ********************************** */

static int setup_napatech()
/*  Setup the reader_thread */
{
    if(log_path == nullptr) {
        if(dirExists("./logs") != 1) {
            tracer->traceEvent(0, "Couldn't find necessary directories, please do `make clean` and then do `make`\n");
            return -1;
        }
        tracer->set_log_file("logs/nt_log");
    }
    else {
        if(dirExists(log_path) != 1) {
            tracer->traceEvent(0, "Couldn't find the directory inserted with -p option, please check the path\n");
            return -1;
        }
        strcat(log_path, "nt_log");
        tracer->set_log_file(log_path);
    }


    for(int i = 0; i < thread_number; i++) {
        string type = "nt";
	type = type + "_";
        type = type + to_string(i);
        NapatechReader *tmp = new NapatechReader(log_path, type.c_str(), i);

	reader_thread[i].initReader(tmp, i, thread_number);
    }    

    /* Analysis starts */
    tracer->traceEvent(2, "\tAnalysis started\r\n\r\n");

    struct timeval actual_time;
    gettimeofday(&actual_time, nullptr);
    time_start = actual_time.tv_sec;

    return 0;
}

/* ********************************** */

static int setup_reader(char const * const file_or_device)
{
	/*  Napatech    */
	if(starts_with(file_or_device, "nt")) {
		reader_thread = new ReaderThread[thread_number];
		type = 1;
		if(setup_napatech() != 0) {
			return -1;
		}
	}
	/*  Pcap    */
	else {
		reader_thread = new ReaderThread();
		type = 0;
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
	switch(type) {
	    case 0:
		reader_thread->startRead();
		break;
	    case 1:
		for(int i = 0; i < thread_number; i++)
		    reader_thread[i].startRead();
	}

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
	if (pthread_create(reader_thread->getThreadIdPtr(), nullptr,
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
	reader_thread->stopRead();

	tracer->traceEvent(1, "Stopping analysis\r\n\r\n");

	struct timespec abstime;

	clock_gettime(CLOCK_REALTIME, &abstime);
	abstime.tv_sec += 10; 

	if (pthread_timedjoin_np(reader_thread->getThreadId(), nullptr, &abstime) != 0) {
		//tracer->traceEvent(0, "Error in pthread_join: %d; Forcing termination\n", strerror(errno));
		//reader_thread.printStats();
		return -1;
	}

	switch(type) {
	    case 0:
            reader_thread->printStats();
            break;
	    case 1:
		    printCustomStats();
		break;
	}
/*	for(int i = 0; i < thread_number; i++) {
   	     reader_thread[i].close();
        }
*/   
        tracer->~Trace();
	for(int i = 0; i < thread_number; i++)
   	    reader_thread[i].~ReaderThread();
	
	exit(0);
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
	if (reader_thread->getEof() == 0)
		return 0;

	return -1;
}

/* ********************************** */

static void printCustomBriefInfos()
{
    NtStatistics_t hStat;
    uint64_t delta = 0;
    NapatechReader *reader_tmp = (NapatechReader *) reader_thread[0].getReader();
    long long unsigned int tot_packets_captured = 0;
    long long unsigned int total_wire_bytes = 0;

    // Open the stat stream.
    hStat.cmd = NT_STATISTICS_READ_CMD_QUERY_V3;
    hStat.u.query_v3.poll = 0;
    hStat.u.query_v3.clear = 0;
    NT_StatRead(*reader_tmp->getStatStream(), &hStat);
    
    tot_packets_captured = (long long unsigned int)hStat.u.query_v3.data.port.aPorts[0].rx.extDrop.pktsFilterDrop +
				 (long long unsigned int)hStat.u.query_v3.data.port.aPorts[1].rx.extDrop.pktsFilterDrop; 

    total_wire_bytes = (long long unsigned int)hStat.u.query_v3.data.port.aPorts[0].rx.extDrop.octetsFilterDrop +
				(long long unsigned int)hStat.u.query_v3.data.port.aPorts[1].rx.extDrop.octetsFilterDrop; 

    for(int i = 0; i < thread_number; i++) {
	NapatechReader *tmp   = (NapatechReader *) reader_thread[i].getReader();
	tot_packets_captured += tmp->getParser()->getPktsCaptured();
	total_wire_bytes     += tmp->getParser()->getTotBytes();
    }

    delta = tot_packets_captured - previous_pkts;
    previous_pkts = tot_packets_captured;
    
    tracer->traceEvent(2, "\tCapture brief summary: Tot. packets: %llu | Tot. bytes: %llu | pps: %llu\r\n",
    			tot_packets_captured, total_wire_bytes, delta);
}



static void printCustomStats()
{
	NtStatistics_t hStat;
	NapatechReader *tmpRdr = (NapatechReader *) reader_thread[0].getReader();
	//Open the stat stream.
	hStat.cmd = NT_STATISTICS_READ_CMD_QUERY_V3;
	hStat.u.query_v3.poll = 0;
	hStat.u.query_v3.clear = 0;
	NT_StatRead(*tmpRdr->getStatStream(), &hStat);

	long long unsigned int tot_unhandled_packets = 0;
    long long unsigned int tot_packets_captured = (long long unsigned int)hStat.u.query_v3.data.port.aPorts[0].rx.extDrop.pktsFilterDrop +
                                (long long unsigned int)hStat.u.query_v3.data.port.aPorts[1].rx.extDrop.pktsFilterDrop;
    long long unsigned int tot_previous_packets = 0;
    long long unsigned int tot_discarded_bytes = 0;
    long long unsigned int tot_ip_pkts = 0;
    long long unsigned int tot_ip_bytes = 0;
    long long unsigned int tot_tcp_pkts = 0;
    long long unsigned int tot_udp_pkts = 0;

    long long unsigned int tot_total_flows_captured = 0;

    long long unsigned int tot_packets_processed = 0;
    long long unsigned int tot_total_l4_data_len = 0;
    long long unsigned int tot_total_wire_bytes = (long long unsigned int)hStat.u.query_v3.data.port.aPorts[0].rx.extDrop.octetsFilterDrop +
                            (long long unsigned int)hStat.u.query_v3.data.port.aPorts[1].rx.extDrop.octetsFilterDrop;

    long long unsigned int tot_detected_flow_protocols = 0;
    long long unsigned int tot_guessed_flow_protocols = 0;
    long long unsigned int tot_unclassified_flow_protocols = 0;
    long long unsigned int tot_avg_pkt_size = 0;
    long long unsigned int tot_breed_stats[NUM_BREEDS] = { 0 };
    uint16_t * tot_protos_cnt = new uint16_t[ndpi_get_num_supported_protocols(reader_thread[0].getReader()->getNdpiStruct()) + 1] ();

    char buf[32], when[65];
    struct tm result;
    long long unsigned int breed_stats[NUM_BREEDS] = { 0 };
    struct timeval actual_time;
    gettimeofday(&actual_time, nullptr);
    time_end = actual_time.tv_sec;
    

	for(int i = 0; i < thread_number; i++) {
	    NapatechReader *tmp 	     = (NapatechReader *) reader_thread[i].getReader();
	    //tmp->getParser()->printStats((Reader *) tmp);
	    tot_unhandled_packets 	    += tmp->getParser()->getUnhPkts();
	    tot_packets_captured  	    += tmp->getParser()->getPktsCaptured();
        tot_discarded_bytes 	    += tmp->getParser()->getDiscardedBytes();
        tot_ip_pkts 		    += tmp->getParser()->getIpPkts();
        tot_ip_bytes 		    += tmp->getParser()->getIpBytes();
        tot_tcp_pkts 		    += tmp->getParser()->getTcpPkts();
        tot_udp_pkts 		    += tmp->getParser()->getUdpPkts();
        tot_total_flows_captured 	    += tmp->getParser()->getCptFlows();
        tot_packets_processed 	    += tmp->getParser()->getProcPkts();
        tot_total_l4_data_len 	    += tmp->getParser()->getL4Bytes();
        tot_total_wire_bytes 	    += tmp->getParser()->getTotBytes();
        tot_detected_flow_protocols     += tmp->getParser()->getDetectedProtos();
        tot_guessed_flow_protocols 	    += tmp->getParser()->getGuessedProtos();
        tot_unclassified_flow_protocols += tmp->getParser()->getUnclassProtos();

	    uint16_t *protos_cnt	     = tmp->getParser()->getProtosCnt();
	    for(u_int32_t i = 0; i <= ndpi_get_num_supported_protocols(tmp->getNdpiStruct()); i++) {
                if(protos_cnt[i] > 0) 
                        tot_protos_cnt[i] += protos_cnt[i];
            }
	}

        tracer->traceEvent(2, "\tTraffic statistics:\r\n");
        tracer->traceEvent(2, "\t\tEthernet bytes:             %-20llu (includes ethernet CRC/IFC/trailer)\n",
                        tot_total_wire_bytes);
        tracer->traceEvent(2, "\t\tDiscarded bytes:            %-20llu\n",
                        tot_discarded_bytes);
        tracer->traceEvent(2, "\t\tIP packets:                 %-20llu of %llu packets total\n",
                        tot_ip_pkts,
                        tot_packets_captured);
        tracer->traceEvent(2, "\t\tUnhandled IP packets:       %-20llu\n",
                        tot_unhandled_packets);
        /* In order to prevent Floating point exception in case of no traffic*/
        if(tot_ip_pkts != 0)
                tot_avg_pkt_size = tot_ip_bytes/tot_ip_pkts;

        tracer->traceEvent(2, "\t\tIP bytes:                   %-20llu (avg pkt size %u bytes)\n",
                        tot_ip_bytes, tot_avg_pkt_size);

        tracer->traceEvent(2, "\t\tUnique flows:               %-20u\n", tot_total_flows_captured);

        tracer->traceEvent(2, "\t\tTCP Packets:                %-20lu\n", tot_tcp_pkts);
        tracer->traceEvent(2, "\t\tUDP Packets:                %-20lu\n", tot_udp_pkts);

        strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime_r(&time_start, &result));
        tracer->traceEvent(2, "\t\tAnalysis begin:             %-20s\n", when);
        strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime_r(&time_end, &result));
        tracer->traceEvent(2, "\t\tAnalysis end:               %-20s\n", when);

        tracer->traceEvent(2, "\t\tDetected flow protos:       %-20u\n", tot_detected_flow_protocols);
        tracer->traceEvent(2, "\t\tGuessed flow protos:        %-20u\n", tot_guessed_flow_protocols);
        tracer->traceEvent(2, "\t\tUnclassified flow protos:   %-20u\r\n", tot_unclassified_flow_protocols);


        tracer->traceEvent(2, "\tDetected protocols:\r\n");

        for(u_int32_t i = 0; i <= ndpi_get_num_supported_protocols(tmpRdr->getNdpiStruct()); i++) {
		ndpi_protocol_breed_t breed = ndpi_get_proto_breed((tmpRdr->getNdpiStruct()), i);
                if(tot_protos_cnt[i] > 0) {
			breed_stats[i] += tot_protos_cnt[i];
                        tracer->traceEvent(2, "\t\t%-20s flows: %-13u\r\n",
                                        ndpi_get_proto_name((tmpRdr->getNdpiStruct()), i), tot_protos_cnt[i]);
                }
        }

        tracer->traceEvent(2, "\tProtocol statistics:\n");

	    for(u_int32_t i = 0; i < NUM_BREEDS; i++) {
	    if(breed_stats[i] > 0) {
			tracer->traceEvent(2, "\t\t%-20s flows: %-13u\n",
	   		ndpi_get_proto_breed_name(tmpRdr->getNdpiStruct(), ndpi_get_proto_breed(tmpRdr->getNdpiStruct(), i)),
	    	breed_stats[i]);
	    }
	}
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

	struct timeval actual_time;
	uint64_t curr_time = 0, sleep_time = 0;

        gettimeofday(&actual_time, nullptr);
        curr_time = actual_time.tv_sec * 1000 + actual_time.tv_usec / 1000; 
    
	sleep(1);
	/*  have to find a better way of doing this job */
	while (terminate_thread == 0 && reader_thread[0].getEof() == 0) {
            switch(type) {
		case 0: {
		    PcapReader *tmp1 = (PcapReader *) reader_thread->getReader();
		    tmp1->getParser()->printBriefInfos(reader_thread->getReader());
		    break;
		    }
		case 1: {
		    printCustomBriefInfos();
		    break;
		    }
	    }

	    gettimeofday(&actual_time, nullptr);
	    sleep_time = 1000 - (actual_time.tv_sec * 1000 + actual_time.tv_usec / 1000) - curr_time;

	    //printf("%llu, %llu, %llu\n", curr_time, (actual_time.tv_sec * 1000 + actual_time.tv_usec / 1000), sleep_time);

            if(sleep_time < 0)
		continue;
	    
	    if(sleep_time > 1000)
		sleep_time = 1000;
	    
	    sleep_time = sleep_time / 1000;

	    //printf("%d\n", sleep_time);

	    sleep(sleep_time);
	    gettimeofday(&actual_time, nullptr);
	    curr_time = actual_time.tv_sec * 1000 + actual_time.tv_usec / 1000;
    }

    if (terminate_thread == 0 && stop_reader() != 0) {
        return 1;
    }

   /* for(int i = 0; i < thread_number; i++) {
   //     reader_thread[i].close();
    }

    tracer->~Trace();
    reader_thread->~ReaderThread();
*/
    return 0;
}
